"""撤销追溯影响清单：事件写入时同事务快照受影响核销、查询 API、失败不留清单。"""
from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

from app.database import (
    connect,
    find_redemptions_affected_by_revocation,
    insert_revocation_impacts,
    load_revocation_impacts,
)
from app.models import RevocationImpactEntry
from tests.conftest import make_token

_chain_seq = itertools.count(1)
_co_seq = itertools.count(1)

_PAST = "2026-01-01T00:00:00Z"
_FUTURE = "2030-01-01T00:00:00Z"


def _now_window(**offsets) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    nb = now + timedelta(seconds=offsets.get("nb", -3600))
    na = now + timedelta(seconds=offsets.get("na", 3600))
    return (
        nb.isoformat().replace("+00:00", "Z"),
        na.isoformat().replace("+00:00", "Z"),
    )


def _chain3(chain_id: str) -> dict:
    """root -> a -> b 的合法三级链（对服务端当前时刻有效）。"""
    nb, na = _now_window()
    root = make_token(
        "root", None, "root", "svc-a", "/files/**", ["GET", "POST"],
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    a = make_token(
        "a", "root", "svc-a", "svc-b", "/files/reports/*", ["GET"],
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    b = make_token(
        "b", "a", "svc-b", "svc-b", "/files/reports/x", ["GET"],
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    return {"chain_id": chain_id, "tokens": [root, a, b]}


def _setup_chain(client) -> str:
    chain_id = f"chain-imp-{next(_chain_seq)}"
    resp = client.post("/api/v1/chains", json=_chain3(chain_id))
    assert resp.status_code == 201, resp.text
    return chain_id


def _co_chain(chain_id, root_id, leaf_id, leaf_subject, leaf_issuer) -> dict:
    """root -> leaf 的合法两级会签链（对服务端当前时刻有效）。"""
    nb, na = _now_window()
    root = make_token(
        root_id, None, "root", leaf_issuer, "/files/**", ["GET", "POST"],
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    leaf = make_token(
        leaf_id, root_id, leaf_issuer, leaf_subject, "/files/reports/x", ["GET"],
        allow_ip="10.1.0.0/16", not_before=nb, not_after=na, chain_id=chain_id,
    )
    return {"chain_id": chain_id, "tokens": [root, leaf]}


def _setup_co(client) -> tuple[str, str]:
    """提交主授权链（末端 alice）与复核链（末端 bob），返回两个 chain_id。"""
    n = next(_co_seq)
    p_id, r_id = f"co-imp-primary-{n}", f"co-imp-review-{n}"
    resp = client.post(
        "/api/v1/chains", json=_co_chain(p_id, "p-root", "p-leaf", "alice", "svc-a")
    )
    assert resp.status_code == 201, resp.text
    resp = client.post(
        "/api/v1/chains", json=_co_chain(r_id, "r-root", "r-leaf", "bob", "svc-b")
    )
    assert resp.status_code == 201, resp.text
    return p_id, r_id


def _redeem(client, chain_id, request_key, token_id="b"):
    return client.post(
        f"/api/v1/chains/{chain_id}/redeem",
        json={
            "token_id": token_id,
            "request_key": request_key,
            "request_path": "/files/reports/x",
            "method": "GET",
        },
    )


def _co_redeem(client, p_id, r_id, request_key):
    return client.post(
        "/api/v1/co-redemptions",
        json={
            "primary": {"chain_id": p_id, "token_id": "p-leaf"},
            "review": {"chain_id": r_id, "token_id": "r-leaf"},
            "request_key": request_key,
            "request_path": "/files/reports/x",
            "method": "GET",
            "source_ip": "10.1.2.3",
        },
    )


def _revoke(client, chain_id, token_id, effective_at, request_key):
    return client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": token_id,
            "effective_at": effective_at,
            "reason": "追溯撤销",
            "request_key": request_key,
        },
    )


def _impacts(client, request_key):
    return client.get(f"/api/v1/revocations/{request_key}/impacts")


# --------------------------------------------------------------------------- #
# 单链核销：撤销追溯到已完成访问之前 -> 列出受影响访问
# --------------------------------------------------------------------------- #
def test_revocation_lists_single_redemption_completed_before_event(client):
    chain_id = _setup_chain(client)
    first = _redeem(client, chain_id, "rk-access-1")
    assert first.status_code == 201, first.text
    redeemed_at = first.json()["redeemed_at"]

    rev = _revoke(client, chain_id, "a", _PAST, "rk-imp-1")
    assert rev.status_code == 201, rev.text
    impacts = rev.json()["affected_redemptions"]
    assert len(impacts) == 1
    hit = impacts[0]
    assert hit["redeemed_at"] == redeemed_at
    assert hit["access_request_key"] == "rk-access-1"
    assert hit["chain_id"] == chain_id
    assert hit["token_id"] == "b"
    assert hit["side"] == "single"

    # 查询 API 返回同一份清单，并带撤销事件定位信息
    got = _impacts(client, "rk-imp-1")
    assert got.status_code == 200
    body = got.json()
    assert body["request_key"] == "rk-imp-1"
    assert body["chain_id"] == chain_id
    assert body["token_id"] == "a"
    assert body["effective_at"].startswith("2026-01-01T00:00:00")
    assert body["impacts"] == impacts


def test_revocation_of_root_lists_redemption(client):
    chain_id = _setup_chain(client)
    assert _redeem(client, chain_id, "rk-access-root").status_code == 201
    rev = _revoke(client, chain_id, "root", _PAST, "rk-imp-root")
    assert rev.status_code == 201
    assert [i["access_request_key"] for i in rev.json()["affected_redemptions"]] == [
        "rk-access-root"
    ]


def test_revocation_of_leaf_lists_redemption(client):
    chain_id = _setup_chain(client)
    assert _redeem(client, chain_id, "rk-access-leaf").status_code == 201
    rev = _revoke(client, chain_id, "b", _PAST, "rk-imp-leaf")
    assert rev.status_code == 201
    hits = rev.json()["affected_redemptions"]
    assert len(hits) == 1
    assert hits[0]["token_id"] == "b"
    assert hits[0]["side"] == "single"


def test_redemption_before_effective_at_not_listed(client):
    chain_id = _setup_chain(client)
    assert _redeem(client, chain_id, "rk-access-early").status_code == 201
    # 生效时间晚于核销时间：该访问不受追溯影响
    rev = _revoke(client, chain_id, "a", _FUTURE, "rk-imp-future")
    assert rev.status_code == 201
    assert rev.json()["affected_redemptions"] == []
    got = _impacts(client, "rk-imp-future")
    assert got.status_code == 200
    assert got.json()["impacts"] == []


def test_effective_at_equal_redeemed_at_is_listed(client):
    chain_id = _setup_chain(client)
    first = _redeem(client, chain_id, "rk-access-eq")
    assert first.status_code == 201
    redeemed_at = first.json()["redeemed_at"]
    # “不早于 effective_at”含边界：核销时间恰好等于生效时间也列入
    rev = _revoke(client, chain_id, "a", redeemed_at, "rk-imp-eq")
    assert rev.status_code == 201
    assert [i["access_request_key"] for i in rev.json()["affected_redemptions"]] == [
        "rk-access-eq"
    ]


def test_redemption_on_other_chain_not_listed(client):
    c1 = _setup_chain(client)
    c2 = _setup_chain(client)
    assert _redeem(client, c1, "rk-access-c1").status_code == 201
    assert _redeem(client, c2, "rk-access-c2").status_code == 201
    rev = _revoke(client, c1, "a", _PAST, "rk-imp-c1")
    assert rev.status_code == 201
    hits = rev.json()["affected_redemptions"]
    assert [i["access_request_key"] for i in hits] == ["rk-access-c1"]
    assert all(i["chain_id"] == c1 for i in hits)


def test_revocation_without_prior_redemptions_has_empty_list(client):
    chain_id = _setup_chain(client)
    rev = _revoke(client, chain_id, "a", _PAST, "rk-imp-empty")
    assert rev.status_code == 201
    assert rev.json()["affected_redemptions"] == []
    got = _impacts(client, "rk-imp-empty")
    assert got.status_code == 200
    assert got.json()["impacts"] == []


# --------------------------------------------------------------------------- #
# 双链会签：纳入清单、一笔只列一次、注明主授权 / 复核侧
# --------------------------------------------------------------------------- #
def test_co_redemption_listed_once_with_primary_side(client):
    p_id, r_id = _setup_co(client)
    first = _co_redeem(client, p_id, r_id, "ck-imp-1")
    assert first.status_code == 201, first.text
    redeemed_at = first.json()["redeemed_at"]

    rev = _revoke(client, p_id, "p-root", _PAST, "rk-imp-co-p")
    assert rev.status_code == 201
    impacts = rev.json()["affected_redemptions"]
    # 一笔会签只列一次，注明主授权侧
    assert len(impacts) == 1
    hit = impacts[0]
    assert hit["access_request_key"] == "ck-imp-1"
    assert hit["chain_id"] == p_id
    assert hit["token_id"] == "p-leaf"
    assert hit["side"] == "primary"
    assert hit["redeemed_at"] == redeemed_at
    assert _impacts(client, "rk-imp-co-p").json()["impacts"] == impacts


def test_co_redemption_listed_with_review_side(client):
    p_id, r_id = _setup_co(client)
    assert _co_redeem(client, p_id, r_id, "ck-imp-2").status_code == 201
    rev = _revoke(client, r_id, "r-leaf", _PAST, "rk-imp-co-r")
    assert rev.status_code == 201
    impacts = rev.json()["affected_redemptions"]
    assert len(impacts) == 1
    assert impacts[0]["side"] == "review"
    assert impacts[0]["chain_id"] == r_id
    assert impacts[0]["token_id"] == "r-leaf"


def test_co_redemption_before_effective_at_not_listed(client):
    p_id, r_id = _setup_co(client)
    assert _co_redeem(client, p_id, r_id, "ck-imp-3").status_code == 201
    rev = _revoke(client, p_id, "p-root", _FUTURE, "rk-imp-co-f")
    assert rev.status_code == 201
    assert rev.json()["affected_redemptions"] == []


# --------------------------------------------------------------------------- #
# 失败不留清单、重放不重复写入、事件不存在 404
# --------------------------------------------------------------------------- #
def test_failed_revocation_leaves_no_impact_list(client):
    chain_id = _setup_chain(client)
    assert _revoke(client, chain_id, "a", _PAST, "rk-fail-1").status_code == 201
    # 重复撤销同一令牌（换键）-> 409：事件未写入，查询其键得到 404
    assert _revoke(client, chain_id, "a", "2026-02-01T00:00:00Z", "rk-fail-2").status_code == 409
    assert _impacts(client, "rk-fail-2").status_code == 404
    # 链不存在 -> 404：同样不留清单
    assert _revoke(client, "chain-ghost", "a", _PAST, "rk-fail-3").status_code == 404
    assert _impacts(client, "rk-fail-3").status_code == 404
    # 同键换内容 -> 409：原事件的清单不被改写
    assert _revoke(client, chain_id, "b", _PAST, "rk-fail-1").status_code == 409
    got = _impacts(client, "rk-fail-1")
    assert got.status_code == 200
    assert got.json()["impacts"] == []


def test_replay_returns_saved_list_without_duplicate_writes(client):
    chain_id = _setup_chain(client)
    assert _redeem(client, chain_id, "rk-access-rp").status_code == 201
    first = _revoke(client, chain_id, "a", _PAST, "rk-imp-rp")
    assert first.status_code == 201
    assert len(first.json()["affected_redemptions"]) == 1

    replay = _revoke(client, chain_id, "a", _PAST, "rk-imp-rp")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["affected_redemptions"] == first.json()["affected_redemptions"]

    # 重放未重复写入：清单仍只有一条
    got = _impacts(client, "rk-imp-rp")
    assert got.status_code == 200
    assert len(got.json()["impacts"]) == 1


def test_impact_query_unknown_request_key_404(client):
    assert _impacts(client, "rk-no-such-event").status_code == 404


# --------------------------------------------------------------------------- #
# 原链查询 / 求值 / 成功核销的重放结论保持原样
# --------------------------------------------------------------------------- #
def test_impacts_do_not_rewrite_original_records(client):
    chain_id = _setup_chain(client)
    first = _redeem(client, chain_id, "rk-keep")
    assert first.status_code == 201
    rev = _revoke(client, chain_id, "a", _PAST, "rk-keep-rev")
    assert rev.status_code == 201
    assert len(rev.json()["affected_redemptions"]) == 1

    # 原核销记录不改写：链查询仍见原记录
    got = client.get(f"/api/v1/chains/{chain_id}").json()
    assert [e["request_key"] for e in got["redemptions"]] == ["rk-keep"]
    assert got["redemptions"][0]["token_id"] == "b"

    # 成功核销的同键重放结论保持原样（仍返回首次 allow）
    replay = _redeem(client, chain_id, "rk-keep")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["decision"] == "allow"
    assert replay.json()["redeemed_at"] == first.json()["redeemed_at"]

    # 只读求值仍按请求时间解释撤销：生效后拒绝
    denied = client.post(
        f"/api/v1/chains/{chain_id}/evaluate",
        json={
            "request_path": "/files/reports/x",
            "method": "GET",
            "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    )
    assert denied.status_code == 200
    assert denied.json()["decision"] == "deny"
    assert denied.json()["first_failed_reason"] == "revoked"


# --------------------------------------------------------------------------- #
# 存储层：排序与“早于事件写入时间”边界
# --------------------------------------------------------------------------- #
def test_load_impacts_sorted_by_redeemed_at_then_request_key(client):
    chain_id = _setup_chain(client)
    assert _revoke(client, chain_id, "a", _PAST, "rk-sort").status_code == 201
    t1 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 6, 1, 13, 0, 0, tzinfo=timezone.utc)
    entries = [
        RevocationImpactEntry(
            redeemed_at=t2, access_request_key="k-b",
            chain_id=chain_id, token_id="b", side="single",
        ),
        RevocationImpactEntry(
            redeemed_at=t1, access_request_key="k-z",
            chain_id=chain_id, token_id="b", side="single",
        ),
        RevocationImpactEntry(
            redeemed_at=t2, access_request_key="k-a",
            chain_id=chain_id, token_id="b", side="single",
        ),
    ]
    conn = connect()
    try:
        insert_revocation_impacts(
            conn, "rk-sort", entries, datetime.now(timezone.utc)
        )
        conn.commit()
        loaded = load_revocation_impacts(conn, "rk-sort")
    finally:
        conn.close()
    # 先按核销时间，再按访问 request_key
    assert [e.access_request_key for e in loaded] == ["k-z", "k-a", "k-b"]
    got = _impacts(client, "rk-sort")
    assert [i["access_request_key"] for i in got.json()["impacts"]] == [
        "k-z", "k-a", "k-b",
    ]


def test_find_requires_redeemed_before_event_write(client):
    chain_id = _setup_chain(client)
    resp = _redeem(client, chain_id, "rk-boundary")
    assert resp.status_code == 201
    redeemed_at = datetime.fromisoformat(resp.json()["redeemed_at"])
    effective = datetime(2026, 1, 1, tzinfo=timezone.utc)
    conn = connect()
    try:
        # 核销时间 == 事件写入时间：不命中（必须严格早于写入时间）
        assert find_redemptions_affected_by_revocation(
            conn, chain_id, ["b"], effective, redeemed_at
        ) == []
        # 写入时间晚一微秒：命中
        hits = find_redemptions_affected_by_revocation(
            conn, chain_id, ["b"], effective,
            redeemed_at + timedelta(microseconds=1),
        )
        assert [h.access_request_key for h in hits] == ["rk-boundary"]
        assert hits[0].side == "single"
    finally:
        conn.close()
