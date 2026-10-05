"""撤销影响清单：事件写入时同事务保存被追溯命中的成功核销，并按撤销 request_key 查询。"""
from __future__ import annotations

import itertools
import threading
from datetime import datetime, timedelta, timezone

from tests.conftest import make_token

_chain_seq = itertools.count(1)


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
        "root", None, "root", "svc-a",
        "/files/**", ["GET", "POST"], not_before=nb, not_after=na,
        chain_id=chain_id,
    )
    a = make_token(
        "a", "root", "svc-a", "svc-b",
        "/files/reports/*", ["GET"], allow_ip="10.0.0.0/8",
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    b = make_token(
        "b", "a", "svc-b", "svc-b",
        "/files/reports/x", ["GET"], allow_ip="10.1.0.0/16",
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    return {"chain_id": chain_id, "tokens": [root, a, b]}


def _leg(chain_id: str, root_id: str, leaf_id: str, leaf_subject: str,
         leaf_issuer: str) -> dict:
    """root -> leaf 的合法两级链（会签演练用，对服务端当前时刻有效）。"""
    nb, na = _now_window()
    root = make_token(
        root_id, None, "root", leaf_issuer,
        "/files/**", ["GET", "POST"], not_before=nb, not_after=na,
        chain_id=chain_id,
    )
    leaf = make_token(
        leaf_id, root_id, leaf_issuer, leaf_subject,
        "/files/reports/x", ["GET"], allow_ip="10.1.0.0/16",
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    return {"chain_id": chain_id, "tokens": [root, leaf]}


def _setup_chain(client) -> str:
    chain_id = f"chain-impact-{next(_chain_seq)}"
    resp = client.post("/api/v1/chains", json=_chain3(chain_id))
    assert resp.status_code == 201, resp.text
    return chain_id


def _setup_co_pair(client) -> tuple[str, str]:
    """提交主授权链（末端 alice）与复核链（末端 bob），返回两个 chain_id。"""
    n = next(_chain_seq)
    primary_id, review_id = f"impact-primary-{n}", f"impact-review-{n}"
    resp = client.post(
        "/api/v1/chains", json=_leg(primary_id, "p-root", "p-leaf", "alice", "svc-a")
    )
    assert resp.status_code == 201, resp.text
    resp = client.post(
        "/api/v1/chains", json=_leg(review_id, "r-root", "r-leaf", "bob", "svc-b")
    )
    assert resp.status_code == 201, resp.text
    return primary_id, review_id


def _redeem(client, chain_id, *, request_key, token_id="b"):
    return client.post(
        f"/api/v1/chains/{chain_id}/redeem",
        json={
            "token_id": token_id,
            "request_key": request_key,
            "request_path": "/files/reports/x",
            "method": "GET",
            "source_ip": "10.1.2.3",
        },
    )


def _co_redeem(client, primary_id, review_id, *, request_key):
    return client.post(
        "/api/v1/co-redemptions",
        json={
            "primary": {"chain_id": primary_id, "token_id": "p-leaf"},
            "review": {"chain_id": review_id, "token_id": "r-leaf"},
            "request_key": request_key,
            "request_path": "/files/reports/x",
            "method": "GET",
            "source_ip": "10.1.2.3",
        },
    )


def _revoke(client, chain_id, token_id, effective_at, request_key, reason="安全事件"):
    return client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": token_id,
            "effective_at": effective_at,
            "reason": reason,
            "request_key": request_key,
        },
    )


def _impacts(client, request_key):
    return client.get(f"/api/v1/revocations/{request_key}/impacts")


def _past(hours: float = 2) -> str:
    return (
        (datetime.now(timezone.utc) - timedelta(hours=hours))
        .isoformat()
        .replace("+00:00", "Z")
    )


def _future(hours: float = 2) -> str:
    return (
        (datetime.now(timezone.utc) + timedelta(hours=hours))
        .isoformat()
        .replace("+00:00", "Z")
    )


# --------------------------------------------------------------------------- #
# 单链核销被追溯命中
# --------------------------------------------------------------------------- #
def test_single_redemption_completed_before_revocation_is_listed(client):
    chain_id = _setup_chain(client)
    redeemed = _redeem(client, chain_id, request_key="imp-acc-single")
    assert redeemed.status_code == 201, redeemed.text
    redeemed_at = redeemed.json()["redeemed_at"]

    resp = _revoke(client, chain_id, "a", _past(), "imp-rk-single")
    assert resp.status_code == 201, resp.text

    got = _impacts(client, "imp-rk-single")
    assert got.status_code == 200, got.text
    body = got.json()
    # 响应携带撤销事件上下文
    assert body["request_key"] == "imp-rk-single"
    assert body["chain_id"] == chain_id
    assert body["token_id"] == "a"
    assert body["effective_at"]
    # 影响清单：该链末端 b 的成功核销，kind=single、无侧
    assert len(body["impacts"]) == 1
    item = body["impacts"][0]
    assert item["request_key"] == "imp-acc-single"
    assert item["chain_id"] == chain_id
    assert item["token_id"] == "b"
    assert item["kind"] == "single"
    assert item["side"] is None
    assert datetime.fromisoformat(item["redeemed_at"]) == datetime.fromisoformat(
        redeemed_at
    )


def test_revoking_tip_itself_lists_its_redemption(client):
    chain_id = _setup_chain(client)
    assert _redeem(client, chain_id, request_key="imp-acc-tip").status_code == 201
    assert _revoke(client, chain_id, "b", _past(), "imp-rk-tip").status_code == 201
    body = _impacts(client, "imp-rk-tip").json()
    assert [i["token_id"] for i in body["impacts"]] == ["b"]


def test_revoking_root_lists_tip_redemption(client):
    chain_id = _setup_chain(client)
    assert _redeem(client, chain_id, request_key="imp-acc-root").status_code == 201
    assert _revoke(client, chain_id, "root", _past(), "imp-rk-root").status_code == 201
    body = _impacts(client, "imp-rk-root").json()
    assert len(body["impacts"]) == 1
    assert body["impacts"][0]["token_id"] == "b"
    assert body["impacts"][0]["kind"] == "single"


# --------------------------------------------------------------------------- #
# 双主体会签被追溯命中：一笔会签只列一次，注明链与主授权 / 复核侧
# --------------------------------------------------------------------------- #
def test_co_redemption_listed_once_with_affected_side(client):
    primary_id, review_id = _setup_co_pair(client)
    co = _co_redeem(client, primary_id, review_id, request_key="imp-acc-co")
    assert co.status_code == 201, co.text
    co_redeemed_at = co.json()["redeemed_at"]

    # 撤销主授权链的根：会签按主授权侧列出一次
    resp = _revoke(client, primary_id, "p-root", _past(), "imp-rk-co-primary")
    assert resp.status_code == 201, resp.text
    body = _impacts(client, "imp-rk-co-primary").json()
    assert len(body["impacts"]) == 1
    item = body["impacts"][0]
    assert item["request_key"] == "imp-acc-co"
    assert item["chain_id"] == primary_id
    assert item["token_id"] == "p-leaf"
    assert item["kind"] == "co"
    assert item["side"] == "primary"
    assert datetime.fromisoformat(item["redeemed_at"]) == datetime.fromisoformat(
        co_redeemed_at
    )

    # 撤销复核链的末端：同一会签在该事件的清单中按复核侧列出一次
    resp = _revoke(client, review_id, "r-leaf", _past(), "imp-rk-co-review")
    assert resp.status_code == 201, resp.text
    body = _impacts(client, "imp-rk-co-review").json()
    assert len(body["impacts"]) == 1
    item = body["impacts"][0]
    assert item["request_key"] == "imp-acc-co"
    assert item["chain_id"] == review_id
    assert item["token_id"] == "r-leaf"
    assert item["kind"] == "co"
    assert item["side"] == "review"


# --------------------------------------------------------------------------- #
# 不命中的情形：空清单
# --------------------------------------------------------------------------- #
def test_redemption_before_effective_at_is_not_listed(client):
    chain_id = _setup_chain(client)
    assert _redeem(client, chain_id, request_key="imp-acc-early").status_code == 201
    # 生效时间晚于核销时间：访问发生在撤销生效之前，不被追溯
    assert _revoke(client, chain_id, "a", _future(), "imp-rk-future").status_code == 201
    body = _impacts(client, "imp-rk-future").json()
    assert body["impacts"] == []


def test_revocation_without_any_redemption_has_empty_impacts(client):
    chain_id = _setup_chain(client)
    assert _revoke(client, chain_id, "a", _past(), "imp-rk-none").status_code == 201
    body = _impacts(client, "imp-rk-none").json()
    assert body["request_key"] == "imp-rk-none"
    assert body["impacts"] == []


def test_redemption_on_other_chain_not_listed(client):
    c1 = _setup_chain(client)
    c2 = _setup_chain(client)
    assert _redeem(client, c1, request_key="imp-acc-other").status_code == 201
    assert _revoke(client, c2, "a", _past(), "imp-rk-other").status_code == 201
    assert _impacts(client, "imp-rk-other").json()["impacts"] == []


def test_impact_list_frozen_at_event_write_time(client):
    chain_id = _setup_chain(client)
    # 先生效时间指向未来的撤销：清单在事件写入时计算（当时无任何核销）
    assert _revoke(client, chain_id, "a", _future(), "imp-rk-frozen").status_code == 201
    # 撤销尚未生效，核销照常成功（核销时间晚于事件写入时间）
    assert _redeem(client, chain_id, request_key="imp-acc-late").status_code == 201
    # 清单不随后续核销改变
    assert _impacts(client, "imp-rk-frozen").json()["impacts"] == []


# --------------------------------------------------------------------------- #
# 查询接口：404、重放不重复写入、失败不留清单
# --------------------------------------------------------------------------- #
def test_impacts_unknown_revocation_request_key_404(client):
    resp = _impacts(client, "imp-rk-does-not-exist")
    assert resp.status_code == 404


def test_replay_does_not_duplicate_impact_list(client):
    chain_id = _setup_chain(client)
    assert _redeem(client, chain_id, request_key="imp-acc-replay").status_code == 201
    eff = _past()
    first = _revoke(client, chain_id, "a", eff, "imp-rk-replay")
    assert first.status_code == 201
    # 同键同内容重放：返回原事件，不重复写入清单
    replay = _revoke(client, chain_id, "a", eff, "imp-rk-replay")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["event"] == first.json()["event"]
    body = _impacts(client, "imp-rk-replay").json()
    assert len(body["impacts"]) == 1
    # 再次查询仍只有一条
    assert _impacts(client, "imp-rk-replay").json()["impacts"] == body["impacts"]


def test_failed_revocation_leaves_no_impact_list(client):
    chain_id = _setup_chain(client)
    assert _redeem(client, chain_id, request_key="imp-acc-fail").status_code == 201
    eff = _past()
    assert _revoke(client, chain_id, "a", eff, "imp-rk-ok").status_code == 201

    # 重复撤销同一令牌：409，不产生新事件，也没有清单
    conflict = _revoke(client, chain_id, "a", eff, "imp-rk-dup")
    assert conflict.status_code == 409
    assert _impacts(client, "imp-rk-dup").status_code == 404

    # 链不存在：404，同样没有清单
    missing = _revoke(client, "chain-ghost", "a", eff, "imp-rk-ghost")
    assert missing.status_code == 404
    assert _impacts(client, "imp-rk-ghost").status_code == 404

    # 同键换内容：409，原事件清单不变
    same_key = _revoke(client, chain_id, "b", _future(), "imp-rk-ok")
    assert same_key.status_code == 409
    body = _impacts(client, "imp-rk-ok").json()
    assert len(body["impacts"]) == 1
    assert body["impacts"][0]["request_key"] == "imp-acc-fail"


# --------------------------------------------------------------------------- #
# 原链查询、求值与成功核销的重放结论保持原样
# --------------------------------------------------------------------------- #
def test_impacts_do_not_rewrite_redemption_or_chain_views(client):
    chain_id = _setup_chain(client)
    redeemed = _redeem(client, chain_id, request_key="imp-acc-keep")
    assert redeemed.status_code == 201
    first_result = redeemed.json()

    # 生效时间早于核销时间、晚于链上令牌生效点（历史请求仍可判定）
    eff = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat().replace(
        "+00:00", "Z"
    )
    assert _revoke(client, chain_id, "a", eff, "imp-rk-keep").status_code == 201
    assert len(_impacts(client, "imp-rk-keep").json()["impacts"]) == 1

    # 原核销记录不被改写：链查询中的 redemptions 保持原样
    chain = client.get(f"/api/v1/chains/{chain_id}").json()
    assert [r["request_key"] for r in chain["redemptions"]] == ["imp-acc-keep"]
    assert chain["redemptions"][0]["token_id"] == "b"
    assert chain["redemptions"][0]["redeemed_at"] == first_result["redeemed_at"]
    assert chain["integrity"]["allow"] is True

    # 成功核销的同键重放结论保持原样（即使令牌随后被撤销）
    replay = _redeem(client, chain_id, request_key="imp-acc-keep")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["redeemed_at"] == first_result["redeemed_at"]
    assert replay.json()["trace"] == first_result["trace"]

    # 求值仍按请求时间解释：生效前的历史请求按原链判定为 allow
    before = (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat().replace(
        "+00:00", "Z"
    )
    ev = client.post(
        f"/api/v1/chains/{chain_id}/evaluate",
        json={
            "request_path": "/files/reports/x",
            "method": "GET",
            "at": before,
            "source_ip": "10.1.2.3",
        },
    )
    assert ev.json()["decision"] == "allow"
    # 生效后的请求照常拒绝
    after = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    ev_after = client.post(
        f"/api/v1/chains/{chain_id}/evaluate",
        json={
            "request_path": "/files/reports/x",
            "method": "GET",
            "at": after,
            "source_ip": "10.1.2.3",
        },
    )
    assert ev_after.json()["decision"] == "deny"
    assert ev_after.json()["first_failed_reason"] == "revoked"


def test_co_redemption_replay_and_chain_views_unchanged_after_revocation(client):
    primary_id, review_id = _setup_co_pair(client)
    co = _co_redeem(client, primary_id, review_id, request_key="imp-acc-co-keep")
    assert co.status_code == 201
    first = co.json()

    assert (
        _revoke(client, primary_id, "p-root", _past(), "imp-rk-co-keep").status_code
        == 201
    )
    assert len(_impacts(client, "imp-rk-co-keep").json()["impacts"]) == 1

    # 同键同内容重放会签：仍返回首次会签结果
    replay = _co_redeem(client, primary_id, review_id, request_key="imp-acc-co-keep")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["redeemed_at"] == first["redeemed_at"]

    # 两侧链查询中的核销记录均不被改写
    for cid, tid in ((primary_id, "p-leaf"), (review_id, "r-leaf")):
        chain = client.get(f"/api/v1/chains/{cid}").json()
        assert [r["request_key"] for r in chain["redemptions"]] == ["imp-acc-co-keep"]
        assert chain["redemptions"][0]["token_id"] == tid


# --------------------------------------------------------------------------- #
# 并发：事件与清单的写入在同一事务内串行化
# --------------------------------------------------------------------------- #
def test_concurrent_same_key_revocations_write_event_and_list_once(client):
    chain_id = _setup_chain(client)
    assert _redeem(client, chain_id, request_key="imp-acc-storm").status_code == 201
    eff = _past()
    responses = []

    def worker():
        responses.append(_revoke(client, chain_id, "a", eff, "imp-rk-storm"))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    codes = sorted(r.status_code for r in responses)
    assert codes.count(201) == 1  # 仅一笔新事件
    assert codes.count(200) == 5  # 其余为同键同内容重放
    # 清单只写入一次
    assert len(_impacts(client, "imp-rk-storm").json()["impacts"]) == 1


def test_concurrent_redemption_and_revocation_are_serialized(client):
    chain_id = _setup_chain(client)
    eff = _past()
    results = {}

    def do_redeem():
        results["redeem"] = _redeem(client, chain_id, request_key="imp-acc-race")

    def do_revoke():
        results["revoke"] = _revoke(client, chain_id, "a", eff, "imp-rk-race")

    threads = [threading.Thread(target=do_redeem), threading.Thread(target=do_revoke)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results["revoke"].status_code == 201
    impacts = _impacts(client, "imp-rk-race").json()["impacts"]
    if results["redeem"].status_code == 201:
        # 核销先于撤销写入：被追溯命中
        assert [i["request_key"] for i in impacts] == ["imp-acc-race"]
    else:
        # 撤销先写入：核销被生效撤销拒绝（不落记录），清单为空
        assert results["redeem"].status_code == 200
        assert results["redeem"].json()["redeemed"] is False
        assert results["redeem"].json()["first_failed_reason"] == "revoked"
        assert impacts == []
