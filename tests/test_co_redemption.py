"""双主体会签：双链同事务核销、共同时间、幂等重放、互不消耗与单链隔离。"""
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


def _chain(chain_id: str, root_id: str, leaf_id: str, leaf_subject: str,
           leaf_issuer: str, window: tuple[str, str] | None = None,
           **leaf_over) -> dict:
    """root -> leaf 的合法两级链（默认对服务端当前时刻有效）。"""
    nb, na = window or _now_window()
    root = make_token(
        root_id, None, "root", leaf_issuer,
        "/files/**", ["GET", "POST"], not_before=nb, not_after=na,
        chain_id=chain_id,
    )
    leaf_kwargs = dict(
        parent_id=root_id, issuer=leaf_issuer, subject=leaf_subject,
        path_pattern="/files/reports/x", methods=["GET"],
        allow_ip="10.1.0.0/16",
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    leaf_kwargs.update(leaf_over)
    leaf = make_token(leaf_id, **leaf_kwargs)
    return {"chain_id": chain_id, "tokens": [root, leaf]}


def _setup(client, *, primary_subject="alice", review_subject="bob",
           p_leaf_over=None, r_leaf_over=None) -> tuple[str, str]:
    """提交主授权链（末端 alice）与复核链（末端 bob），返回两个 chain_id。"""
    n = next(_chain_seq)
    primary_id, review_id = f"co-primary-{n}", f"co-review-{n}"
    resp = client.post("/api/v1/chains", json=_chain(
        primary_id, "p-root", "p-leaf", primary_subject, "svc-a",
        **(p_leaf_over or {}),
    ))
    assert resp.status_code == 201, resp.text
    resp = client.post("/api/v1/chains", json=_chain(
        review_id, "r-root", "r-leaf", review_subject, "svc-b",
        **(r_leaf_over or {}),
    ))
    assert resp.status_code == 201, resp.text
    return primary_id, review_id


def _co_redeem(
    client,
    primary_id,
    review_id,
    *,
    p_token="p-leaf",
    r_token="r-leaf",
    request_key="ck",
    request_path="/files/reports/x",
    method="GET",
    source_ip="10.1.2.3",
    body=None,
):
    payload = {
        "primary": {"chain_id": primary_id, "token_id": p_token},
        "review": {"chain_id": review_id, "token_id": r_token},
        "request_key": request_key,
        "request_path": request_path,
        "method": method,
    }
    if source_ip is not None:
        payload["source_ip"] = source_ip
    if body is not None:
        payload["body"] = body
    return client.post("/api/v1/co-redemptions", json=payload)


def _single_redeem(client, chain_id, *, token_id, request_key,
                   request_path="/files/reports/x", method="GET",
                   source_ip="10.1.2.3"):
    return client.post(
        f"/api/v1/chains/{chain_id}/redeem",
        json={
            "token_id": token_id,
            "request_key": request_key,
            "request_path": request_path,
            "method": method,
            "source_ip": source_ip,
        },
    )


# --------------------------------------------------------------------------- #
# 成功会签：两侧同时核销、共同时间、两份轨迹
# --------------------------------------------------------------------------- #
def test_co_redeem_success_redeems_both_sides_with_common_time(client):
    primary_id, review_id = _setup(client)
    resp = _co_redeem(client, primary_id, review_id, request_key="ck-ok",
                      body={"q": 1})
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["redeemed"] is True
    assert data["replayed"] is False
    assert data["request_key"] == "ck-ok"
    # 共同判定 / 核销时间
    assert data["evaluated_at"] is not None
    assert data["redeemed_at"] == data["evaluated_at"]
    assert len(data["body_sha256"]) == 64
    # 两份判定轨迹：各自链、各自末端、各自 subject
    p, r = data["primary"], data["review"]
    assert p["chain_id"] == primary_id and p["token_id"] == "p-leaf"
    assert r["chain_id"] == review_id and r["token_id"] == "r-leaf"
    assert p["subject"] == "alice" and r["subject"] == "bob"
    assert p["decision"] == "allow" and r["decision"] == "allow"
    assert p["first_failed_node"] is None and r["first_failed_node"] is None
    assert {n["token_id"] for n in p["trace"]} == {"p-root", "p-leaf"}
    assert {n["token_id"] for n in r["trace"]} == {"r-root", "r-leaf"}
    leaf_checks = {c["name"] for n in p["trace"] if n["token_id"] == "p-leaf"
                   for c in n["checks"]}
    assert {"signature", "revocation_active", "time_valid",
            "method_allowed", "path_covered", "ip_allowed"} <= leaf_checks


def test_co_redeem_evaluated_at_is_server_time(client):
    primary_id, review_id = _setup(client)
    before = datetime.now(timezone.utc)
    resp = _co_redeem(client, primary_id, review_id, request_key="ck-time")
    after = datetime.now(timezone.utc)
    assert resp.status_code == 201
    evaluated = datetime.fromisoformat(resp.json()["evaluated_at"])
    assert before <= evaluated <= after + timedelta(seconds=1)


def test_chain_get_lists_co_redemption_leg_on_each_chain(client):
    primary_id, review_id = _setup(client)
    resp = _co_redeem(client, primary_id, review_id, request_key="ck-list")
    assert resp.status_code == 201
    redeemed_at = resp.json()["redeemed_at"]

    for chain_id, token_id in ((primary_id, "p-leaf"), (review_id, "r-leaf")):
        got = client.get(f"/api/v1/chains/{chain_id}").json()
        assert [e["request_key"] for e in got["redemptions"]] == ["ck-list"]
        event = got["redemptions"][0]
        assert event["chain_id"] == chain_id
        assert event["token_id"] == token_id
        assert event["request_path"] == "/files/reports/x"
        assert event["method"] == "GET"
        assert event["source_ip"] == "10.1.2.3"
        assert event["redeemed_at"] == redeemed_at
        assert event["evaluated_at"] == redeemed_at


# --------------------------------------------------------------------------- #
# 幂等：同键同内容回放首次会签结果（即使事后撤销 / 到期）
# --------------------------------------------------------------------------- #
def test_same_key_same_content_replays_first_result(client):
    primary_id, review_id = _setup(client)
    first = _co_redeem(client, primary_id, review_id, request_key="ck-replay",
                       body={"q": 1})
    assert first.status_code == 201
    second = _co_redeem(client, primary_id, review_id, request_key="ck-replay",
                        body={"q": 1})
    assert second.status_code == 200
    f, s = first.json(), second.json()
    assert s["replayed"] is True
    assert s["redeemed"] is True
    assert s["redeemed_at"] == f["redeemed_at"]
    assert s["evaluated_at"] == f["evaluated_at"]
    assert s["primary"] == f["primary"]
    assert s["review"] == f["review"]


def test_replay_returns_first_result_even_after_revocation(client):
    primary_id, review_id = _setup(client)
    first = _co_redeem(client, primary_id, review_id, request_key="ck-rev")
    assert first.status_code == 201
    # 会签成功后，复核链末端被撤销
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    revoked = client.post(
        f"/api/v1/chains/{review_id}/revocations",
        json={"token_id": "r-leaf", "effective_at": now,
              "reason": "事后撤销", "request_key": "ops-revoke-r"},
    )
    assert revoked.status_code == 201
    # 同键重放：仍返回首次双侧 allow 的会签结果
    replay = _co_redeem(client, primary_id, review_id, request_key="ck-rev")
    assert replay.status_code == 200
    body = replay.json()
    assert body["replayed"] is True
    assert body["redeemed"] is True
    assert body["primary"]["decision"] == "allow"
    assert body["review"]["decision"] == "allow"
    assert body["redeemed_at"] == first.json()["redeemed_at"]


def test_replay_returns_first_result_even_after_expiry(client):
    window = _now_window(nb=-3600, na=1)
    n = next(_chain_seq)
    primary_id, review_id = f"co-primary-{n}", f"co-review-{n}"
    for cid, root_id, leaf_id, subject, issuer in (
        (primary_id, "p-root", "p-leaf", "alice", "svc-a"),
        (review_id, "r-root", "r-leaf", "bob", "svc-b"),
    ):
        chain = _chain(cid, root_id, leaf_id, subject, issuer, window=window)
        assert client.post("/api/v1/chains", json=chain).status_code == 201
    first = _co_redeem(client, primary_id, review_id, request_key="ck-exp")
    assert first.status_code == 201

    import time as _time

    _time.sleep(1.1)
    replay = _co_redeem(client, primary_id, review_id, request_key="ck-exp")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["redeemed"] is True
    assert replay.json()["redeemed_at"] == first.json()["redeemed_at"]


def test_same_key_changed_content_conflicts(client):
    primary_id, review_id = _setup(client)
    assert _co_redeem(
        client, primary_id, review_id, request_key="ck-change"
    ).status_code == 201
    # 换路径 / 方法 / 来源 IP / 请求体 / 任一侧目标：均 409
    for kw in (
        {"request_path": "/files/reports/y"},
        {"method": "POST"},
        {"source_ip": "10.1.9.9"},
        {"body": {"other": 1}},
        {"p_token": "p-root"},
        {"r_token": "r-root"},
    ):
        resp = _co_redeem(client, primary_id, review_id,
                          request_key="ck-change", **kw)
        assert resp.status_code == 409, kw
        assert resp.json()["detail"]["request_key"] == "ck-change"


def test_same_key_swapped_sides_conflicts(client):
    primary_id, review_id = _setup(client)
    assert _co_redeem(
        client, primary_id, review_id, request_key="ck-swap"
    ).status_code == 201
    # 主 / 复核互换即换内容
    resp = _co_redeem(client, review_id, primary_id, request_key="ck-swap",
                      p_token="r-leaf", r_token="p-leaf")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["existing_sha256"] != detail["received_sha256"]


# --------------------------------------------------------------------------- #
# 一方拒绝 / 已核销：另一方不被消耗
# --------------------------------------------------------------------------- #
def test_denied_side_consumes_nothing_and_key_stays_reusable(client):
    # 复核链末端限定另一网段：共享来源 IP 只让复核侧拒绝
    primary_id, review_id = _setup(
        client, r_leaf_over={"allow_ip": "10.2.0.0/16"}
    )
    resp = _co_redeem(client, primary_id, review_id, request_key="ck-deny")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["redeemed"] is False
    assert data["redeemed_at"] is None
    assert data["primary"]["decision"] == "allow"
    assert data["review"]["decision"] == "deny"
    assert data["review"]["first_failed_reason"] == "ip_not_allowed"

    # 主授权侧未被消耗：可独立单链核销
    single = _single_redeem(client, primary_id, token_id="p-leaf",
                            request_key="co-rk-after-deny")
    assert single.status_code == 201

    # request_key 未被占用：换个主授权链后同键会签成功
    primary2, review2 = _setup(client)
    ok = _co_redeem(client, primary2, review2, request_key="ck-deny")
    assert ok.status_code == 201
    assert ok.json()["redeemed"] is True


def test_denied_co_redeem_then_same_key_success_replays(client):
    primary_id, review_id = _setup(client)
    bad = _co_redeem(client, primary_id, review_id, request_key="ck-seq",
                     method="POST")
    assert bad.status_code == 200 and bad.json()["redeemed"] is False
    ok = _co_redeem(client, primary_id, review_id, request_key="ck-seq")
    assert ok.status_code == 201 and ok.json()["redeemed"] is True
    replay = _co_redeem(client, primary_id, review_id, request_key="ck-seq")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["redeemed_at"] == ok.json()["redeemed_at"]


def test_revoked_side_denies_and_other_side_not_consumed(client):
    primary_id, review_id = _setup(client)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    assert client.post(
        f"/api/v1/chains/{review_id}/revocations",
        json={"token_id": "r-leaf", "effective_at": now,
              "reason": "泄露", "request_key": "ops-r"},
    ).status_code == 201
    resp = _co_redeem(client, primary_id, review_id, request_key="ck-revoked")
    assert resp.status_code == 200
    data = resp.json()
    assert data["redeemed"] is False
    assert data["review"]["decision"] == "deny"
    assert data["review"]["first_failed_reason"] == "revoked"
    assert data["review"]["first_revoked_node"] == "r-leaf"
    # 主授权侧未被消耗
    assert _single_redeem(
        client, primary_id, token_id="p-leaf", request_key="co-rk-p1"
    ).status_code == 201


def test_one_side_already_redeemed_conflicts_and_other_side_untouched(client):
    primary_id, review_id = _setup(client)
    # 主授权链末端先被单链核销
    assert _single_redeem(
        client, primary_id, token_id="p-leaf", request_key="co-rk-first"
    ).status_code == 201
    resp = _co_redeem(client, primary_id, review_id, request_key="ck-half")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["side"] == "primary"
    assert detail["existing_request_key"] == "co-rk-first"
    assert "未消耗任何一侧" in detail["detail"]
    # 复核侧未被消耗：仍可独立核销
    assert _single_redeem(
        client, review_id, token_id="r-leaf", request_key="co-rk-r1"
    ).status_code == 201


def test_second_co_redeem_reusing_one_side_conflicts(client):
    p1, r1 = _setup(client)
    assert _co_redeem(client, p1, r1, request_key="ck-1").status_code == 201
    # 新会签复用已核销的复核侧（换新键、新主授权链）
    p2, r2 = _setup(client)
    resp = _co_redeem(client, p2, r1, request_key="ck-2", r_token="r-leaf")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["side"] == "review"
    assert detail["existing_request_key"] == "ck-1"
    # 新主授权链 p2 未被这次失败消耗：与另一新复核链会签成功
    assert _co_redeem(client, p2, r2, request_key="ck-3").status_code == 201


# --------------------------------------------------------------------------- #
# 与单链核销的隔离：会签的一半不能被当作独立请求重放
# --------------------------------------------------------------------------- #
def test_single_redeem_cannot_replay_co_sign_half(client):
    primary_id, review_id = _setup(client)
    assert _co_redeem(
        client, primary_id, review_id, request_key="ck-co"
    ).status_code == 201
    # 换键单链核销会签的一侧：已核销 -> 409，而非再次成功
    resp = _single_redeem(client, primary_id, token_id="p-leaf",
                          request_key="co-rk-single")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["existing_request_key"] == "ck-co"
    assert "只能成功核销一次" in detail["detail"]
    # 用会签的同一把键走单链接口：同样不能成功重放
    resp2 = _single_redeem(client, primary_id, token_id="p-leaf",
                           request_key="ck-co")
    assert resp2.status_code == 409


def test_request_key_space_shared_with_single_redeem(client):
    primary_id, review_id = _setup(client)
    # 单链核销占用键 K 后，会签不得复用
    assert _single_redeem(
        client, primary_id, token_id="p-leaf", request_key="co-rk-shared"
    ).status_code == 201
    resp = _co_redeem(client, primary_id, review_id, request_key="co-rk-shared")
    assert resp.status_code == 409
    assert "单链核销" in resp.json()["detail"]["detail"]

    # 会签占用键 K2 后，单链核销不得复用（即便目标是另一条未核销链）
    p2, r2 = _setup(client)
    assert _co_redeem(client, p2, r2, request_key="ck-shared").status_code == 201
    p3, _ = _setup(client)
    resp2 = _single_redeem(client, p3, token_id="p-leaf",
                           request_key="ck-shared")
    assert resp2.status_code == 409
    assert "会签" in resp2.json()["detail"]["detail"]


# --------------------------------------------------------------------------- #
# 结构约束：两条链必须不同、末端 subject 必须不同、目标必须是末端
# --------------------------------------------------------------------------- #
def test_same_chain_for_both_sides_rejected_422(client):
    primary_id, _ = _setup(client)
    resp = _co_redeem(client, primary_id, primary_id, request_key="ck-same")
    assert resp.status_code == 422


def test_same_tip_subject_conflicts(client):
    primary_id, review_id = _setup(client, review_subject="alice")
    resp = _co_redeem(client, primary_id, review_id, request_key="ck-subj")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["subject"] == "alice"
    assert "不同主体" in detail["detail"]
    # 两侧均未被消耗
    assert _single_redeem(
        client, primary_id, token_id="p-leaf", request_key="co-rk-p2"
    ).status_code == 201
    assert _single_redeem(
        client, review_id, token_id="r-leaf", request_key="co-rk-r2"
    ).status_code == 201


def test_non_tip_target_conflicts(client):
    primary_id, review_id = _setup(client)
    resp = _co_redeem(client, primary_id, review_id, p_token="p-root",
                      request_key="ck-mid")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["side"] == "primary"
    assert detail["chain_tip_token_id"] == "p-leaf"
    # 未消耗：修正目标后同一 request_key 可成功
    ok = _co_redeem(client, primary_id, review_id, request_key="ck-mid")
    assert ok.status_code == 201


def test_unknown_chain_404(client):
    primary_id, review_id = _setup(client)
    resp = _co_redeem(client, "chain-missing", review_id, request_key="ck-404")
    assert resp.status_code == 404
    resp2 = _co_redeem(client, primary_id, "chain-missing",
                       request_key="ck-404b")
    assert resp2.status_code == 404


def test_unknown_token_404(client):
    primary_id, review_id = _setup(client)
    resp = _co_redeem(client, primary_id, review_id, r_token="ghost",
                      request_key="ck-ghost")
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# 并发：同一对末端仅一笔会签成功
# --------------------------------------------------------------------------- #
def test_concurrent_co_redeems_only_one_wins(client):
    primary_id, review_id = _setup(client)
    results: list[tuple[int, dict]] = []
    barrier = threading.Barrier(8)

    def worker(i: int) -> None:
        barrier.wait()
        resp = _co_redeem(client, primary_id, review_id,
                          request_key=f"ck-conc-{i}")
        results.append((resp.status_code, resp.json()))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    created = [r for r in results if r[0] == 201]
    conflicts = [r for r in results if r[0] == 409]
    assert len(created) == 1
    assert len(conflicts) == 7
    assert created[0][1]["redeemed"] is True
    for _, body in conflicts:
        assert "核销" in body["detail"]["detail"]


# --------------------------------------------------------------------------- #
# 与密钥轮换共存：各链按提交时锁定的代次验签
# --------------------------------------------------------------------------- #
def test_co_redeem_uses_locked_key_generations_after_rotation(client):
    # 专用签发主体，避免轮换影响其他用例共享的 svc-a
    assert client.post(
        "/api/v1/principals",
        json={"name": "svc-co-rot", "hmac_secret": "svc-co-rot-v1"},
    ).status_code == 201
    n = next(_chain_seq)
    primary_id, review_id = f"co-primary-{n}", f"co-review-{n}"
    assert client.post("/api/v1/chains", json=_chain(
        primary_id, "p-root", "p-leaf", "alice", "svc-co-rot",
        secret="svc-co-rot-v1",
    )).status_code == 201
    assert client.post("/api/v1/chains", json=_chain(
        review_id, "r-root", "r-leaf", "bob", "svc-b",
    )).status_code == 201
    # 轮换主授权链签发者的密钥；既有链仍按提交时锁定的代次验签
    rotated = client.post(
        "/api/v1/principals/svc-co-rot/rotate-key",
        json={"hmac_secret": "svc-co-rot-v2"},
    )
    assert rotated.status_code == 200
    resp = _co_redeem(client, primary_id, review_id, request_key="ck-rot")
    assert resp.status_code == 201, resp.text
    assert resp.json()["redeemed"] is True


def test_invalid_method_rejected_by_validation(client):
    primary_id, review_id = _setup(client)
    resp = client.post(
        "/api/v1/co-redemptions",
        json={
            "primary": {"chain_id": primary_id, "token_id": "p-leaf"},
            "review": {"chain_id": review_id, "token_id": "r-leaf"},
            "request_key": "ck-bad",
            "request_path": "/files/reports/x",
            "method": "GET POST",
        },
    )
    assert resp.status_code == 422
