"""HMAC 密钥轮换：代次归属、轮换后验签、既有链结论冻结、原子切换与迁移。"""
from __future__ import annotations

import itertools
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from tests.conftest import make_token

_principal_seq = itertools.count(1)
_chain_seq = itertools.count(1)


def _now_window(**offsets) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    nb = now + timedelta(seconds=offsets.get("nb", -3600))
    na = now + timedelta(seconds=offsets.get("na", 3600))
    return (
        nb.isoformat().replace("+00:00", "Z"),
        na.isoformat().replace("+00:00", "Z"),
    )


def _new_principal(client) -> tuple[str, str]:
    """注册一个独立主体（避免影响其他测试文件的固定主体），返回 (名字, 初始密钥)。"""
    name = f"rot-svc-{next(_principal_seq)}"
    secret = f"{name}-secret-v1"
    resp = client.post(
        "/api/v1/principals", json={"name": name, "hmac_secret": secret}
    )
    assert resp.status_code == 201, resp.text
    return name, secret


def _rotate(client, name: str, new_secret: str):
    return client.post(
        f"/api/v1/principals/{name}/rotate-key", json={"hmac_secret": new_secret}
    )


def _chain2(chain_id: str, issuer: str, issuer_secret: str) -> dict:
    """root -> child 两级链；child 由 issuer 用 issuer_secret 签名（当前时刻有效）。"""
    nb, na = _now_window()
    root = make_token(
        "root", None, "root", issuer,
        "/files/**", ["GET", "POST"],
        not_before=nb, not_after=na, chain_id=chain_id,
    )
    child = make_token(
        "child", "root", issuer, "svc-b",
        "/files/x", ["GET"],
        not_before=nb, not_after=na, chain_id=chain_id,
        secret=issuer_secret,
    )
    return {"chain_id": chain_id, "tokens": [root, child]}


def _submit(client, chain_id: str, issuer: str, issuer_secret: str):
    payload = _chain2(chain_id, issuer, issuer_secret)
    resp = client.post("/api/v1/chains", json=payload)
    assert resp.status_code == 201, resp.text
    return payload, resp.json()


def _evaluate(client, chain_id: str):
    at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return client.post(
        f"/api/v1/chains/{chain_id}/evaluate",
        json={"request_path": "/files/x", "method": "GET", "at": at},
    )


def _redeem(client, chain_id: str, request_key: str):
    return client.post(
        f"/api/v1/chains/{chain_id}/redeem",
        json={
            "token_id": "child",
            "request_key": request_key,
            "request_path": "/files/x",
            "method": "GET",
        },
    )


# --------------------------------------------------------------------------- #
# 轮换端点契约
# --------------------------------------------------------------------------- #
def test_rotate_unknown_principal_404(client):
    resp = _rotate(client, "ghost-principal", "whatever")
    assert resp.status_code == 404
    assert "ghost-principal" in resp.json()["detail"]


def test_rotate_success_increments_generation_and_leaks_no_secret(client):
    name, secret = _new_principal(client)
    resp = _rotate(client, name, f"{name}-secret-v2")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {"name", "generation", "rotated_at"}
    assert body["name"] == name
    assert body["generation"] == 2
    assert body["rotated_at"]
    # 任何响应都不得泄露密钥材料
    assert secret not in resp.text
    assert f"{name}-secret-v2" not in resp.text


def test_rotate_to_same_secret_conflicts_and_leaves_no_partial_switch(client):
    name, secret = _new_principal(client)
    resp = _rotate(client, name, secret)
    assert resp.status_code == 409

    # 失败不留部分切换：当前代次仍是 1，新链仍按原密钥验签
    chain_id = f"chain-rot-{next(_chain_seq)}"
    _, body = _submit(client, chain_id, name, secret)
    assert body["integrity"]["allow"] is True

    # 随后的真实轮换应落到第 2 代（若 409 留下部分切换，这里会变成 3）
    rotated = _rotate(client, name, f"{name}-secret-v2")
    assert rotated.status_code == 200
    assert rotated.json()["generation"] == 2


def test_rotate_empty_secret_rejected(client):
    name, _ = _new_principal(client)
    resp = _rotate(client, name, "")
    assert resp.status_code == 422


def test_register_response_leaks_no_secret(client):
    resp = client.post(
        "/api/v1/principals",
        json={"name": f"rot-svc-{next(_principal_seq)}", "hmac_secret": "top-secret"},
    )
    assert resp.status_code == 201
    assert "top-secret" not in resp.text


# --------------------------------------------------------------------------- #
# 轮换后：新链只按新密钥验签
# --------------------------------------------------------------------------- #
def test_new_chains_verify_only_against_new_key_after_rotation(client):
    name, secret_v1 = _new_principal(client)
    secret_v2 = f"{name}-secret-v2"
    assert _rotate(client, name, secret_v2).status_code == 200

    # 旧密钥签出的新链不得通过
    stale_id = f"chain-rot-{next(_chain_seq)}"
    _, stale = _submit(client, stale_id, name, secret_v1)
    assert stale["integrity"]["allow"] is False
    assert stale["integrity"]["first_failed_reason"] == "bad_signature"

    # 新密钥签出的新链正常通过
    fresh_id = f"chain-rot-{next(_chain_seq)}"
    _, fresh = _submit(client, fresh_id, name, secret_v2)
    assert fresh["integrity"]["allow"] is True
    assert _evaluate(client, fresh_id).json()["decision"] == "allow"


# --------------------------------------------------------------------------- #
# 轮换前保存的链：结论冻结
# --------------------------------------------------------------------------- #
def test_prerotation_chain_keeps_verdict_on_get_evaluate_and_replay(client):
    name, secret_v1 = _new_principal(client)
    chain_id = f"chain-rot-{next(_chain_seq)}"
    payload, submitted = _submit(client, chain_id, name, secret_v1)
    assert submitted["integrity"]["allow"] is True

    assert _rotate(client, name, f"{name}-secret-v2").status_code == 200

    # 链查询：仍是提交时（轮换前密钥）的验签结论
    got = client.get(f"/api/v1/chains/{chain_id}")
    assert got.status_code == 200
    assert got.json()["integrity"]["allow"] is True

    # 只读求值：继续用轮换前的密钥重验，结论不变
    assert _evaluate(client, chain_id).json()["decision"] == "allow"

    # 同内容重放：返回与首次一致的验签结论
    replay = client.post("/api/v1/chains", json=payload)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["integrity"]["allow"] is True


def test_invalid_chain_does_not_turn_valid_when_new_key_happens_to_match(client):
    name, secret_v1 = _new_principal(client)
    future_secret = f"{name}-secret-v2"

    # 用“未来的新密钥”签名：按当前密钥（v1）验签必然失败，链以无效结论落库
    chain_id = f"chain-rot-{next(_chain_seq)}"
    payload, submitted = _submit(client, chain_id, name, future_secret)
    assert submitted["integrity"]["allow"] is False
    assert submitted["integrity"]["first_failed_reason"] == "bad_signature"

    # 轮换到该密钥：既有无效链不得因新密钥恰好匹配而翻转为有效
    assert _rotate(client, name, future_secret).status_code == 200

    got = client.get(f"/api/v1/chains/{chain_id}").json()
    assert got["integrity"]["allow"] is False

    evaluated = _evaluate(client, chain_id).json()
    assert evaluated["decision"] == "deny"
    assert evaluated["first_failed_reason"] == "bad_signature"

    replay = client.post("/api/v1/chains", json=payload)
    assert replay.status_code == 200
    assert replay.json()["integrity"]["allow"] is False


def test_multiple_rotations_keep_each_chains_generation(client):
    name, secret_v1 = _new_principal(client)
    secret_v2 = f"{name}-secret-v2"
    secret_v3 = f"{name}-secret-v3"

    id1 = f"chain-rot-{next(_chain_seq)}"
    _submit(client, id1, name, secret_v1)
    assert _rotate(client, name, secret_v2).json()["generation"] == 2

    id2 = f"chain-rot-{next(_chain_seq)}"
    _submit(client, id2, name, secret_v2)
    assert _rotate(client, name, secret_v3).json()["generation"] == 3

    id3 = f"chain-rot-{next(_chain_seq)}"
    _submit(client, id3, name, secret_v3)

    # 三代链各自按提交时锁定的代次重验，全部维持 allow
    for chain_id in (id1, id2, id3):
        assert _evaluate(client, chain_id).json()["decision"] == "allow"

    # 旧代次密钥（v2 已轮换）签出的新链不得通过
    stale_id = f"chain-rot-{next(_chain_seq)}"
    _, stale = _submit(client, stale_id, name, secret_v2)
    assert stale["integrity"]["allow"] is False
    assert stale["integrity"]["first_failed_reason"] == "bad_signature"


# --------------------------------------------------------------------------- #
# 撤销与一次性核销在轮换前后照常
# --------------------------------------------------------------------------- #
def test_revocation_still_processed_after_rotation(client):
    name, secret_v1 = _new_principal(client)
    chain_id = f"chain-rot-{next(_chain_seq)}"
    _submit(client, chain_id, name, secret_v1)
    assert _rotate(client, name, f"{name}-secret-v2").status_code == 200

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    revoked = client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "child",
            "effective_at": now,
            "reason": "轮换后撤销",
            "request_key": f"ops-{chain_id}",
        },
    )
    assert revoked.status_code == 201
    assert revoked.json()["affected_token_ids"] == ["child"]

    evaluated = _evaluate(client, chain_id).json()
    assert evaluated["decision"] == "deny"
    assert evaluated["first_failed_reason"] == "revoked"
    assert evaluated["first_revoked_node"] == "child"

    # 撤销后首次核销：判定拒绝，不核销、不占 request_key
    denied = _redeem(client, chain_id, f"rk-{chain_id}")
    assert denied.status_code == 200
    assert denied.json()["redeemed"] is False
    assert denied.json()["decision"] == "deny"


def test_first_redeem_after_rotation_uses_prerotation_key(client):
    name, secret_v1 = _new_principal(client)
    chain_id = f"chain-rot-{next(_chain_seq)}"
    _submit(client, chain_id, name, secret_v1)
    assert _rotate(client, name, f"{name}-secret-v2").status_code == 200

    # 首次核销：按链提交时锁定的旧密钥重验，结论与轮换前一致
    resp = _redeem(client, chain_id, f"rk-{chain_id}")
    assert resp.status_code == 201, resp.text
    assert resp.json()["redeemed"] is True
    assert resp.json()["decision"] == "allow"

    # 同键同内容重放：仍返回首次结果
    replay = _redeem(client, chain_id, f"rk-{chain_id}")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["redeemed_at"] == resp.json()["redeemed_at"]


def test_redeem_replay_after_rotation_returns_first_result(client):
    name, secret_v1 = _new_principal(client)
    chain_id = f"chain-rot-{next(_chain_seq)}"
    _submit(client, chain_id, name, secret_v1)

    first = _redeem(client, chain_id, f"rk-{chain_id}")
    assert first.status_code == 201

    assert _rotate(client, name, f"{name}-secret-v2").status_code == 200

    # 已核销请求的同键同内容重放仍返回首次结果（与轮换无关）
    replay = _redeem(client, chain_id, f"rk-{chain_id}")
    assert replay.status_code == 200
    body = replay.json()
    assert body["replayed"] is True
    assert body["redeemed"] is True
    assert body["decision"] == "allow"
    assert body["redeemed_at"] == first.json()["redeemed_at"]
    assert body["trace"] == first.json()["trace"]


# --------------------------------------------------------------------------- #
# 轮换与链提交并发：密钥归属与提交时验签结果一致
# --------------------------------------------------------------------------- #
def test_concurrent_rotation_and_submission_attribution_consistent(client):
    name, secret_v1 = _new_principal(client)
    barrier = threading.Barrier(7)
    results: list[tuple[str, bool, str | None]] = []

    def submitter(i: int) -> None:
        chain_id = f"chain-rot-conc-{i}"
        payload = _chain2(chain_id, name, secret_v1)
        barrier.wait()
        resp = client.post("/api/v1/chains", json=payload)
        assert resp.status_code == 201, resp.text
        integrity = resp.json()["integrity"]
        results.append(
            (chain_id, integrity["allow"], integrity["first_failed_reason"])
        )

    threads = [threading.Thread(target=submitter, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    barrier.wait()  # 与 6 个提交并发执行轮换
    rotated = _rotate(client, name, f"{name}-secret-v2")
    assert rotated.status_code == 200
    for t in threads:
        t.join()

    assert len(results) == 6
    for chain_id, allow, reason in results:
        # 无论提交落在轮换前还是后，链的密钥归属必须与提交时的验签结果一致：
        # 之后的链查询与只读求值重验，结论与提交时完全相同
        got = client.get(f"/api/v1/chains/{chain_id}").json()
        assert got["integrity"]["allow"] is allow
        evaluated = _evaluate(client, chain_id).json()
        assert (evaluated["decision"] == "allow") is allow
        if not allow:
            assert reason == "bad_signature"
            assert evaluated["first_failed_reason"] == "bad_signature"


# --------------------------------------------------------------------------- #
# 既有数据库迁移：旧库归一到第 1 代，轮换后旧链结论不变
# --------------------------------------------------------------------------- #
def _create_legacy_db(path: str) -> None:
    """构造轮换功能上线前的旧 schema 数据库（无代次列、无密钥历史表）。"""
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE principals (
            name        TEXT PRIMARY KEY,
            hmac_secret TEXT NOT NULL
        );
        CREATE TABLE chains (
            chain_id       TEXT PRIMARY KEY,
            content_sha256 TEXT NOT NULL,
            report_json    TEXT NOT NULL,
            created_at     TEXT NOT NULL
        );
        CREATE TABLE tokens (
            chain_id    TEXT NOT NULL,
            position    INTEGER NOT NULL,
            token_json  TEXT NOT NULL,
            PRIMARY KEY (chain_id, position)
        );
        """
    )
    conn.execute(
        "INSERT INTO principals (name, hmac_secret) VALUES ('root', 'test-root-secret')"
    )
    conn.execute(
        "INSERT INTO principals (name, hmac_secret) VALUES ('legacy-a', 'legacy-v1')"
    )
    root = make_token(
        "root", None, "root", "legacy-a", "/files/**", ["GET"],
        chain_id="legacy-chain",
    )
    child = make_token(
        "child", "root", "legacy-a", "svc-b", "/files/x", ["GET"],
        chain_id="legacy-chain", secret="legacy-v1",
    )
    conn.execute(
        "INSERT INTO chains (chain_id, content_sha256, report_json, created_at) "
        "VALUES ('legacy-chain', '0' * 64, '{}', '2026-01-01T00:00:00+00:00')"
    )
    for pos, token in enumerate((root, child)):
        import json as _json

        conn.execute(
            "INSERT INTO tokens (chain_id, position, token_json) VALUES (?, ?, ?)",
            ("legacy-chain", pos, _json.dumps(token)),
        )
    conn.commit()
    conn.close()


def test_legacy_database_is_migrated_and_backfilled(tmp_path):
    from app.database import (
        connect,
        get_principal_key_row,
        get_secret_at_generation,
        init_db,
        install_next_key_generation,
        load_chain_key_generations,
        load_submission,
    )
    from app.engine import validate_chain
    from app.main import _chain_secret_lookup

    db_path = str(tmp_path / "legacy.db")
    _create_legacy_db(db_path)

    conn = connect(db_path)
    init_db(conn)

    # 迁移：既有主体归一到第 1 代，既有链归属到第 1 代
    assert get_principal_key_row(conn, "legacy-a")["current_generation"] == 1
    assert get_secret_at_generation(conn, "legacy-a", 1) == "legacy-v1"
    assert load_chain_key_generations(conn, "legacy-chain") == {
        "root": 1,
        "legacy-a": 1,
    }

    # 迁移后旧链按第 1 代密钥重验：结论与迁移前一致
    submission = load_submission(conn, "legacy-chain")
    assert submission is not None
    report, _ = validate_chain(submission, _chain_secret_lookup(conn, "legacy-chain"))
    assert report.allow is True

    # 轮换后：旧链仍按第 1 代重验；新代次密钥不影响既有链
    generation, _ = install_next_key_generation(conn, "legacy-a", "legacy-v2")
    assert generation == 2
    conn.commit()
    report, _ = validate_chain(submission, _chain_secret_lookup(conn, "legacy-chain"))
    assert report.allow is True
    conn.close()
