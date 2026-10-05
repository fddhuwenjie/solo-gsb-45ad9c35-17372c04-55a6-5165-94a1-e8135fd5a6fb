"""提交时未注册签发者（unknown_issuer）的链：缺失事实随链持久化，结论永不翻转。

覆盖：
- 事后注册该主体（密钥恰好匹配旧签名）后，查询 / 重放 / 求值 / 首次核销仍拒绝；
- 事后注册并轮换到匹配旧签名的密钥，旧链仍不翻转；
- 旧库回填：提交时未注册的签发者不得归到后来注册的代次，原本有效的旧链
  仍按历史第 1 代密钥验签；
- 早期版本误写入的代次归属在启动回填时被修复；
- 撤销与同键重放等既有行为对这类链照旧。
"""
from __future__ import annotations

import itertools
import json
import sqlite3
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


def _submit_unknown(client, chain_id: str, issuer: str, issuer_secret: str) -> dict:
    payload = _chain2(chain_id, issuer, issuer_secret)
    resp = client.post("/api/v1/chains", json=payload)
    assert resp.status_code == 201, resp.text
    integrity = resp.json()["integrity"]
    assert integrity["allow"] is False
    assert integrity["first_failed_node"] == "child"
    assert integrity["first_failed_reason"] == "unknown_issuer"
    return payload


def _register(client, name: str, secret: str) -> None:
    resp = client.post(
        "/api/v1/principals", json={"name": name, "hmac_secret": secret}
    )
    assert resp.status_code == 201, resp.text


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


def _assert_still_unknown_issuer(client, chain_id: str, payload: dict) -> None:
    """查询 / 重放 / 求值 / 首次核销对该链全部保持提交时的 unknown_issuer 拒绝。"""
    got = client.get(f"/api/v1/chains/{chain_id}")
    assert got.status_code == 200
    assert got.json()["integrity"]["allow"] is False
    assert got.json()["integrity"]["first_failed_reason"] == "unknown_issuer"

    replay = client.post("/api/v1/chains", json=payload)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["integrity"]["allow"] is False
    assert replay.json()["integrity"]["first_failed_reason"] == "unknown_issuer"

    evaluated = _evaluate(client, chain_id)
    assert evaluated.status_code == 200
    assert evaluated.json()["decision"] == "deny"
    assert evaluated.json()["first_failed_reason"] == "unknown_issuer"

    denied = _redeem(client, chain_id, f"rk-{chain_id}")
    assert denied.status_code == 200
    assert denied.json()["redeemed"] is False
    assert denied.json()["replayed"] is False
    assert denied.json()["decision"] == "deny"
    assert denied.json()["first_failed_reason"] == "unknown_issuer"


# --------------------------------------------------------------------------- #
# 事后注册（密钥恰好匹配旧签名）：结论不翻转
# --------------------------------------------------------------------------- #
def test_unregistered_issuer_chain_never_flips_after_registration(client):
    from app.database import (
        get_conn,
        load_chain_key_generations,
        load_chain_missing_issuers,
    )

    name = f"ghost-{next(_principal_seq)}"
    ghost_secret = f"{name}-secret"
    chain_id = f"chain-ghost-{next(_chain_seq)}"
    payload = _submit_unknown(client, chain_id, name, ghost_secret)

    # “提交时缺失密钥”的事实随链持久化；归属表只记录已注册的 root
    with get_conn() as conn:
        assert load_chain_missing_issuers(conn, chain_id) == {name}
        assert load_chain_key_generations(conn, chain_id) == {"root": 1}

    # 事后用“恰好匹配旧签名”的密钥注册该主体
    _register(client, name, ghost_secret)

    # 查询 / 重放 / 求值 / 首次核销：全部保持提交时的拒绝结论
    _assert_still_unknown_issuer(client, chain_id, payload)

    # 注册本身对新链生效：同一密钥签出的新链正常通过
    fresh_id = f"chain-ghost-{next(_chain_seq)}"
    fresh = client.post("/api/v1/chains", json=_chain2(fresh_id, name, ghost_secret))
    assert fresh.status_code == 201
    assert fresh.json()["integrity"]["allow"] is True
    assert _evaluate(client, fresh_id).json()["decision"] == "allow"


def test_unregistered_issuer_chain_never_flips_after_rotation_to_matching_key(client):
    name = f"ghost-{next(_principal_seq)}"
    future_secret = f"{name}-secret-v2"
    chain_id = f"chain-ghost-{next(_chain_seq)}"
    # 用“未来的第 2 代密钥”签名：提交时主体未注册，链以 unknown_issuer 落库
    payload = _submit_unknown(client, chain_id, name, future_secret)

    # 事后注册（第 1 代密钥与签名不符），再轮换到匹配旧签名的第 2 代密钥
    _register(client, name, f"{name}-secret-v1")
    rotated = client.post(
        f"/api/v1/principals/{name}/rotate-key",
        json={"hmac_secret": future_secret},
    )
    assert rotated.status_code == 200
    assert rotated.json()["generation"] == 2

    # 当前密钥已能匹配旧签名，但旧链结论不翻转
    _assert_still_unknown_issuer(client, chain_id, payload)


def test_unknown_issuer_chain_revocation_and_replay_behave_as_usual(client):
    name = f"ghost-{next(_principal_seq)}"
    chain_id = f"chain-ghost-{next(_chain_seq)}"
    _submit_unknown(client, chain_id, name, f"{name}-secret")
    _register(client, name, f"{name}-secret")

    # 撤销事件照常追加（撤销不依赖验签）
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    revoked = client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "child",
            "effective_at": now,
            "reason": "运维安全事件",
            "request_key": f"ops-{chain_id}",
        },
    )
    assert revoked.status_code == 201
    assert revoked.json()["affected_token_ids"] == ["child"]

    # 撤销的同键同内容重放照旧幂等
    replay = client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "child",
            "effective_at": now,
            "reason": "运维安全事件",
            "request_key": f"ops-{chain_id}",
        },
    )
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True

    # 求值仍拒绝：首个失败仍是提交时的 unknown_issuer，撤销信息照常标注
    evaluated = _evaluate(client, chain_id).json()
    assert evaluated["decision"] == "deny"
    assert evaluated["first_failed_reason"] == "unknown_issuer"
    assert evaluated["first_revoked_node"] == "child"


# --------------------------------------------------------------------------- #
# 旧库回填：不得把提交时未注册的签发者归到后来注册的代次
# --------------------------------------------------------------------------- #
def _legacy_schema() -> str:
    return """
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


def _report_json(chain_id: str, tokens: list[dict], secrets: dict[str, str]) -> str:
    """用真实引擎生成提交时报告（secrets 之外的签发者即“提交时未注册”）。"""
    from app.engine import validate_chain
    from app.models import CapabilityToken, ChainSubmission

    submission = ChainSubmission(
        chain_id=chain_id,
        tokens=[CapabilityToken.model_validate(t) for t in tokens],
    )
    report, _ = validate_chain(submission, secrets.get)
    return report.model_dump_json()


def _insert_chain(
    conn: sqlite3.Connection, chain_id: str, tokens: list[dict], report_json: str
) -> None:
    conn.execute(
        "INSERT INTO chains (chain_id, content_sha256, report_json, created_at) "
        "VALUES (?, ?, ?, '2026-01-01T00:00:00+00:00')",
        (chain_id, "0" * 64, report_json),
    )
    for pos, token in enumerate(tokens):
        conn.execute(
            "INSERT INTO tokens (chain_id, position, token_json) VALUES (?, ?, ?)",
            (chain_id, pos, json.dumps(token)),
        )


def _legacy_chains() -> tuple[list[dict], list[dict]]:
    """两条旧链：legacy-ok（提交时有效）与 legacy-unknown（提交时 ghost 未注册）。

    ghost 的签名密钥就是其后来注册的第 1 代密钥——若回填误绑代次，旧链会翻转。
    """
    ok = _chain2("legacy-ok", "legacy-a", "legacy-v1")["tokens"]
    unknown = _chain2("legacy-unknown", "ghost", "ghost-v1")["tokens"]
    return ok, unknown


def _create_legacy_db(path: str) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(_legacy_schema())
    conn.execute(
        "INSERT INTO principals (name, hmac_secret) VALUES ('root', 'test-root-secret')"
    )
    conn.execute(
        "INSERT INTO principals (name, hmac_secret) VALUES ('legacy-a', 'legacy-v1')"
    )
    # ghost 是链提交之后才注册的主体（旧库中只有当前状态，无法区分注册先后）
    conn.execute(
        "INSERT INTO principals (name, hmac_secret) VALUES ('ghost', 'ghost-v1')"
    )
    ok, unknown = _legacy_chains()
    secrets = {"root": "test-root-secret", "legacy-a": "legacy-v1"}
    _insert_chain(conn, "legacy-ok", ok, _report_json("legacy-ok", ok, secrets))
    _insert_chain(
        conn, "legacy-unknown", unknown, _report_json("legacy-unknown", unknown, secrets)
    )
    conn.commit()
    conn.close()


def test_backfill_never_attributes_unknown_issuer_to_later_generation(tmp_path):
    from app.database import (
        connect,
        init_db,
        install_next_key_generation,
        load_chain_key_generations,
        load_chain_missing_issuers,
        load_submission,
    )
    from app.engine import validate_chain
    from app.main import _chain_secret_lookup

    db_path = str(tmp_path / "legacy.db")
    _create_legacy_db(db_path)

    conn = connect(db_path)
    init_db(conn)

    # 提交时有效的旧链：归属到第 1 代，仍按历史密钥验签
    assert load_chain_key_generations(conn, "legacy-ok") == {
        "root": 1,
        "legacy-a": 1,
    }
    ok_submission = load_submission(conn, "legacy-ok")
    report, _ = validate_chain(ok_submission, _chain_secret_lookup(conn, "legacy-ok"))
    assert report.allow is True

    # 提交时 ghost 未注册的旧链：不得归到 ghost 后来注册的第 1 代；
    # 缺失事实落表，重验仍是 unknown_issuer（尽管 ghost 当前密钥匹配旧签名）
    assert load_chain_key_generations(conn, "legacy-unknown") == {"root": 1}
    assert load_chain_missing_issuers(conn, "legacy-unknown") == {"ghost"}
    unknown_submission = load_submission(conn, "legacy-unknown")
    report, _ = validate_chain(
        unknown_submission, _chain_secret_lookup(conn, "legacy-unknown")
    )
    assert report.allow is False
    assert report.first_failed_reason == "unknown_issuer"

    # 回填幂等：再跑一次结论不变
    init_db(conn)
    assert load_chain_key_generations(conn, "legacy-unknown") == {"root": 1}
    assert load_chain_missing_issuers(conn, "legacy-unknown") == {"ghost"}

    # 有效旧链在轮换后仍按提交时锁定的第 1 代密钥验签
    generation, _ = install_next_key_generation(conn, "legacy-a", "legacy-v2")
    assert generation == 2
    conn.commit()
    report, _ = validate_chain(ok_submission, _chain_secret_lookup(conn, "legacy-ok"))
    assert report.allow is True
    conn.close()


def test_backfill_repairs_earlier_misattribution(tmp_path):
    """早期版本回填误把 ghost 归到第 1 代：启动回填应清除误归属并补记缺失事实。"""
    from app.database import (
        connect,
        init_db,
        load_chain_key_generations,
        load_chain_missing_issuers,
        load_submission,
    )
    from app.engine import validate_chain
    from app.main import _chain_secret_lookup

    db_path = str(tmp_path / "misattributed.db")
    conn = connect(db_path)
    init_db(conn)  # 建当前 schema

    unknown = _chain2("legacy-unknown", "ghost", "ghost-v1")["tokens"]
    secrets = {"root": "test-root-secret"}
    conn.execute(
        "INSERT INTO principals (name, hmac_secret) VALUES ('root', 'test-root-secret')"
    )
    conn.execute(
        "INSERT INTO principals (name, hmac_secret) VALUES ('ghost', 'ghost-v1')"
    )
    _insert_chain(
        conn, "legacy-unknown", unknown, _report_json("legacy-unknown", unknown, secrets)
    )
    # 模拟旧版回填的误归属：ghost 被绑到后注册的第 1 代
    conn.execute(
        "INSERT INTO chain_key_generations (chain_id, principal, generation) "
        "VALUES ('legacy-unknown', 'root', 1)"
    )
    conn.execute(
        "INSERT INTO chain_key_generations (chain_id, principal, generation) "
        "VALUES ('legacy-unknown', 'ghost', 1)"
    )
    conn.commit()

    # 重启（再次 init_db）：误归属被清除，缺失事实落表
    init_db(conn)
    assert load_chain_key_generations(conn, "legacy-unknown") == {"root": 1}
    assert load_chain_missing_issuers(conn, "legacy-unknown") == {"ghost"}

    submission = load_submission(conn, "legacy-unknown")
    report, _ = validate_chain(
        submission, _chain_secret_lookup(conn, "legacy-unknown")
    )
    assert report.allow is False
    assert report.first_failed_reason == "unknown_issuer"
    conn.close()
