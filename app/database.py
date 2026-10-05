"""SQLite 持久层：主体密钥（含代次历史）、能力链及完整性报告。"""
from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

from .config import settings
from .models import (
    CapabilityToken,
    ChainSubmission,
    CoRedemptionEvent,
    IntegrityReport,
    RedemptionEvent,
    RevocationEvent,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS principals (
    name               TEXT PRIMARY KEY,
    hmac_secret        TEXT NOT NULL,
    current_generation INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS chains (
    chain_id       TEXT PRIMARY KEY,
    content_sha256 TEXT NOT NULL,
    report_json    TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    chain_id    TEXT NOT NULL,
    position    INTEGER NOT NULL,
    token_json  TEXT NOT NULL,
    PRIMARY KEY (chain_id, position),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 主体 HMAC 密钥的完整代次历史（只追加）：注册为第 1 代，每次轮换追加一代并
-- 切换 principals.current_generation；旧代次永久保留，供轮换前提交的链重验。
CREATE TABLE IF NOT EXISTS principal_keys (
    principal    TEXT NOT NULL,
    generation   INTEGER NOT NULL,
    hmac_secret  TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (principal, generation),
    FOREIGN KEY (principal) REFERENCES principals (name)
);

-- 每条链在提交时锁定的“签发主体 -> 密钥代次”归属（随链写入，之后不可变）。
-- 链重放 / 求值 / 核销重验签名时按此归属取密钥：轮换不改变既有链的验签结论。
CREATE TABLE IF NOT EXISTS chain_key_generations (
    chain_id   TEXT NOT NULL,
    principal  TEXT NOT NULL,
    generation INTEGER NOT NULL,
    PRIMARY KEY (chain_id, principal),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 每条链在提交时“签发主体未注册、无法取得密钥”的事实（随链写入，之后不可变）。
-- 与 chain_key_generations 互补：归属表记录提交时已注册主体的代次，本表记录
-- 提交时未注册的主体。事后注册该主体（甚至轮换到匹配旧签名的密钥）都不会让
-- 旧链的 unknown_issuer 结论翻转。
CREATE TABLE IF NOT EXISTS chain_missing_issuers (
    chain_id   TEXT NOT NULL,
    principal  TEXT NOT NULL,
    PRIMARY KEY (chain_id, principal),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 撤销事件为只追加（append-only）审计记录：无更新 / 删除路径。
-- request_key 全局唯一（跨链也不可复用）；同一令牌至多一条有效撤销事件。
CREATE TABLE IF NOT EXISTS revocations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id       TEXT NOT NULL,
    token_id       TEXT NOT NULL,
    effective_at   TEXT NOT NULL,
    reason         TEXT NOT NULL,
    request_key    TEXT NOT NULL UNIQUE,
    content_sha256 TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    UNIQUE (chain_id, token_id),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 一次性访问核销：只在“末端 + 判定允许”时追加，成功后令牌不可再次核销。
-- request_key 全局唯一（重放/冲突判定）；同一链内同一令牌至多成功核销一次。
CREATE TABLE IF NOT EXISTS redemptions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id       TEXT NOT NULL,
    token_id       TEXT NOT NULL,
    request_key    TEXT NOT NULL UNIQUE,
    request_path   TEXT NOT NULL,
    method         TEXT NOT NULL,
    source_ip      TEXT,
    request_body   TEXT,
    content_sha256 TEXT NOT NULL,
    evaluated_at   TEXT NOT NULL,
    redeemed_at    TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    result_json    TEXT NOT NULL,
    UNIQUE (chain_id, token_id),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 双主体会签核销：主授权链与复核链的末端在同一事务内同时核销，或都不核销。
-- request_key 全局唯一（与单链核销共用同一键空间，由应用层交叉检查兜底）；
-- 每条链的末端令牌至多参与一次成功会签（含作为任一侧）。
CREATE TABLE IF NOT EXISTS co_redemptions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    request_key      TEXT NOT NULL UNIQUE,
    primary_chain_id TEXT NOT NULL,
    primary_token_id TEXT NOT NULL,
    review_chain_id  TEXT NOT NULL,
    review_token_id  TEXT NOT NULL,
    request_path     TEXT NOT NULL,
    method           TEXT NOT NULL,
    source_ip        TEXT,
    request_body     TEXT,
    content_sha256   TEXT NOT NULL,
    evaluated_at     TEXT NOT NULL,
    redeemed_at      TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    result_json      TEXT NOT NULL,
    UNIQUE (primary_chain_id, primary_token_id),
    UNIQUE (review_chain_id, review_token_id),
    FOREIGN KEY (primary_chain_id) REFERENCES chains (chain_id),
    FOREIGN KEY (review_chain_id) REFERENCES chains (chain_id)
);
"""

DEMO_PRINCIPALS = {
    "root": settings.root_hmac_secret,
    "service-a": "demo-secret-service-a",
    "service-b": "demo-secret-service-b",
    "alice": "demo-secret-alice",
}


def connect(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or settings.db_path
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # 并发写事务（BEGIN IMMEDIATE）锁竞争时等待而非立刻 SQLITE_BUSY
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_db() -> Iterator[sqlite3.Connection]:
    """FastAPI 依赖：每请求一个连接，自动提交 / 回滚。"""
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    _migrate_principals(conn)
    if settings.seed_demo_principals:
        conn.executemany(
            "INSERT OR IGNORE INTO principals (name, hmac_secret) VALUES (?, ?)",
            list(DEMO_PRINCIPALS.items()),
        )
    _backfill_key_tables(conn)
    conn.commit()


def _migrate_principals(conn: sqlite3.Connection) -> None:
    """为轮换功能上线前创建的既有库补充 current_generation 列（已有数据归一到第 1 代）。"""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(principals)")}
    if "current_generation" not in cols:
        conn.execute(
            "ALTER TABLE principals "
            "ADD COLUMN current_generation INTEGER NOT NULL DEFAULT 1"
        )


def _backfill_key_tables(conn: sqlite3.Connection) -> None:
    """把轮换功能上线前的数据归一到第 1 代密钥（幂等，可每次启动执行）。

    - 尚无密钥历史的主体：以其当前 hmac_secret 作为第 1 代（轮换过的主体已有
      历史行，INSERT OR IGNORE 自然跳过，不会用当前密钥覆盖旧代次）；
    - 既有链的密钥归属回填见 :func:`_backfill_chain_attributions`。
    """
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR IGNORE INTO principal_keys "
        "(principal, generation, hmac_secret, created_at) "
        "SELECT name, 1, hmac_secret, ? FROM principals",
        (now,),
    )
    _backfill_chain_attributions(conn)


def _backfill_chain_attributions(conn: sqlite3.Connection) -> None:
    """回填既有链的“提交时密钥归属”（幂等，可每次启动执行）。

    以随链保存的提交时完整性报告为准区分两类签发者：

    - 报告中含 ``unknown_issuer`` 失败的主体：提交时未注册。把缺失事实记入
      ``chain_missing_issuers``，并清除早期版本误写入的代次归属——绝不把
      提交时未注册的签发者归到后来注册的密钥代次；
    - 其余签发者：提交时已注册（轮换功能上线前只有一代密钥），归属到第 1 代，
      原本有效的旧链继续按该历史密钥验签。
    """
    chains = conn.execute("SELECT chain_id, report_json FROM chains").fetchall()
    if not chains:
        return
    issuers_by_chain: dict[str, set[str]] = {}
    for row in conn.execute(
        "SELECT DISTINCT chain_id, "
        "json_extract(token_json, '$.issuer') AS issuer FROM tokens"
    ).fetchall():
        issuers_by_chain.setdefault(row["chain_id"], set()).add(row["issuer"])
    registered = {
        row["name"] for row in conn.execute("SELECT name FROM principals").fetchall()
    }
    for chain in chains:
        chain_id = chain["chain_id"]
        unknown = _report_unknown_issuers(chain["report_json"])
        for name in sorted(unknown):
            conn.execute(
                "DELETE FROM chain_key_generations "
                "WHERE chain_id = ? AND principal = ?",
                (chain_id, name),
            )
            conn.execute(
                "INSERT OR IGNORE INTO chain_missing_issuers (chain_id, principal) "
                "VALUES (?, ?)",
                (chain_id, name),
            )
        for name in sorted(issuers_by_chain.get(chain_id, set()) - unknown):
            if name in registered:
                conn.execute(
                    "INSERT OR IGNORE INTO chain_key_generations "
                    "(chain_id, principal, generation) VALUES (?, ?, 1)",
                    (chain_id, name),
                )


def _report_unknown_issuers(report_json: str) -> set[str]:
    """从随链保存的提交时报告中提取验签时未注册的签发者（解析失败按空集处理）。"""
    try:
        report = json.loads(report_json)
    except ValueError:
        return set()
    if not isinstance(report, dict):
        return set()
    unknown: set[str] = set()
    for node in report.get("trace") or []:
        if not isinstance(node, dict):
            continue
        for check in node.get("checks") or []:
            if not isinstance(check, dict):
                continue
            if check.get("reason") == "unknown_issuer" and not check.get("passed", True):
                issuer = node.get("issuer")
                if isinstance(issuer, str) and issuer:
                    unknown.add(issuer)
    return unknown


def get_secret(conn: sqlite3.Connection, name: str) -> str | None:
    row = conn.execute(
        "SELECT hmac_secret FROM principals WHERE name = ?", (name,)
    ).fetchone()
    return row["hmac_secret"] if row else None


def upsert_principal(conn: sqlite3.Connection, name: str, secret: str) -> bool:
    """注册主体并安装其第 1 代密钥（同一事务）；已存在返回 False。"""
    cur = conn.execute(
        "INSERT INTO principals (name, hmac_secret) VALUES (?, ?)",
        (name, secret),
    )
    if cur.rowcount == 1:
        conn.execute(
            "INSERT INTO principal_keys "
            "(principal, generation, hmac_secret, created_at) "
            "VALUES (?, 1, ?, ?)",
            (name, secret, datetime.now(timezone.utc).isoformat()),
        )
    return cur.rowcount == 1


# --------------------------------------------------------------------------- #
# 密钥代次：当前快照、按代次取钥、原子轮换
# --------------------------------------------------------------------------- #
def get_principal_key_row(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
    """主体的当前密钥行（name / hmac_secret / current_generation）；不存在返回 None。"""
    return conn.execute(
        "SELECT name, hmac_secret, current_generation FROM principals WHERE name = ?",
        (name,),
    ).fetchone()


def install_next_key_generation(
    conn: sqlite3.Connection, name: str, new_secret: str
) -> tuple[int, datetime]:
    """为主体安装新一代密钥并切换为当前代，返回 (新代次, 安装时间)。

    历史追加与当前代切换在同一事务内提交；调用方负责开启写事务
    （``BEGIN IMMEDIATE``）并在失败时回滚——任何失败都不会留下部分切换。
    """
    row = get_principal_key_row(conn, name)
    assert row is not None, "install_next_key_generation 前须确认主体存在"
    new_generation = row["current_generation"] + 1
    now = datetime.now(timezone.utc)
    conn.execute(
        "INSERT INTO principal_keys "
        "(principal, generation, hmac_secret, created_at) VALUES (?, ?, ?, ?)",
        (name, new_generation, new_secret, now.isoformat()),
    )
    conn.execute(
        "UPDATE principals SET hmac_secret = ?, current_generation = ? WHERE name = ?",
        (new_secret, new_generation, name),
    )
    return new_generation, now


def snapshot_current_keys(
    conn: sqlite3.Connection, names: Iterable[str]
) -> dict[str, tuple[str, int]]:
    """当前密钥快照：``{主体名: (密钥, 代次)}``；未注册主体不出现在结果中。

    链提交时先取快照再验签、再把快照中的代次随链持久化，保证与并发轮换
    交错时“验签用哪一代密钥，归属就记哪一代”。
    """
    unique = sorted(set(names))
    if not unique:
        return {}
    placeholders = ", ".join("?" for _ in unique)
    rows = conn.execute(
        "SELECT name, hmac_secret, current_generation FROM principals "
        f"WHERE name IN ({placeholders})",
        unique,
    ).fetchall()
    return {r["name"]: (r["hmac_secret"], r["current_generation"]) for r in rows}


def get_secret_at_generation(
    conn: sqlite3.Connection, name: str, generation: int
) -> str | None:
    """指定代次的密钥；主体或该代次不存在时返回 None。"""
    row = conn.execute(
        "SELECT hmac_secret FROM principal_keys "
        "WHERE principal = ? AND generation = ?",
        (name, generation),
    ).fetchone()
    return row["hmac_secret"] if row else None


def load_chain_key_generations(
    conn: sqlite3.Connection, chain_id: str
) -> dict[str, int]:
    """链在提交时锁定的 ``{签发主体: 密钥代次}`` 归属（无记录时为空 dict）。"""
    rows = conn.execute(
        "SELECT principal, generation FROM chain_key_generations WHERE chain_id = ?",
        (chain_id,),
    ).fetchall()
    return {r["principal"]: r["generation"] for r in rows}


def load_chain_missing_issuers(
    conn: sqlite3.Connection, chain_id: str
) -> set[str]:
    """链在提交时未注册（无法取得密钥）的签发主体集合（无记录时为空集）。"""
    rows = conn.execute(
        "SELECT principal FROM chain_missing_issuers WHERE chain_id = ?",
        (chain_id,),
    ).fetchall()
    return {r["principal"] for r in rows}


def save_chain(
    conn: sqlite3.Connection,
    submission: ChainSubmission,
    content_sha256: str,
    report: IntegrityReport,
    key_generations: dict[str, int],
    missing_issuers: Iterable[str] = (),
) -> None:
    """持久化链及其提交时锁定的密钥归属（同一事务，要么全部落库要么都不落）。

    ``key_generations`` 记录提交时已注册主体的密钥代次；``missing_issuers``
    记录提交时未注册的主体——“提交时缺失密钥”这一事实随链保存，事后注册
    不改变旧链的验签结论。
    """
    created_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO chains (chain_id, content_sha256, report_json, created_at) "
        "VALUES (?, ?, ?, ?)",
        (
            submission.chain_id,
            content_sha256,
            json.dumps(report.model_dump(mode="json"), ensure_ascii=False),
            created_at,
        ),
    )
    conn.executemany(
        "INSERT INTO tokens (chain_id, position, token_json) VALUES (?, ?, ?)",
        [
            (submission.chain_id, i, t.model_dump_json())
            for i, t in enumerate(submission.tokens)
        ],
    )
    conn.executemany(
        "INSERT INTO chain_key_generations (chain_id, principal, generation) "
        "VALUES (?, ?, ?)",
        [
            (submission.chain_id, name, generation)
            for name, generation in sorted(key_generations.items())
        ],
    )
    conn.executemany(
        "INSERT INTO chain_missing_issuers (chain_id, principal) VALUES (?, ?)",
        [(submission.chain_id, name) for name in sorted(missing_issuers)],
    )


def get_chain_hash(conn: sqlite3.Connection, chain_id: str) -> str | None:
    row = conn.execute(
        "SELECT content_sha256 FROM chains WHERE chain_id = ?", (chain_id,)
    ).fetchone()
    return row["content_sha256"] if row else None


def load_submission(conn: sqlite3.Connection, chain_id: str) -> ChainSubmission | None:
    chain = conn.execute(
        "SELECT content_sha256, report_json, created_at FROM chains WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()
    if chain is None:
        return None
    rows = conn.execute(
        "SELECT token_json FROM tokens WHERE chain_id = ? ORDER BY position",
        (chain_id,),
    ).fetchall()
    tokens = [CapabilityToken.model_validate_json(r["token_json"]) for r in rows]
    return ChainSubmission(chain_id=chain_id, tokens=tokens)


def load_chain_record(conn: sqlite3.Connection, chain_id: str) -> dict | None:
    chain = conn.execute(
        "SELECT content_sha256, report_json, created_at FROM chains WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()
    if chain is None:
        return None
    submission = load_submission(conn, chain_id)
    assert submission is not None
    return {
        "chain_id": chain_id,
        "content_sha256": chain["content_sha256"],
        "created_at": datetime.fromisoformat(chain["created_at"]),
        "integrity": IntegrityReport.model_validate(json.loads(chain["report_json"])),
        "tokens": submission.tokens,
        "revocations": load_revocations(conn, chain_id),
        "redemptions": load_redemptions(conn, chain_id),
    }


# --------------------------------------------------------------------------- #
# 撤销事件（不可变，只追加）
# --------------------------------------------------------------------------- #
def token_exists(conn: sqlite3.Connection, chain_id: str, token_id: str) -> bool:
    """令牌是否存在于指定链的提交中（按 position 存在性判定，重复 id 也算存在）。"""
    row = conn.execute(
        "SELECT 1 FROM tokens WHERE chain_id = ? "
        "AND json_extract(token_json, '$.token_id') = ? LIMIT 1",
        (chain_id, token_id),
    ).fetchone()
    return row is not None


def load_revocation_by_request_key(
    conn: sqlite3.Connection, request_key: str
) -> RevocationEvent | None:
    row = conn.execute(
        "SELECT chain_id, token_id, effective_at, reason, request_key, "
        "content_sha256, created_at FROM revocations WHERE request_key = ?",
        (request_key,),
    ).fetchone()
    return _revocation_from_row(row) if row else None


def load_revocation_for_token(
    conn: sqlite3.Connection, chain_id: str, token_id: str
) -> RevocationEvent | None:
    row = conn.execute(
        "SELECT chain_id, token_id, effective_at, reason, request_key, "
        "content_sha256, created_at FROM revocations "
        "WHERE chain_id = ? AND token_id = ?",
        (chain_id, token_id),
    ).fetchone()
    return _revocation_from_row(row) if row else None


def load_revocations(
    conn: sqlite3.Connection, chain_id: str
) -> list[RevocationEvent]:
    """按追加顺序（id 升序）返回某条链的全部撤销事件。"""
    rows = conn.execute(
        "SELECT chain_id, token_id, effective_at, reason, request_key, "
        "content_sha256, created_at FROM revocations WHERE chain_id = ? ORDER BY id",
        (chain_id,),
    ).fetchall()
    return [_revocation_from_row(r) for r in rows]


def insert_revocation(
    conn: sqlite3.Connection,
    event: RevocationEvent,
) -> None:
    """追加一条撤销事件；唯一约束冲突时抛出 sqlite3.IntegrityError（事务回滚）。"""
    conn.execute(
        "INSERT INTO revocations (chain_id, token_id, effective_at, reason, "
        "request_key, content_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            event.chain_id,
            event.token_id,
            event.effective_at.astimezone(timezone.utc).isoformat(),
            event.reason,
            event.request_key,
            event.content_sha256,
            event.created_at.astimezone(timezone.utc).isoformat(),
        ),
    )


def _revocation_from_row(row: sqlite3.Row) -> RevocationEvent:
    return RevocationEvent(
        chain_id=row["chain_id"],
        token_id=row["token_id"],
        effective_at=datetime.fromisoformat(row["effective_at"]),
        reason=row["reason"],
        request_key=row["request_key"],
        content_sha256=row["content_sha256"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


# --------------------------------------------------------------------------- #
# 一次性访问核销（只在允许且末端时追加，成功记录不可变）
# --------------------------------------------------------------------------- #
_REDEMPTION_COLUMNS = (
    "chain_id, token_id, request_key, request_path, method, source_ip, "
    "request_body, content_sha256, evaluated_at, redeemed_at, created_at"
)


def load_redemption_by_request_key(
    conn: sqlite3.Connection, request_key: str
) -> tuple[RedemptionEvent, str] | None:
    """返回（核销事件, 首次响应 JSON）；未见过该 request_key 时返回 None。"""
    row = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS}, result_json FROM redemptions "
        "WHERE request_key = ?",
        (request_key,),
    ).fetchone()
    if row is None:
        return None
    return _redemption_from_row(row), row["result_json"]


def load_redemption_for_token(
    conn: sqlite3.Connection, chain_id: str, token_id: str
) -> RedemptionEvent | None:
    """该令牌此前的成功核销记录（同一令牌只能成功核销一次）。

    单链核销与会签核销共用同一“已核销”判定：会签成功的每一侧，对单链
    核销而言同样视为已核销（反之亦然）——会签的一半不能被当作独立请求
    再次核销。
    """
    row = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS}, result_json FROM redemptions "
        "WHERE chain_id = ? AND token_id = ?",
        (chain_id, token_id),
    ).fetchone()
    if row is not None:
        return _redemption_from_row(row)
    co = load_co_redemption_for_token(conn, chain_id, token_id)
    if co is None:
        return None
    return co.leg_event(chain_id)


def load_redemptions(
    conn: sqlite3.Connection, chain_id: str
) -> list[RedemptionEvent]:
    """某条链的全部成功核销记录（单链核销 + 会签中涉及本链的一侧），按落库顺序。"""
    rows = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS} FROM redemptions "
        "WHERE chain_id = ? ORDER BY id",
        (chain_id,),
    ).fetchall()
    events = [_redemption_from_row(r) for r in rows]
    co_rows = conn.execute(
        f"SELECT {_CO_REDEMPTION_COLUMNS} FROM co_redemptions "
        "WHERE primary_chain_id = ? OR review_chain_id = ?",
        (chain_id, chain_id),
    ).fetchall()
    events.extend(
        _co_redemption_from_row(r).leg_event(chain_id) for r in co_rows
    )
    # 两张表各自只追加；以落库时间（微秒级）归并排序，键与令牌 id 兜底确定性
    events.sort(key=lambda e: (e.created_at, e.request_key, e.token_id))
    return events


def insert_redemption(
    conn: sqlite3.Connection, event: RedemptionEvent, result_json: str
) -> None:
    """追加一条成功核销记录；唯一约束冲突时抛 sqlite3.IntegrityError。"""
    conn.execute(
        "INSERT INTO redemptions (chain_id, token_id, request_key, request_path, "
        "method, source_ip, request_body, content_sha256, evaluated_at, redeemed_at, "
        "created_at, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event.chain_id,
            event.token_id,
            event.request_key,
            event.request_path,
            event.method,
            event.source_ip,
            json.dumps(event.request_body, ensure_ascii=False),
            event.content_sha256,
            event.evaluated_at.astimezone(timezone.utc).isoformat(),
            event.redeemed_at.astimezone(timezone.utc).isoformat(),
            event.created_at.astimezone(timezone.utc).isoformat(),
            result_json,
        ),
    )


def _redemption_from_row(row: sqlite3.Row) -> RedemptionEvent:
    return RedemptionEvent(
        chain_id=row["chain_id"],
        token_id=row["token_id"],
        request_key=row["request_key"],
        request_path=row["request_path"],
        method=row["method"],
        source_ip=row["source_ip"],
        request_body=json.loads(row["request_body"]),
        content_sha256=row["content_sha256"],
        evaluated_at=datetime.fromisoformat(row["evaluated_at"]),
        redeemed_at=datetime.fromisoformat(row["redeemed_at"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


# --------------------------------------------------------------------------- #
# 双主体会签核销（两侧同时成功才追加，记录不可变）
# --------------------------------------------------------------------------- #
_CO_REDEMPTION_COLUMNS = (
    "request_key, primary_chain_id, primary_token_id, review_chain_id, "
    "review_token_id, request_path, method, source_ip, request_body, "
    "content_sha256, evaluated_at, redeemed_at, created_at"
)


def load_co_redemption_by_request_key(
    conn: sqlite3.Connection, request_key: str
) -> tuple[CoRedemptionEvent, str] | None:
    """返回（会签事件, 首次响应 JSON）；未见过该 request_key 时返回 None。"""
    row = conn.execute(
        f"SELECT {_CO_REDEMPTION_COLUMNS}, result_json FROM co_redemptions "
        "WHERE request_key = ?",
        (request_key,),
    ).fetchone()
    if row is None:
        return None
    return _co_redemption_from_row(row), row["result_json"]


def load_co_redemption_for_token(
    conn: sqlite3.Connection, chain_id: str, token_id: str
) -> CoRedemptionEvent | None:
    """该令牌作为会签一侧（主或复核）此前的成功会签记录。"""
    row = conn.execute(
        f"SELECT {_CO_REDEMPTION_COLUMNS} FROM co_redemptions "
        "WHERE (primary_chain_id = ? AND primary_token_id = ?) "
        "OR (review_chain_id = ? AND review_token_id = ?)",
        (chain_id, token_id, chain_id, token_id),
    ).fetchone()
    return _co_redemption_from_row(row) if row else None


def insert_co_redemption(
    conn: sqlite3.Connection, event: CoRedemptionEvent, result_json: str
) -> None:
    """追加一条会签核销记录；唯一约束冲突时抛 sqlite3.IntegrityError。"""
    conn.execute(
        "INSERT INTO co_redemptions (request_key, primary_chain_id, "
        "primary_token_id, review_chain_id, review_token_id, request_path, "
        "method, source_ip, request_body, content_sha256, evaluated_at, "
        "redeemed_at, created_at, result_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event.request_key,
            event.primary_chain_id,
            event.primary_token_id,
            event.review_chain_id,
            event.review_token_id,
            event.request_path,
            event.method,
            event.source_ip,
            json.dumps(event.request_body, ensure_ascii=False),
            event.content_sha256,
            event.evaluated_at.astimezone(timezone.utc).isoformat(),
            event.redeemed_at.astimezone(timezone.utc).isoformat(),
            event.created_at.astimezone(timezone.utc).isoformat(),
            result_json,
        ),
    )


def _co_redemption_from_row(row: sqlite3.Row) -> CoRedemptionEvent:
    return CoRedemptionEvent(
        request_key=row["request_key"],
        primary_chain_id=row["primary_chain_id"],
        primary_token_id=row["primary_token_id"],
        review_chain_id=row["review_chain_id"],
        review_token_id=row["review_token_id"],
        request_path=row["request_path"],
        method=row["method"],
        source_ip=row["source_ip"],
        request_body=json.loads(row["request_body"]),
        content_sha256=row["content_sha256"],
        evaluated_at=datetime.fromisoformat(row["evaluated_at"]),
        redeemed_at=datetime.fromisoformat(row["redeemed_at"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )
