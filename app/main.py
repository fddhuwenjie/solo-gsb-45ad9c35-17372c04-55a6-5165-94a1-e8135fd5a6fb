"""FastAPI 应用：提交能力链、幂等重放、冲突检测、撤销审计（含追溯影响清单）、请求级判定、一次性核销、双主体会签与密钥轮换。"""
from __future__ import annotations

import json
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse

from .database import (
    find_redemptions_affected_by_revocation,
    get_conn,
    get_db,
    get_principal_key_row,
    get_secret_at_generation,
    init_db,
    insert_co_redemption,
    insert_redemption,
    insert_revocation,
    insert_revocation_impacts,
    install_next_key_generation,
    load_chain_key_generations,
    load_chain_missing_issuers,
    load_chain_record,
    load_co_redemption_by_request_key,
    load_redemption_by_request_key,
    load_redemption_for_token,
    load_redemptions,
    load_revocation_by_request_key,
    load_revocation_for_token,
    load_revocation_impacts,
    load_revocations,
    load_submission,
    save_chain,
    snapshot_current_keys,
    token_exists,
    upsert_principal,
)
from .engine import affected_token_ids, chain_tip_token, evaluate_request, validate_chain
from .models import (
    CapabilityToken,
    ChainRecord,
    ChainSubmission,
    CoRedeemLegResult,
    CoRedeemRequest,
    CoRedeemResult,
    CoRedemptionEvent,
    ConflictDetail,
    EvaluateRequest,
    EvaluateResult,
    KeyRotationIn,
    PrincipalIn,
    PrincipalOut,
    PrincipalRotationOut,
    RedemptionEvent,
    RedeemRequest,
    RedeemResult,
    RevocationEvent,
    RevocationImpactList,
    RevocationRequest,
    RevocationResult,
    SubmissionResult,
)
from .security import (
    canonical_co_redemption_hash,
    canonical_redemption_hash,
    canonical_revocation_hash,
    canonical_submission_hash,
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    with get_conn() as conn:
        init_db(conn)
    yield


app = FastAPI(
    title="委托能力链验证 API",
    description=(
        "客户端提交根授权和以 parent_id 相连的委托令牌；服务验签、检测断链与环，"
        "并强制路径 / 方法 / 时间窗 / IP 网段只能逐级收窄。"
        "支持按时间生效的不可变撤销事件（事件写入时同事务保存追溯影响清单）、"
        "请求级判定、链末端令牌的一次性访问核销、"
        "双主体会签核销（主授权链与复核链的末端在同一事务内同时核销或都不核销），"
        "以及按代次管理的签发主体 HMAC 密钥轮换（既有链按提交时锁定的代次重验）。"
    ),
    version="1.5.0",
    lifespan=lifespan,
)


def _chain_secret_lookup(conn: sqlite3.Connection, chain_id: str):
    """按链提交时锁定的密钥归属构造验签查询。

    - 提交时已注册的主体：固定使用链归属记录中的那一代密钥——轮换不影响
      既有链的验签结论，既有无效链也不会因新密钥恰好匹配而翻转为有效；
    - 提交时未注册的主体（缺失事实已随链持久化）：一律按 unknown_issuer
      处理——事后注册该主体、甚至轮换到匹配旧签名的密钥，都不会让旧链
      在查询 / 重放 / 求值 / 核销中翻转为有效；
    - 归属表与缺失表都无记录（只会出现在尚未回填的极旧数据上）：同样按
      提交时未注册处理，拒绝放行。
    """
    recorded = load_chain_key_generations(conn, chain_id)
    missing = load_chain_missing_issuers(conn, chain_id)

    def lookup(name: str) -> str | None:
        if name in missing:
            return None
        generation = recorded.get(name)
        if generation is None:
            return None
        return get_secret_at_generation(conn, name, generation)

    return lookup


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/principals", response_model=PrincipalOut, status_code=201)
def register_principal(
    payload: PrincipalIn, conn: sqlite3.Connection = Depends(get_db)
) -> PrincipalOut:
    """注册一个签发主体及其 HMAC 密钥（演示 / 运维引导用）。"""
    try:
        created = upsert_principal(conn, payload.name, payload.hmac_secret)
    except sqlite3.IntegrityError:
        created = False
    if not created:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"主体 {payload.name!r} 已存在",
        )
    return PrincipalOut(name=payload.name)


@app.post("/api/v1/principals/{name}/rotate-key", response_model=PrincipalRotationOut)
def rotate_principal_key(
    name: str, payload: KeyRotationIn, conn: sqlite3.Connection = Depends(get_db)
) -> PrincipalRotationOut:
    """轮换已注册主体的 HMAC 密钥：原子安装新一代密钥并切换为当前代。

    - 轮换后**新提交**的链只按新密钥验签（旧密钥签出的新链得到 ``bad_signature``）；
    - 轮换前已保存的链按提交时锁定的代次继续用原密钥重验，结论不变；
    - 整个切换在同一事务（``BEGIN IMMEDIATE``）内完成：主体不存在（404）、
      新密钥与当前相同（409）或任何写失败都不会留下部分切换；
    - 响应只包含主体名、新代次与轮换时间，不回显密钥。
    """
    conn.execute("BEGIN IMMEDIATE")
    row = get_principal_key_row(conn, name)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"主体 {name!r} 不存在，无法轮换密钥",
        )
    if payload.hmac_secret == row["hmac_secret"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="新密钥与当前密钥相同；轮换未执行",
        )
    generation, rotated_at = install_next_key_generation(
        conn, name, payload.hmac_secret
    )
    return PrincipalRotationOut(name=name, generation=generation, rotated_at=rotated_at)


@app.post(
    "/api/v1/chains",
    response_model=SubmissionResult,
    responses={409: {"model": ConflictDetail}},
    status_code=201,
)
def submit_chain(
    submission: ChainSubmission,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """提交（或重放）一条能力链。

    - 相同 chain_id 且内容完全一致：幂等返回 200，``replayed=true``；
    - 相同 chain_id 但内容变化：返回 409 冲突；
    - 新 chain_id：持久化并返回 201。完整性失败也会持久化（含失败轨迹）。

    验签严格使用“提交时各签发主体的当前密钥代次”快照，并把该代次归属随链
    持久化：与并发轮换交错时，链的密钥归属与提交时的验签结果始终一致。
    提交时未注册的签发者同样把“缺失密钥”这一事实随链持久化：事后注册该
    主体（或轮换到匹配旧签名的密钥）都不会让这条链的验签结论翻转。
    """
    received_hash = canonical_submission_hash(
        submission.chain_id, submission.tokens
    )
    existing_hash = _existing_hash(conn, submission.chain_id)

    if existing_hash is not None:
        if existing_hash == received_hash:
            # 幂等重放：按链提交时锁定的密钥代次重验，结论与首次提交一致
            report, _ = validate_chain(
                submission, _chain_secret_lookup(conn, submission.chain_id)
            )
            result = SubmissionResult(
                chain_id=submission.chain_id, replayed=True, integrity=report
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result.model_dump(mode="json"),
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"chain_id={submission.chain_id!r} 已存在但内容不同；"
                    "相同 chain_id 不允许提交不同内容"
                ),
                "chain_id": submission.chain_id,
                "existing_sha256": existing_hash,
                "received_sha256": received_hash,
            },
        )

    # 新链：先快照各签发主体的当前密钥与代次，验签与归属记录使用同一快照；
    # 快照之外的签发者（提交时未注册）把“缺失密钥”事实一并随链持久化
    issuers = {t.issuer for t in submission.tokens}
    snapshot = snapshot_current_keys(conn, issuers)
    report, _ = validate_chain(
        submission,
        lambda name: snapshot[name][0] if name in snapshot else None,
    )
    save_chain(
        conn,
        submission,
        received_hash,
        report,
        {name: generation for name, (_, generation) in snapshot.items()},
        missing_issuers=issuers - snapshot.keys(),
    )
    result = SubmissionResult(
        chain_id=submission.chain_id, replayed=False, integrity=report
    )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


def _existing_hash(conn: sqlite3.Connection, chain_id: str) -> str | None:
    row = conn.execute(
        "SELECT content_sha256 FROM chains WHERE chain_id = ?", (chain_id,)
    ).fetchone()
    return row["content_sha256"] if row else None


@app.get("/api/v1/chains/{chain_id}", response_model=ChainRecord)
def get_chain(
    chain_id: str, conn: sqlite3.Connection = Depends(get_db)
) -> dict:
    record = load_chain_record(conn, chain_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"chain_id {chain_id!r} 不存在")
    return record


@app.post("/api/v1/chains/{chain_id}/evaluate", response_model=EvaluateResult)
def evaluate_chain(
    chain_id: str,
    payload: EvaluateRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> EvaluateResult:
    submission = load_submission(conn, chain_id)
    if submission is None:
        raise HTTPException(status_code=404, detail=f"chain_id {chain_id!r} 不存在")
    revocations = load_revocations(conn, chain_id)
    return evaluate_request(
        submission, payload, _chain_secret_lookup(conn, chain_id), revocations=revocations
    )


@app.post("/api/v1/chains/{chain_id}/redeem")
def redeem_chain(
    chain_id: str,
    payload: RedeemRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """对链末端令牌执行一次性访问核销。

    判定时间不由调用方提供，而以**服务端接收时刻**（UTC）实时重算现有
    验签 / 权限范围 / 撤销状态；全部工作在同一 SQLite 事务（``BEGIN IMMEDIATE``）内：

    - 201 Created：目标确为链末端且判定允许——记录核销（该令牌此后不可再核销）；
    - 200 OK：同 ``request_key`` 同内容重放，返回**首次结果**（``replayed=true``，
      即使令牌随后过期 / 被撤销）；或目标为末端但本次判定拒绝（``redeemed=false``，
      不核销、不占用 request_key，后续有效请求仍可尝试）；
    - 409 Conflict：同 ``request_key`` 换内容；目标不是链末端；令牌此前已被核销
      （并发请求仅一笔成功，其余统一报告已核销，与其当下是否过期 / 被撤销无关）；
    - 404 Not Found：链不存在，或令牌不属于该链；
    - 422：输入校验失败（如非法 source_ip / HTTP 方法）。
    """
    content_hash = canonical_redemption_hash(
        chain_id,
        payload.token_id,
        payload.request_key,
        payload.request_path,
        payload.method,
        payload.source_ip,
        payload.body,
    )

    # 立即取写锁，串行化“判定 + 插入”，保证并发请求仅一笔成功核销
    conn.execute("BEGIN IMMEDIATE")

    # 1) request_key 幂等 / 冲突（成功核销才会占用 request_key）
    existing = load_redemption_by_request_key(conn, payload.request_key)
    if existing is not None:
        event, first_result_json = existing
        if event.content_sha256 != content_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "detail": (
                        f"request_key={payload.request_key!r} 已用于另一次核销，"
                        "同一 request_key 不得更换目标或请求内容"
                    ),
                    "request_key": payload.request_key,
                    "existing_sha256": event.content_sha256,
                    "received_sha256": content_hash,
                },
            )
        # 同键同内容：无条件回放首次结果（令牌随后过期 / 被撤销也不变）
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=json.loads(first_result_json) | {"replayed": True},
        )

    # request_key 与会签核销共用同一键空间：已被成功会签占用的键不得复用
    co_existing = load_co_redemption_by_request_key(conn, payload.request_key)
    if co_existing is not None:
        co_event, _ = co_existing
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"request_key={payload.request_key!r} 已用于一次双主体会签，"
                    "同一 request_key 不得复用"
                ),
                "request_key": payload.request_key,
                "existing_sha256": co_event.content_sha256,
                "received_sha256": content_hash,
            },
        )

    # 2) 链必须存在
    submission = load_submission(conn, chain_id)
    if submission is None:
        raise HTTPException(
            status_code=404, detail=f"chain_id {chain_id!r} 不存在"
        )

    # 3) 令牌必须属于该链
    if not token_exists(conn, chain_id, payload.token_id):
        raise HTTPException(
            status_code=404,
            detail=(
                f"chain_id {chain_id!r} 中不存在 token_id={payload.token_id!r}"
            ),
        )

    # 4) 目标必须确为链末端（结构选路：唯一根 → 唯一子链的最后一个令牌）
    tip = chain_tip_token(submission)
    if tip is None or tip.token_id != payload.token_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"token_id={payload.token_id!r} 不是链 {chain_id!r} 的末端令牌，"
                    "一次性核销只允许对链末端执行"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "chain_tip_token_id": None if tip is None else tip.token_id,
            },
        )

    # 5) 同一令牌只能成功核销一次：已核销则明确报告（并发输家亦走此路）
    prior = load_redemption_for_token(conn, chain_id, payload.token_id)
    if prior is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"token_id={payload.token_id!r} 已在 request_key="
                    f"{prior.request_key!r} 中核销，令牌只能成功核销一次"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "existing_request_key": prior.request_key,
                "redeemed_at": prior.redeemed_at.isoformat(),
            },
        )

    # 6) 以接收时刻重算现有验签 / 收窄 / 撤销 / 请求级权限
    #    （验签按链提交时锁定的密钥代次取钥，轮换不改变既有链结论）
    now = datetime.now(timezone.utc)
    evaluation = EvaluateRequest(
        request_path=payload.request_path,
        method=payload.method,
        at=now,
        source_ip=payload.source_ip,
        body=payload.body,
    )
    decision = evaluate_request(
        submission,
        evaluation,
        _chain_secret_lookup(conn, chain_id),
        revocations=load_revocations(conn, chain_id),
    )

    if decision.decision != "allow":
        # 判定拒绝：既不核销，也不占用 request_key
        result = RedeemResult(
            chain_id=chain_id,
            token_id=payload.token_id,
            request_key=payload.request_key,
            redeemed=False,
            replayed=False,
            evaluated_at=now,
            redeemed_at=None,
            decision=decision.decision,
            first_failed_node=decision.first_failed_node,
            first_failed_reason=decision.first_failed_reason,
            body_sha256=decision.body_sha256,
            first_revoked_node=decision.first_revoked_node,
            trace=decision.trace,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=result.model_dump(mode="json"),
        )

    event = RedemptionEvent(
        chain_id=chain_id,
        token_id=payload.token_id,
        request_key=payload.request_key,
        request_path=payload.request_path,
        method=payload.method,
        source_ip=payload.source_ip,
        request_body=payload.body,
        content_sha256=content_hash,
        evaluated_at=now,
        redeemed_at=now,
        created_at=now,
    )
    result = RedeemResult(
        chain_id=chain_id,
        token_id=payload.token_id,
        request_key=payload.request_key,
        redeemed=True,
        replayed=False,
        evaluated_at=now,
        redeemed_at=now,
        decision=decision.decision,
        first_failed_node=decision.first_failed_node,
        first_failed_reason=decision.first_failed_reason,
        body_sha256=decision.body_sha256,
        first_revoked_node=decision.first_revoked_node,
        trace=decision.trace,
    )
    try:
        insert_redemption(conn, event, json.dumps(
            result.model_dump(mode="json"), ensure_ascii=False
        ))
    except sqlite3.IntegrityError as exc:
        # 并发下唯一约束兜底（request_key 或 chain_id+token_id 抢占）
        prior = load_redemption_for_token(conn, chain_id, payload.token_id)
        detail = (
            {
                "detail": (
                    f"token_id={payload.token_id!r} 已在 request_key="
                    f"{prior.request_key!r} 中核销，令牌只能成功核销一次"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "existing_request_key": prior.request_key,
            }
            if prior is not None
            else {"detail": f"核销请求与已有记录冲突: {exc}"}
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=detail
        )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


@app.post("/api/v1/co-redemptions")
def co_redeem(
    payload: CoRedeemRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """双主体会签：一次访问需主授权链与复核链的末端同时允许，才一并核销。

    整个流程在**同一 SQLite 写事务**（``BEGIN IMMEDIATE``）内、以**同一服务端
    接收时刻**（UTC）完成：两条链分别按各自提交时锁定的密钥归属验签，并检查
    撤销、请求级权限与已核销状态。

    - 201 Created：两条链的末端都判定允许且均未核销——同一事务内同时记入两侧
      核销（共同核销时间），返回两份判定轨迹；
    - 200 OK：同 ``request_key`` 同内容重放，返回**首次会签结果**
      （``replayed=true``，即使令牌随后过期 / 被撤销）；或任一侧判定拒绝
      （``redeemed=false``——两侧都不核销、不占用 request_key）；
    - 409 Conflict：同 ``request_key`` 换内容（含主 / 复核互换）；两链末端
      subject 相同；目标不是链末端；任一侧此前已被核销（单链核销或会签，
      另一侧不被消耗）；request_key 已被单链核销占用；
    - 404 Not Found：任一链不存在，或令牌不属于对应链；
    - 422：输入校验失败（如两链 chain_id 相同、非法 source_ip / HTTP 方法）。
    """
    content_hash = canonical_co_redemption_hash(
        payload.primary.chain_id,
        payload.primary.token_id,
        payload.review.chain_id,
        payload.review.token_id,
        payload.request_key,
        payload.request_path,
        payload.method,
        payload.source_ip,
        payload.body,
    )

    # 立即取写锁：两侧“判定 + 核销”在同一事务内串行化，要么同时落库要么都不落
    conn.execute("BEGIN IMMEDIATE")

    # 1) request_key 幂等 / 冲突（成功会签才占用 request_key）
    existing = load_co_redemption_by_request_key(conn, payload.request_key)
    if existing is not None:
        event, first_result_json = existing
        if event.content_sha256 != content_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "detail": (
                        f"request_key={payload.request_key!r} 已用于另一次会签，"
                        "同一 request_key 不得更换链、目标或请求内容"
                    ),
                    "request_key": payload.request_key,
                    "existing_sha256": event.content_sha256,
                    "received_sha256": content_hash,
                },
            )
        # 同键同内容：无条件回放首次会签结果（令牌随后过期 / 被撤销也不变）
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=json.loads(first_result_json) | {"replayed": True},
        )

    # request_key 与单链核销共用同一键空间：已被单链核销占用的键不得复用
    single_existing = load_redemption_by_request_key(conn, payload.request_key)
    if single_existing is not None:
        single_event, _ = single_existing
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"request_key={payload.request_key!r} 已用于一次单链核销，"
                    "同一 request_key 不得复用"
                ),
                "request_key": payload.request_key,
                "existing_sha256": single_event.content_sha256,
                "received_sha256": content_hash,
            },
        )

    # 2) 两条链都必须存在、令牌都属于对应链、且都确为各自链的末端
    sides: dict[str, tuple[str, str, ChainSubmission, CapabilityToken]] = {}
    for side_name, side in (("primary", payload.primary), ("review", payload.review)):
        submission = load_submission(conn, side.chain_id)
        if submission is None:
            raise HTTPException(
                status_code=404, detail=f"chain_id {side.chain_id!r} 不存在"
            )
        if not token_exists(conn, side.chain_id, side.token_id):
            raise HTTPException(
                status_code=404,
                detail=(
                    f"chain_id {side.chain_id!r} 中不存在 "
                    f"token_id={side.token_id!r}"
                ),
            )
        tip = chain_tip_token(submission)
        if tip is None or tip.token_id != side.token_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "detail": (
                        f"token_id={side.token_id!r} 不是链 {side.chain_id!r} "
                        "的末端令牌，会签只允许对两侧各自的链末端执行"
                    ),
                    "side": side_name,
                    "chain_id": side.chain_id,
                    "token_id": side.token_id,
                    "chain_tip_token_id": None if tip is None else tip.token_id,
                },
            )
        sides[side_name] = (side.chain_id, side.token_id, submission, tip)

    # 3) 双主体：两链末端令牌的 subject 必须不同
    primary_tip = sides["primary"][3]
    review_tip = sides["review"][3]
    if primary_tip.subject == review_tip.subject:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"两条链末端令牌的 subject 相同（{primary_tip.subject!r}），"
                    "会签要求主授权与复核为不同主体"
                ),
                "subject": primary_tip.subject,
                "primary_chain_id": payload.primary.chain_id,
                "review_chain_id": payload.review.chain_id,
            },
        )

    # 4) 任一侧已核销（单链核销或会签）-> 409，另一侧不被消耗
    for side_name in ("primary", "review"):
        chain_id, token_id, _, _ = sides[side_name]
        prior = load_redemption_for_token(conn, chain_id, token_id)
        if prior is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "detail": (
                        f"token_id={token_id!r} 已在 request_key="
                        f"{prior.request_key!r} 中核销，令牌只能成功核销一次；"
                        "本次会签未消耗任何一侧"
                    ),
                    "side": side_name,
                    "chain_id": chain_id,
                    "token_id": token_id,
                    "existing_request_key": prior.request_key,
                    "redeemed_at": prior.redeemed_at.isoformat(),
                },
            )

    # 5) 以同一接收时刻重算两链的验签 / 收窄 / 撤销 / 请求级权限
    #    （各链分别按其提交时锁定的密钥代次取钥，轮换不改变既有链结论）
    now = datetime.now(timezone.utc)
    evaluation = EvaluateRequest(
        request_path=payload.request_path,
        method=payload.method,
        at=now,
        source_ip=payload.source_ip,
        body=payload.body,
    )
    decisions = {}
    for side_name in ("primary", "review"):
        chain_id, _, submission, _ = sides[side_name]
        decisions[side_name] = evaluate_request(
            submission,
            evaluation,
            _chain_secret_lookup(conn, chain_id),
            revocations=load_revocations(conn, chain_id),
        )
    legs = {
        side_name: CoRedeemLegResult(
            chain_id=sides[side_name][0],
            token_id=sides[side_name][1],
            subject=sides[side_name][3].subject,
            decision=decisions[side_name].decision,
            first_failed_node=decisions[side_name].first_failed_node,
            first_failed_reason=decisions[side_name].first_failed_reason,
            first_revoked_node=decisions[side_name].first_revoked_node,
            trace=decisions[side_name].trace,
        )
        for side_name in ("primary", "review")
    }
    body_sha256 = decisions["primary"].body_sha256

    if any(leg.decision != "allow" for leg in legs.values()):
        # 任一侧拒绝：两侧都不核销，也不占用 request_key
        result = CoRedeemResult(
            request_key=payload.request_key,
            redeemed=False,
            replayed=False,
            evaluated_at=now,
            redeemed_at=None,
            body_sha256=body_sha256,
            primary=legs["primary"],
            review=legs["review"],
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=result.model_dump(mode="json"),
        )

    # 6) 两侧都允许且均未核销：同一事务内同时记入两侧核销（共同核销时间）
    event = CoRedemptionEvent(
        request_key=payload.request_key,
        primary_chain_id=payload.primary.chain_id,
        primary_token_id=payload.primary.token_id,
        review_chain_id=payload.review.chain_id,
        review_token_id=payload.review.token_id,
        request_path=payload.request_path,
        method=payload.method,
        source_ip=payload.source_ip,
        request_body=payload.body,
        content_sha256=content_hash,
        evaluated_at=now,
        redeemed_at=now,
        created_at=now,
    )
    result = CoRedeemResult(
        request_key=payload.request_key,
        redeemed=True,
        replayed=False,
        evaluated_at=now,
        redeemed_at=now,
        body_sha256=body_sha256,
        primary=legs["primary"],
        review=legs["review"],
    )
    try:
        insert_co_redemption(conn, event, json.dumps(
            result.model_dump(mode="json"), ensure_ascii=False
        ))
    except sqlite3.IntegrityError as exc:
        # 并发下唯一约束兜底（request_key 或任一侧 chain_id+token_id 抢占）
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"detail": f"会签请求与已有记录冲突: {exc}"},
        )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


@app.post(
    "/api/v1/chains/{chain_id}/revocations",
    response_model=RevocationResult,
    status_code=201,
)
def submit_revocation(
    chain_id: str,
    payload: RevocationRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> JSONResponse:
    """提交（或重放）一条按时间生效的不可变撤销事件。

    - 相同 ``request_key`` 且内容完全一致：幂等返回 200，``replayed=true``，
      影响清单返回事件写入时保存的原清单（不重复写入）；
    - 相同 ``request_key`` 但目标 / 内容变化：返回 409 冲突；
    - 链或令牌不存在：404；目标令牌已有撤销事件（含不同 request_key）：409。

    “确认令牌存在”“追加撤销事件”与“保存影响清单”在同一 SQLite 事务内完成：
    事件写入时找出核销时间不早于 ``effective_at``、早于事件写入时间，且末端
    令牌为撤销目标或其后代的成功核销（单链核销与双链会签均纳入，一笔会签
    只列一次），随事件一并落库；撤销失败（404 / 409 / 写冲突）不会留下清单。
    """
    content_hash = canonical_revocation_hash(
        chain_id,
        payload.token_id,
        payload.effective_at,
        payload.reason,
        payload.request_key,
    )

    # 1) request_key 幂等 / 冲突（全局唯一键）
    existing_key = load_revocation_by_request_key(conn, payload.request_key)
    if existing_key is not None:
        if existing_key.content_sha256 == content_hash:
            # 同键同内容：返回原事件与写入时保存的影响清单，不重复写入
            result = RevocationResult(
                replayed=True,
                event=existing_key,
                affected_token_ids=_affected_ids(conn, chain_id, existing_key),
                affected_redemptions=load_revocation_impacts(
                    conn, existing_key.request_key
                ),
            )
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=result.model_dump(mode="json"),
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"request_key={payload.request_key!r} 已用于另一条撤销事件，"
                    "同一 request_key 不得更换目标或内容"
                ),
                "request_key": payload.request_key,
                "existing_sha256": existing_key.content_sha256,
                "received_sha256": content_hash,
            },
        )

    # 2) 链必须存在
    submission = load_submission(conn, chain_id)
    if submission is None:
        raise HTTPException(
            status_code=404, detail=f"chain_id {chain_id!r} 不存在"
        )

    # 3) 令牌必须属于该链（与后续插入在同一事务）
    if not token_exists(conn, chain_id, payload.token_id):
        raise HTTPException(
            status_code=404,
            detail=(
                f"chain_id {chain_id!r} 中不存在 token_id={payload.token_id!r}"
            ),
        )

    # 4) 目标令牌不得重复撤销（已撤销令牌不得再次生效为新事件）
    existing_revocation = load_revocation_for_token(
        conn, chain_id, payload.token_id
    )
    if existing_revocation is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    f"token_id={payload.token_id!r} 已在 request_key="
                    f"{existing_revocation.request_key!r} 中被撤销，"
                    "撤销事件不可变且不可重复"
                ),
                "chain_id": chain_id,
                "token_id": payload.token_id,
                "existing_request_key": existing_revocation.request_key,
            },
        )

    event = RevocationEvent(
        chain_id=chain_id,
        token_id=payload.token_id,
        effective_at=payload.effective_at.astimezone(timezone.utc),
        reason=payload.reason,
        request_key=payload.request_key,
        content_sha256=content_hash,
        created_at=datetime.now(timezone.utc),
    )
    try:
        insert_revocation(conn, event)
    except sqlite3.IntegrityError as exc:
        # 并发下唯一约束兜底（request_key 或 chain_id+token_id 抢占）
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"撤销事件与已有记录冲突: {exc}",
        )

    # 同一事务内计算并保存影响清单：核销时间不早于 effective_at、早于事件
    # 写入时间，且末端令牌为撤销目标或其后代的成功核销（单链核销与会签均
    # 纳入，一笔会签只列一次）。清单与事件同事务落库——上方任何失败都会
    # 整体回滚，撤销失败不会留下清单；原核销记录不改写。
    affected_ids = _affected_ids(conn, chain_id, event)
    impacts = find_redemptions_affected_by_revocation(
        conn, chain_id, affected_ids, event.effective_at, event.created_at
    )
    insert_revocation_impacts(conn, event.request_key, impacts, event.created_at)

    result = RevocationResult(
        replayed=False,
        event=event,
        affected_token_ids=affected_ids,
        affected_redemptions=impacts,
    )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=result.model_dump(mode="json"),
    )


@app.get(
    "/api/v1/revocations/{request_key}/impacts",
    response_model=RevocationImpactList,
)
def get_revocation_impacts(
    request_key: str, conn: sqlite3.Connection = Depends(get_db)
) -> RevocationImpactList:
    """按撤销 request_key 查询其追溯影响的成功核销清单。

    返回核销时间、访问 request_key、链和末端令牌（会签注明主授权 / 复核侧），
    按核销时间及访问键排序；无命中返回空清单，撤销事件不存在返回 404。
    """
    event = load_revocation_by_request_key(conn, request_key)
    if event is None:
        raise HTTPException(
            status_code=404,
            detail=f"撤销事件 request_key={request_key!r} 不存在",
        )
    return RevocationImpactList(
        request_key=event.request_key,
        chain_id=event.chain_id,
        token_id=event.token_id,
        effective_at=event.effective_at,
        impacts=load_revocation_impacts(conn, request_key),
    )


def _affected_ids(
    conn: sqlite3.Connection, chain_id: str, event: RevocationEvent
) -> list[str]:
    """按存储的完整性轨迹顺序计算受影响令牌（目标及其后代）。"""
    record = load_chain_record(conn, chain_id)
    if record is None:  # 理论不可达：调用前已确认链存在
        return [event.token_id]
    submission = ChainSubmission(
        chain_id=chain_id, tokens=record["tokens"]
    )
    trace_order = [t.token_id for t in record["integrity"].trace]
    return affected_token_ids(submission, trace_order, event)
