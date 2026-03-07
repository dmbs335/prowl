"""Mid-crawl control endpoints: inject URLs, scope, session, queue, config updates."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException

from prowl.api.deps import get_api_state
from prowl.api.schemas import (
    ConfigUpdateRequest,
    InjectURLsRequest,
    InjectURLsResponse,
    InterventionResponse,
    OperationResponse,
    QueueStatsResponse,
    ResolveInterventionRequest,
    ScopeResponse,
    ScopeUpdateRequest,
    SessionInjectRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ── URL Injection ─────────────────────────────────────────────────────────────


@router.post(
    "/inject/urls",
    response_model=InjectURLsResponse,
    summary="Inject URLs into crawl queue",
    description="Programmatically inject URLs into the active crawl queue. "
    "URLs are validated against scope and dedup before acceptance.",
)
async def inject_urls(body: InjectURLsRequest) -> InjectURLsResponse:
    from prowl.core.engine import EngineState
    from prowl.models.request import CrawlRequest

    api = get_api_state()
    engine = api.engine

    if engine.state not in (EngineState.RUNNING, EngineState.PAUSED):
        raise HTTPException(409, "Engine is not running")

    accepted = 0
    rejected_scope = 0
    rejected_dup = 0
    rejected_depth = 0

    for url in body.urls:
        if body.depth > engine.config.max_depth:
            rejected_depth += 1
            continue
        if not engine.scope.is_in_scope(url):
            rejected_scope += 1
            continue

        req = CrawlRequest(
            url=url,
            source_module=body.source_module,
            priority=body.priority,
            depth=body.depth,
            auth_role=body.auth_role,
        )
        added = await engine.submit(req)
        if added:
            accepted += 1
        else:
            rejected_dup += 1

    return InjectURLsResponse(
        accepted=accepted,
        rejected_out_of_scope=rejected_scope,
        rejected_duplicate=rejected_dup,
        rejected_depth=rejected_depth,
    )


# ── Scope ─────────────────────────────────────────────────────────────────────


@router.get(
    "/scope",
    response_model=ScopeResponse,
    summary="Get current scope",
    description="Returns the current crawl scope configuration: target host and regex patterns.",
)
async def get_scope() -> ScopeResponse:
    api = get_api_state()
    scope = api.engine.scope
    return ScopeResponse(
        target_host=scope._target_host,
        include_patterns=[p.pattern for p in scope._include_re],
        exclude_patterns=[p.pattern for p in scope._exclude_re],
    )


@router.post(
    "/scope/update",
    response_model=OperationResponse,
    summary="Update crawl scope",
    description="Add include/exclude regex patterns to the crawl scope at runtime. "
    "Scope can only be expanded, not contracted.",
)
async def update_scope(body: ScopeUpdateRequest) -> OperationResponse:
    api = get_api_state()
    scope = api.engine.scope

    added_include = 0
    added_exclude = 0

    for pattern in body.add_include_patterns:
        scope.add_include_pattern(pattern)
        added_include += 1

    for pattern in body.add_exclude_patterns:
        scope.add_exclude_pattern(pattern)
        added_exclude += 1

    return OperationResponse(
        status="ok",
        message=f"Added {added_include} include, {added_exclude} exclude patterns",
    )


# ── Session ───────────────────────────────────────────────────────────────────


@router.post(
    "/session/inject",
    response_model=OperationResponse,
    summary="Inject auth session",
    description="Inject authentication session data (cookies, headers, bearer token) "
    "into the session pool for a specific role.",
)
async def inject_session(body: SessionInjectRequest) -> OperationResponse:
    api = get_api_state()
    engine = api.engine

    injected = []

    if body.cookies:
        await engine.sessions.update_session_cookies(body.role, body.cookies)
        injected.append(f"{len(body.cookies)} cookies")

    if body.headers:
        # Update role headers via session pool
        session = await engine.sessions.get_session(body.role)
        if session:
            session.role.headers.update(body.headers)
        injected.append(f"{len(body.headers)} headers")

    if body.token:
        session = await engine.sessions.get_session(body.role)
        if session:
            session.role.token = body.token
        injected.append("bearer token")

    # Auto-resume if engine is paused
    if hasattr(engine, '_state'):
        from prowl.core.engine import EngineState
        if engine._state == EngineState.PAUSED:
            engine.resume()
            injected.append("auto-resumed")

    return OperationResponse(
        status="ok",
        message=f"Injected {', '.join(injected)} for role '{body.role}'" if injected else "No data to inject",
    )


# ── Queue ─────────────────────────────────────────────────────────────────────


@router.get(
    "/queue/stats",
    response_model=QueueStatsResponse,
    summary="Get queue statistics",
    description="Returns current queue size, total URLs queued, and total dropped.",
)
async def get_queue_stats() -> QueueStatsResponse:
    api = get_api_state()
    q = api.engine.queue
    return QueueStatsResponse(
        queue_size=q.qsize,
        total_queued=q.total_queued,
        total_dropped=q.total_dropped,
    )


# ── Config Hot-Update ─────────────────────────────────────────────────────────


@router.post(
    "/config/update",
    response_model=OperationResponse,
    summary="Hot-update crawl config",
    description="Update mutable configuration fields mid-crawl without restart. "
    "Only max_depth, max_requests, request_delay, saturation_threshold, and user_agent "
    "can be changed at runtime.",
)
async def update_config(body: ConfigUpdateRequest) -> OperationResponse:
    api = get_api_state()
    engine = api.engine
    config = engine.config
    updated: list[str] = []

    if body.max_depth is not None:
        config.max_depth = body.max_depth
        updated.append(f"max_depth={body.max_depth}")

    if body.max_requests is not None:
        config.max_requests = body.max_requests
        updated.append(f"max_requests={body.max_requests}")

    if body.request_delay is not None:
        engine.rate_limiter._delay = body.request_delay
        updated.append(f"request_delay={body.request_delay}")

    if body.saturation_threshold is not None:
        config.saturation_threshold = body.saturation_threshold
        if hasattr(engine.coverage, "_sat_threshold"):
            engine.coverage._sat_threshold = body.saturation_threshold
        updated.append(f"saturation_threshold={body.saturation_threshold}")

    if body.user_agent is not None:
        config.user_agent = body.user_agent
        updated.append(f"user_agent={body.user_agent}")

    if not updated:
        return OperationResponse(status="noop", message="No fields to update")

    return OperationResponse(
        status="ok",
        message=f"Updated: {', '.join(updated)}",
    )


# ── Interventions ─────────────────────────────────────────────────────────────


@router.get(
    "/interventions",
    response_model=list[InterventionResponse],
    summary="List all interventions",
    description="Returns all intervention requests (pending, resolved, expired).",
)
async def list_interventions() -> list[InterventionResponse]:
    api = get_api_state()
    return [
        InterventionResponse(**i) for i in api.intervention_manager.get_all()
    ]


@router.get(
    "/interventions/pending",
    response_model=list[InterventionResponse],
    summary="List pending interventions",
    description="Returns only pending interventions that need resolution.",
)
async def list_pending_interventions() -> list[InterventionResponse]:
    api = get_api_state()
    return [
        InterventionResponse(
            id=i.id,
            kind=str(i.kind),
            message=i.message,
            module=i.module,
            state=str(i.state),
            data=i.data,
        )
        for i in api.intervention_manager.pending_interventions
    ]


@router.post(
    "/interventions/{intervention_id}/resolve",
    response_model=OperationResponse,
    summary="Resolve an intervention",
    description="Resolve an intervention by providing auth data (cookies, headers, token, credentials). "
    "The engine is automatically resumed after resolution.",
)
async def resolve_intervention(
    intervention_id: str, body: ResolveInterventionRequest
) -> OperationResponse:
    api = get_api_state()

    data: dict[str, Any] = {}
    if body.cookies:
        data["cookies"] = body.cookies
    if body.headers:
        data["headers"] = body.headers
    if body.token:
        data["token"] = body.token
    if body.credentials:
        data["credentials"] = body.credentials
    data.update(body.extra_data)

    success = await api.intervention_manager.resolve(intervention_id, data)
    if not success:
        raise HTTPException(404, "Intervention not found or already resolved")

    # Inject session if auth data was provided
    role = data.get("role", "default")
    if body.cookies:
        await api.engine.sessions.update_session_cookies(role, body.cookies)

    # Resume engine
    api.engine.resume()

    return OperationResponse(
        status="resolved",
        message=f"Intervention {intervention_id} resolved, engine resumed",
    )
