"""Orchestration endpoints: request merging, credential management, LLM decision support."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from fastapi import APIRouter, HTTPException

from prowl.api.deps import get_api_state
from prowl.api.schemas import (
    AutoLoginRequest,
    AutoMergeRuleRequest,
    AutoMergeRulesResponse,
    CoverageGapItem,
    CoverageGapsResponse,
    DecisionContextSnapshot,
    EndpointClusterItem,
    EndpointClusterResponse,
    HypothesisTestRequest,
    LoginResultResponse,
    MergeCandidateResponse,
    MergePreviewResponse,
    MergeRequestsRequest,
    MergeResultResponse,
    OperationResponse,
    PlaybookResult,
    QueueDetailedStatsResponse,
    QueueItemResponse,
    QueueItemsResponse,
    QueueRemoveRequest,
    ReauthRequest,
    ReprioritizeRequest,
    RoleStatusResponse,
    StrategyAdjustRequest,
    TemplateProductivity,
)
from prowl.core.exploration import CoverageBitmap

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/orchestration")


# ── Helpers ──────────────────────────────────────────────────────────────────


def _normalize(url: str) -> str:
    """Normalize URL to template using CoverageBitmap logic."""
    return CoverageBitmap._normalize_to_template(url)


def _group_by_template(requests: list) -> dict[str, list]:
    """Group CrawlRequest list by normalized URL template."""
    groups: dict[str, list] = defaultdict(list)
    for req in requests:
        template = _normalize(req.url)
        groups[template].append(req)
    return groups


# ── Queue Operations ─────────────────────────────────────────────────────────


@router.get(
    "/queue/merge-preview",
    response_model=MergePreviewResponse,
    summary="Preview merge candidates",
    description="Dry-run showing which queued requests would be merged "
    "under a given strategy, without modifying the queue.",
)
async def merge_preview(
    strategy: str = "batch_endpoints",
    url_pattern: str = "",
    sample_size: int = 3,
) -> MergePreviewResponse:
    api = get_api_state()
    engine = api.engine

    all_reqs = await engine.queue.peek_all()
    if url_pattern:
        all_reqs = [r for r in all_reqs if url_pattern in r.url]

    groups = _group_by_template(all_reqs)

    candidates: list[MergeCandidateResponse] = []
    total_after = 0

    for template, reqs in sorted(groups.items(), key=lambda x: -len(x[1])):
        if len(reqs) < 2:
            total_after += 1
            continue

        methods = list({r.method.upper() for r in reqs})
        sample_urls = [r.url for r in reqs[:5]]

        if strategy == "combine_params":
            # Would merge into 1 per template+method combo
            after = len(methods)
        elif strategy == "sample_template":
            after = min(len(reqs), sample_size)
        else:  # batch_endpoints
            after = 1

        total_after += after
        candidates.append(MergeCandidateResponse(
            template=template,
            request_count=len(reqs),
            sample_urls=sample_urls,
            methods=methods,
        ))

    # Add singletons
    singletons = sum(1 for reqs in groups.values() if len(reqs) < 2)
    total_after += 0  # already counted above

    total_before = len(all_reqs)
    reduction = ((total_before - total_after) / total_before * 100) if total_before else 0.0

    return MergePreviewResponse(
        candidates=candidates,
        total_before=total_before,
        total_after=total_after,
        reduction_pct=round(reduction, 1),
    )


@router.post(
    "/queue/merge",
    response_model=MergeResultResponse,
    summary="Merge queued requests",
    description="Merge multiple queued requests into fewer requests "
    "based on URL template grouping. Reduces queue size for efficient crawling.",
)
async def merge_queue(body: MergeRequestsRequest) -> MergeResultResponse:
    from prowl.core.signals import Signal
    from prowl.models.request import CrawlRequest

    api = get_api_state()
    engine = api.engine

    # Drain all matching requests
    if body.url_pattern:
        removed, kept = await engine.queue.drain_matching(
            lambda r: body.url_pattern in r.url
        )
    else:
        removed, kept = await engine.queue.drain_matching(lambda _: True)

    if not removed:
        return MergeResultResponse(
            merged_groups=0,
            requests_before=kept,
            requests_after=kept,
            reduction_pct=0.0,
        )

    total_before = len(removed) + kept
    groups = _group_by_template(removed)
    merged_groups = 0
    re_queued = 0

    for template, reqs in groups.items():
        if len(reqs) < 2:
            # Singleton: re-queue as-is
            for r in reqs:
                await engine.queue._queue.put((-r.priority, engine.queue._counter, r))
                engine.queue._counter += 1
                re_queued += 1
            continue

        merged_groups += 1

        if body.strategy == "combine_params":
            # Merge query params across same template into combined requests per method
            by_method: dict[str, list] = defaultdict(list)
            for r in reqs:
                by_method[r.method.upper()].append(r)

            for method, method_reqs in by_method.items():
                # Combine all query params
                combined_params: dict[str, str] = {}
                base_req = method_reqs[0]
                for r in method_reqs:
                    parsed = urlparse(r.url)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    for k, vs in params.items():
                        if k not in combined_params:
                            combined_params[k] = vs[0] if vs else ""

                # Build merged URL
                parsed = urlparse(base_req.url)
                merged_query = urlencode(combined_params)
                merged_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    "", merged_query, "",
                ))

                merged = CrawlRequest(
                    url=merged_url,
                    method=method.lower(),
                    source_module="orchestration:merge",
                    priority=max(r.priority for r in method_reqs),
                    depth=min(r.depth for r in method_reqs),
                    auth_role=base_req.auth_role,
                )
                await engine.queue._queue.put((-merged.priority, engine.queue._counter, merged))
                engine.queue._counter += 1
                re_queued += 1

        elif body.strategy == "sample_template":
            # Keep N representative samples
            samples = reqs[:body.sample_size]
            for r in samples:
                await engine.queue._queue.put((-r.priority, engine.queue._counter, r))
                engine.queue._counter += 1
                re_queued += 1

        else:  # batch_endpoints
            # Keep highest-priority request per template
            best = max(reqs, key=lambda r: r.priority)
            await engine.queue._queue.put((-best.priority, engine.queue._counter, best))
            engine.queue._counter += 1
            re_queued += 1

    total_after = re_queued + kept
    reduction = ((total_before - total_after) / total_before * 100) if total_before else 0.0

    await engine.signals.emit(
        Signal.QUEUE_MERGED,
        merged_groups=merged_groups,
        reduction_pct=round(reduction, 1),
    )

    return MergeResultResponse(
        merged_groups=merged_groups,
        requests_before=total_before,
        requests_after=total_after,
        reduction_pct=round(reduction, 1),
    )


@router.post(
    "/queue/reprioritize",
    response_model=OperationResponse,
    summary="Reprioritize queued requests",
    description="Change priority of queued requests matching URL patterns. "
    "Higher priority values are processed sooner.",
)
async def reprioritize_queue(body: ReprioritizeRequest) -> OperationResponse:
    api = get_api_state()
    engine = api.engine

    # Drain all, adjust, re-insert
    all_items: list[tuple[int, int, Any]] = []
    while not engine.queue._queue.empty():
        try:
            all_items.append(engine.queue._queue.get_nowait())
        except Exception:
            break

    affected = 0
    for i, (neg_prio, counter, req) in enumerate(all_items):
        for rule in body.rules:
            if rule.url_pattern in req.url:
                req.priority = rule.new_priority
                all_items[i] = (-rule.new_priority, counter, req)
                affected += 1
                break

    for item in all_items:
        await engine.queue._queue.put(item)

    return OperationResponse(
        status="ok",
        message=f"Reprioritized {affected} requests across {len(body.rules)} rules",
    )


@router.post(
    "/queue/remove",
    response_model=OperationResponse,
    summary="Remove requests from queue",
    description="Remove queued requests matching any of the given URL patterns.",
)
async def remove_from_queue(body: QueueRemoveRequest) -> OperationResponse:
    api = get_api_state()
    engine = api.engine

    def matches(req: Any) -> bool:
        return any(p in req.url for p in body.url_patterns)

    removed, kept = await engine.queue.drain_matching(matches)

    return OperationResponse(
        status="ok",
        message=f"Removed {len(removed)} requests ({kept} remaining)",
    )


@router.post(
    "/queue/pause",
    response_model=OperationResponse,
    summary="Pause queue processing",
    description="Pause all worker threads. Requests stay in queue but are not processed.",
)
async def pause_queue() -> OperationResponse:
    api = get_api_state()
    engine = api.engine
    engine.pause()
    return OperationResponse(status="paused", message="Queue processing paused")


@router.post(
    "/queue/resume",
    response_model=OperationResponse,
    summary="Resume queue processing",
    description="Resume worker threads after a pause.",
)
async def resume_queue() -> OperationResponse:
    api = get_api_state()
    engine = api.engine
    engine.resume()
    return OperationResponse(status="resumed", message="Queue processing resumed")


@router.post(
    "/queue/clear",
    response_model=OperationResponse,
    summary="Clear entire queue",
    description="Remove all pending requests from the queue.",
)
async def clear_queue() -> OperationResponse:
    api = get_api_state()
    engine = api.engine
    removed, _kept = await engine.queue.drain_matching(lambda _: True)
    return OperationResponse(
        status="ok",
        message=f"Cleared {len(removed)} requests from queue",
    )


@router.get(
    "/queue/items",
    response_model=QueueItemsResponse,
    summary="List queued requests",
    description="Paginated view of all requests currently in queue, sorted by priority.",
)
async def list_queue_items(
    offset: int = 0,
    limit: int = 50,
) -> QueueItemsResponse:
    api = get_api_state()
    engine = api.engine
    all_reqs = await engine.queue.peek_all()
    # Sort by priority descending (highest first)
    all_reqs.sort(key=lambda r: -r.priority)
    total = len(all_reqs)
    page = all_reqs[offset:offset + limit]
    return QueueItemsResponse(
        items=[
            QueueItemResponse(
                url=r.url,
                method=r.method.upper(),
                priority=r.priority,
                depth=r.depth,
                source_module=r.source_module or "",
                auth_role=getattr(r, "auth_role", None),
            )
            for r in page
        ],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get(
    "/queue/stats",
    response_model=QueueDetailedStatsResponse,
    summary="Detailed queue statistics",
    description="Breakdown of queue by source module, priority band, and processing state.",
)
async def get_queue_stats() -> QueueDetailedStatsResponse:
    from prowl.core.engine import EngineState

    api = get_api_state()
    engine = api.engine
    all_reqs = await engine.queue.peek_all()

    by_source: dict[str, int] = defaultdict(int)
    by_priority: dict[str, int] = defaultdict(int)
    for r in all_reqs:
        src = r.source_module or "unknown"
        by_source[src] += 1
        if r.priority >= 20:
            by_priority["high (20+)"] += 1
        elif r.priority >= 10:
            by_priority["medium (10-19)"] += 1
        else:
            by_priority["low (0-9)"] += 1

    return QueueDetailedStatsResponse(
        queue_size=engine.queue.qsize,
        total_queued=engine.queue.total_queued,
        total_dropped=engine.queue.total_dropped,
        total_auto_merged=engine.queue.total_auto_merged,
        active_requests=engine._active_requests,
        is_paused=engine._state == EngineState.PAUSED,
        by_source=dict(by_source),
        by_priority=dict(by_priority),
    )


# ── Auto-Merge Rules ────────────────────────────────────────────────────────


@router.post(
    "/queue/auto-merge-rules",
    response_model=OperationResponse,
    summary="Add auto-merge rule",
    description="Register a rule that auto-drops URLs when the same template "
    "already has N entries queued. Persists for the session.",
)
async def add_auto_merge_rule(body: AutoMergeRuleRequest) -> OperationResponse:
    api = get_api_state()
    engine = api.engine
    engine.queue.add_auto_merge_rule(body.pattern, body.max_per_template)
    return OperationResponse(
        status="ok",
        message=f"Auto-merge rule added: {body.pattern} (max {body.max_per_template})",
    )


@router.get(
    "/queue/auto-merge-rules",
    response_model=AutoMergeRulesResponse,
    summary="List auto-merge rules",
    description="Return all active auto-merge rules and total items dropped.",
)
async def list_auto_merge_rules() -> AutoMergeRulesResponse:
    api = get_api_state()
    engine = api.engine
    return AutoMergeRulesResponse(
        rules=engine.queue.get_auto_merge_rules(),
        total_auto_merged=engine.queue.total_auto_merged,
    )


@router.delete(
    "/queue/auto-merge-rules",
    response_model=OperationResponse,
    summary="Remove auto-merge rule",
    description="Remove an auto-merge rule by pattern.",
)
async def remove_auto_merge_rule(pattern: str) -> OperationResponse:
    api = get_api_state()
    engine = api.engine
    removed = engine.queue.remove_auto_merge_rule(pattern)
    if not removed:
        return OperationResponse(status="not_found", message=f"Rule not found: {pattern}")
    return OperationResponse(status="ok", message=f"Removed auto-merge rule: {pattern}")


# ── Auth Management ──────────────────────────────────────────────────────────


@router.post(
    "/auth/login",
    response_model=LoginResultResponse,
    summary="Auto-login with credentials",
    description="Fetch the login page, auto-detect form fields, and POST credentials. "
    "On success, cookies are registered in the session pool for the specified role.",
)
async def auto_login(body: AutoLoginRequest) -> LoginResultResponse:
    from prowl.core.auth_utils import perform_login
    from prowl.core.signals import Signal
    from prowl.models.session import AuthRole, AuthSession, Credential

    api = get_api_state()
    engine = api.engine

    result = await perform_login(
        login_url=body.login_url,
        username=body.username,
        password=body.password,
        extra_fields=body.extra_fields or None,
    )

    if result["success"]:
        # Register role and session in engine
        role = AuthRole(
            name=body.role,
            cookies=result["cookies"],
            is_active=True,
            credential=Credential(
                username=body.username,
                password=body.password,
                login_url=body.login_url,
                extra_fields=body.extra_fields or {},
            ),
        )
        engine.sessions.add_role(role)
        session = AuthSession(role=role, session_cookies=result["cookies"])
        engine.sessions.add_session(session)

    await engine.signals.emit(
        Signal.AUTH_LOGIN_ATTEMPTED,
        role=body.role,
        success=result["success"],
        message=result["message"],
    )

    return LoginResultResponse(
        success=result["success"],
        role=body.role,
        cookies_obtained=len(result.get("cookies", {})),
        message=result["message"],
    )


@router.get(
    "/auth/roles",
    response_model=list[RoleStatusResponse],
    summary="List auth roles",
    description="Returns all registered auth roles with session status.",
)
async def list_roles() -> list[RoleStatusResponse]:
    api = get_api_state()
    pool = api.engine.sessions

    result: list[RoleStatusResponse] = []
    for role_name, role in pool._roles.items():
        sessions = pool._sessions.get(role_name, [])
        valid = [s for s in sessions if s.is_valid]
        result.append(RoleStatusResponse(
            name=role_name,
            is_active=role.is_active,
            has_credentials=role.credential is not None,
            session_count=len(sessions),
            valid_sessions=len(valid),
            cookies_count=len(role.cookies),
            last_used=max((s.last_used for s in sessions), default=0.0),
            total_requests=sum(s.request_count for s in sessions),
        ))

    return result


@router.post(
    "/auth/reauth",
    response_model=LoginResultResponse,
    summary="Re-authenticate a role",
    description="Re-authenticate an existing role using its stored credentials. "
    "Fails if no credentials are stored for the role.",
)
async def reauth(body: ReauthRequest) -> LoginResultResponse:
    from prowl.core.auth_utils import perform_login
    from prowl.core.signals import Signal
    from prowl.models.session import AuthSession

    api = get_api_state()
    pool = api.engine.sessions

    role = pool._roles.get(body.role)
    if not role:
        raise HTTPException(404, f"Role '{body.role}' not found")
    if not role.credential:
        raise HTTPException(400, f"No stored credentials for role '{body.role}'")

    result = await perform_login(
        login_url=role.credential.login_url,
        username=role.credential.username,
        password=role.credential.password,
        extra_fields=role.credential.extra_fields or None,
    )

    if result["success"]:
        role.cookies.update(result["cookies"])
        role.is_active = True
        session = AuthSession(role=role, session_cookies=result["cookies"])
        pool.add_session(session)

    await api.engine.signals.emit(
        Signal.AUTH_LOGIN_ATTEMPTED,
        role=body.role,
        success=result["success"],
        message=f"Re-auth: {result['message']}",
    )

    return LoginResultResponse(
        success=result["success"],
        role=body.role,
        cookies_obtained=len(result.get("cookies", {})),
        message=result["message"],
    )


@router.delete(
    "/auth/roles/{role_name}",
    response_model=OperationResponse,
    summary="Remove an auth role",
    description="Delete a role and all its sessions from the session pool.",
)
async def delete_role(role_name: str) -> OperationResponse:
    api = get_api_state()
    pool = api.engine.sessions

    if role_name not in pool._roles:
        raise HTTPException(404, f"Role '{role_name}' not found")

    del pool._roles[role_name]
    pool._sessions.pop(role_name, None)

    return OperationResponse(
        status="ok",
        message=f"Deleted role '{role_name}' and its sessions",
    )


# ── LLM Decision Support ────────────────────────────────────────────────────


@router.get(
    "/context/snapshot",
    response_model=DecisionContextSnapshot,
    summary="Get decision context snapshot",
    description="All-in-one context dump for LLM orchestrator decision-making. "
    "Call once per decision cycle to get crawl state, coverage, queue pressure, "
    "auth status, productive templates, and exploration gaps.",
)
async def get_decision_context() -> DecisionContextSnapshot:
    api = get_api_state()
    engine = api.engine

    # Coverage stats
    cov_stats = engine.coverage.get_stats()

    # Thompson Sampling: top productive templates
    ts_items: list[tuple[str, int, int]] = []
    for template in set(list(engine.scheduler._ts_alpha.keys()) + list(engine.scheduler._ts_beta.keys())):
        alpha = engine.scheduler._ts_alpha.get(template, 1)
        beta = engine.scheduler._ts_beta.get(template, 1)
        ts_items.append((template, alpha, beta))

    # Top productive (high alpha)
    top_productive = sorted(ts_items, key=lambda x: -x[1])[:20]
    # Under-explored (high beta relative to alpha)
    under_explored = sorted(ts_items, key=lambda x: -(x[2] / max(x[1], 1)))[:20]

    # Method hints from hindsight
    method_hints = [
        {"url": h.url, "method": h.method, "detail": h.detail}
        for h in engine.hindsight.get_method_hints()
    ][:20]

    # Active roles
    active_roles = [
        name for name, role in engine.sessions._roles.items()
        if role.is_active
    ]

    # Module discovery rates
    module_rates: dict[str, float] = {}
    for mod_name, rate in engine.scheduler._module_discovery_rate.items():
        module_rates[mod_name] = round(rate, 4)

    # Rate limiter
    rl_stats = engine.rate_limiter.get_stats()

    # Pending interventions
    pending_count = len(api.intervention_manager.pending_interventions)

    return DecisionContextSnapshot(
        crawl_state=str(engine.state),
        elapsed=round(engine.elapsed, 1),
        target=engine.config.target_url,
        phase_name=api.state.phase_name if api.state else "",
        current_phase=api.state.current_phase if api.state else 0,
        requests_completed=engine.requests_completed,
        requests_failed=engine.requests_failed,
        queue_size=engine.queue.qsize,
        endpoints_found=engine.endpoints_found,
        coverage_unique=cov_stats.get("unique_coverage", 0),
        coverage_discovery_rate=cov_stats.get("discovery_rate", 0.0),
        coverage_saturated=cov_stats.get("saturated", False),
        queue_total_queued=engine.queue.total_queued,
        queue_total_dropped=engine.queue.total_dropped,
        active_roles=active_roles,
        pending_interventions=pending_count,
        top_productive_templates=[
            TemplateProductivity(
                template=t, alpha=a, beta=b,
                hit_rate=round(a / max(a + b, 1), 3),
            )
            for t, a, b in top_productive
        ],
        under_explored_areas=[
            TemplateProductivity(
                template=t, alpha=a, beta=b,
                hit_rate=round(a / max(a + b, 1), 3),
            )
            for t, a, b in under_explored
        ],
        method_hints=method_hints,
        module_discovery_rates=module_rates,
        rate_limiter_delay=rl_stats.get("current_delay", 0.0),
        rate_limiter_backoffs=rl_stats.get("total_backoffs", 0),
    )


@router.post(
    "/strategy/adjust",
    response_model=OperationResponse,
    summary="Adjust crawl strategy",
    description="Adjust module weights, focus patterns, and depth mid-crawl. "
    "Focus patterns boost priority for matching queued requests.",
)
async def adjust_strategy(body: StrategyAdjustRequest) -> OperationResponse:
    from prowl.core.signals import Signal

    api = get_api_state()
    engine = api.engine
    changes: list[str] = []

    # Depth override
    if body.depth_override is not None:
        engine.config.max_depth = body.depth_override
        changes.append(f"max_depth={body.depth_override}")

    # Module weight adjustments: update discovery rate multipliers
    for mod_name, weight in body.module_weights.items():
        current = engine.scheduler._module_discovery_rate.get(mod_name, 0.0)
        engine.scheduler._module_discovery_rate[mod_name] = current * weight
        changes.append(f"{mod_name} weight x{weight}")

    # Focus patterns: boost matching items in queue
    if body.focus_patterns:
        all_items: list[tuple[int, int, Any]] = []
        while not engine.queue._queue.empty():
            try:
                all_items.append(engine.queue._queue.get_nowait())
            except Exception:
                break

        boosted = 0
        for i, (neg_prio, counter, req) in enumerate(all_items):
            for pattern in body.focus_patterns:
                if pattern in req.url:
                    req.priority += body.focus_boost
                    all_items[i] = (-(req.priority), counter, req)
                    boosted += 1
                    break

        for item in all_items:
            await engine.queue._queue.put(item)
        changes.append(f"boosted {boosted} requests for {len(body.focus_patterns)} patterns")

    detail = ", ".join(changes) if changes else "No changes applied"
    await engine.signals.emit(Signal.STRATEGY_ADJUSTED, detail=detail)

    return OperationResponse(status="ok", message=detail)


@router.get(
    "/endpoints/clusters",
    response_model=EndpointClusterResponse,
    summary="Get endpoint clusters",
    description="Group discovered endpoints by URL template for efficient analysis. "
    "Each cluster shows methods, parameters, coverage stats, and sample URLs.",
)
async def get_endpoint_clusters() -> EndpointClusterResponse:
    api = get_api_state()
    engine = api.engine

    # Group endpoints by template
    clusters: dict[str, dict] = defaultdict(lambda: {
        "count": 0, "methods": set(), "param_names": set(),
        "sample_urls": [], "has_auth_boundary": False,
    })

    for ep in engine.discovered_endpoints:
        template = _normalize(ep.url)
        c = clusters[template]
        c["count"] += 1
        c["methods"].add(ep.method.upper())
        if hasattr(ep, "parameters"):
            for p in (ep.parameters or []):
                c["param_names"].add(p.name if hasattr(p, "name") else str(p))
        if len(c["sample_urls"]) < 5:
            c["sample_urls"].append(ep.url)

    # Check auth boundaries
    for ab in engine.attack_surface.auth_boundaries:
        template = _normalize(ab.url)
        if template in clusters:
            clusters[template]["has_auth_boundary"] = True

    items: list[EndpointClusterItem] = []
    for template, data in sorted(clusters.items(), key=lambda x: -x[1]["count"]):
        alpha = engine.scheduler._ts_alpha.get(template, 1)
        beta = engine.scheduler._ts_beta.get(template, 1)
        items.append(EndpointClusterItem(
            template=template,
            count=data["count"],
            methods=sorted(data["methods"]),
            param_names=sorted(data["param_names"]),
            coverage_alpha=alpha,
            coverage_beta=beta,
            sample_urls=data["sample_urls"],
            has_auth_boundary=data["has_auth_boundary"],
        ))

    return EndpointClusterResponse(
        clusters=items,
        total_endpoints=len(engine.discovered_endpoints),
        total_templates=len(items),
    )


@router.get(
    "/coverage/gaps",
    response_model=CoverageGapsResponse,
    summary="Analyze coverage gaps",
    description="Identify under-explored areas: untested methods, auth boundaries "
    "never re-tested with credentials, unspidered endpoints, low-coverage templates.",
)
async def get_coverage_gaps() -> CoverageGapsResponse:
    api = get_api_state()
    engine = api.engine

    gaps: list[CoverageGapItem] = []

    # 1. Method hints: 405s suggesting other methods
    for hint in engine.hindsight.get_method_hints():
        gaps.append(CoverageGapItem(
            gap_type="untested_method",
            url=hint.url,
            detail=hint.detail,
            suggested_action=f"Retry with suggested methods: {hint.detail}",
        ))

    # 2. Unspidered endpoints (discovered but never deeply crawled)
    unspidered = engine.get_unspidered_endpoints()
    for ep in unspidered[:30]:
        gaps.append(CoverageGapItem(
            gap_type="unspidered",
            url=ep.url,
            detail=f"{ep.method} {ep.url} discovered by {ep.source_module} but never spidered",
            suggested_action="Inject URL for deep crawl",
        ))

    # 3. Auth boundaries not yet tested with credentials
    active_roles = [n for n, r in engine.sessions._roles.items() if r.is_active]
    if active_roles:
        for ab in engine.attack_surface.auth_boundaries:
            if ab.auth_status is None or ab.auth_status == 0:
                gaps.append(CoverageGapItem(
                    gap_type="auth_boundary",
                    url=ab.url,
                    detail=f"Auth boundary ({ab.boundary_type}) not re-tested with credentials",
                    suggested_action=f"Re-test with roles: {', '.join(active_roles)}",
                ))

    # 4. Low-coverage templates (high beta, low alpha in Thompson Sampling)
    for template in engine.scheduler._ts_beta:
        alpha = engine.scheduler._ts_alpha.get(template, 1)
        beta = engine.scheduler._ts_beta.get(template, 1)
        if beta > 5 and alpha <= 1:
            gaps.append(CoverageGapItem(
                gap_type="low_coverage",
                url=template,
                detail=f"Template tried {alpha + beta - 2} times but only {alpha - 1} new coverage hits",
                suggested_action="Consider different methods, params, or auth roles",
            ))

    # Cap at 100 gaps
    gaps = gaps[:100]

    return CoverageGapsResponse(
        gaps=gaps,
        total_gaps=len(gaps),
    )


@router.post(
    "/hypothesis/test",
    response_model=OperationResponse,
    summary="Test a hypothesis",
    description="Inject targeted test requests based on a hypothesis about the application. "
    "Useful for LLM-driven exploration: formulate a theory, inject tests, observe results.",
)
async def test_hypothesis(body: HypothesisTestRequest) -> OperationResponse:
    from prowl.core.engine import EngineState
    from prowl.models.request import CrawlRequest

    api = get_api_state()
    engine = api.engine

    if engine.state not in (EngineState.RUNNING, EngineState.PAUSED):
        raise HTTPException(409, "Engine is not running")

    injected = 0
    rejected = 0

    for url in body.test_urls:
        if not engine.scope.is_in_scope(url):
            rejected += 1
            continue

        for method in body.methods:
            req = CrawlRequest(
                url=url,
                method=method.lower(),
                source_module="orchestration:hypothesis",
                priority=body.priority,
                auth_role=body.auth_role,
                meta={"hypothesis": body.hypothesis},
            )
            added = await engine.submit(req)
            if added:
                injected += 1
            else:
                rejected += 1

    logger.info("Hypothesis test: '%s' -> %d injected, %d rejected", body.hypothesis, injected, rejected)

    return OperationResponse(
        status="ok",
        message=f"Hypothesis '{body.hypothesis}': {injected} requests injected, {rejected} rejected",
    )


# ── Playbook ─────────────────────────────────────────────────────────────────


@router.get(
    "/playbook/results",
    response_model=PlaybookResult,
    summary="Get playbook results",
    description="Return accumulated playbook findings from all phase checkpoints during the current crawl.",
)
async def get_playbook_results() -> PlaybookResult:
    state = get_api_state()
    engine = state.engine
    playbook = getattr(engine, "_playbook", None)
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook engine not active")
    return playbook.get_result()
