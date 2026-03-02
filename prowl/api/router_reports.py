"""Report and analysis endpoints: summary, risk, high-risk findings, exploration stats."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from prowl.api.deps import get_api_state
from prowl.api.schemas import (
    AttackSurfaceSummaryResponse,
    EndpointResponse,
    ExplorationStatsResponse,
    HighRiskFindingsResponse,
    InputVectorResponse,
    RiskSummaryResponse,
    SecretResponse,
)
from prowl.api.router_discovery import (
    _endpoint_to_response,
    _iv_to_response,
    _secret_to_response,
)

router = APIRouter()


# ── Summary ───────────────────────────────────────────────────────────────────


@router.get(
    "/report/summary",
    response_model=AttackSurfaceSummaryResponse,
    summary="Attack surface summary",
    description="High-level attack surface overview with risk score, "
    "endpoint/vector/tech/secret counts for LLM triage.",
)
async def get_summary() -> AttackSurfaceSummaryResponse:
    api = get_api_state()
    store = api.engine.attack_surface
    report = store.build_report(
        target=api.engine.config.target_url,
        scan_duration=api.engine.elapsed,
    )

    return AttackSurfaceSummaryResponse(
        target=report.target,
        scan_duration=report.scan_duration,
        risk_summary=RiskSummaryResponse(
            total_endpoints=report.risk_summary.total_endpoints,
            total_input_vectors=report.risk_summary.total_input_vectors,
            high_risk_vectors=report.risk_summary.high_risk_vectors,
            auth_boundaries_found=report.risk_summary.auth_boundaries_found,
            unprotected_admin_paths=report.risk_summary.unprotected_admin_paths,
            exposed_debug_endpoints=report.risk_summary.exposed_debug_endpoints,
            secrets_found=report.risk_summary.secrets_found,
            score=report.risk_summary.score,
        ),
        endpoint_count=store.endpoint_count,
        input_vector_count=store.input_vector_count,
        tech_count=len(store.tech_stack),
        secret_count=len(store.secrets),
        auth_boundary_count=len(store.auth_boundaries),
        api_schema_count=len(store.api_schemas),
    )


# ── Risk ──────────────────────────────────────────────────────────────────────


@router.get(
    "/report/risk",
    response_model=RiskSummaryResponse,
    summary="Risk summary",
    description="Composite risk score (0-100) with breakdown: high-risk vectors, "
    "unprotected admin, exposed debug, secrets.",
)
async def get_risk() -> RiskSummaryResponse:
    api = get_api_state()
    report = api.engine.attack_surface.build_report(
        target=api.engine.config.target_url,
        scan_duration=api.engine.elapsed,
    )
    rs = report.risk_summary
    return RiskSummaryResponse(
        total_endpoints=rs.total_endpoints,
        total_input_vectors=rs.total_input_vectors,
        high_risk_vectors=rs.high_risk_vectors,
        auth_boundaries_found=rs.auth_boundaries_found,
        unprotected_admin_paths=rs.unprotected_admin_paths,
        exposed_debug_endpoints=rs.exposed_debug_endpoints,
        secrets_found=rs.secrets_found,
        score=rs.score,
    )


# ── High-Risk Findings ───────────────────────────────────────────────────────


@router.get(
    "/report/high-risk",
    response_model=HighRiskFindingsResponse,
    summary="High-risk findings",
    description="Consolidated high-risk findings: input vectors with risk indicators, "
    "unprotected admin endpoints, exposed debug endpoints, and discovered secrets.",
)
async def get_high_risk() -> HighRiskFindingsResponse:
    api = get_api_state()
    store = api.engine.attack_surface

    high_risk_ivs = store.get_high_risk_vectors()
    admin_unprotected = [
        ep for ep in store.endpoints
        if ep.page_type == "admin" and not ep.requires_auth
    ]
    debug_exposed = [
        ep for ep in store.endpoints
        if any(t in ep.tags for t in ("debug", "actuator", "phpinfo"))
    ]

    return HighRiskFindingsResponse(
        high_risk_input_vectors=[_iv_to_response(iv) for iv in high_risk_ivs],
        unprotected_admin_endpoints=[_endpoint_to_response(ep) for ep in admin_unprotected],
        exposed_debug_endpoints=[_endpoint_to_response(ep) for ep in debug_exposed],
        secrets=[_secret_to_response(s) for s in store.secrets],
    )


# ── Exploration Stats ─────────────────────────────────────────────────────────


@router.get(
    "/report/exploration",
    response_model=ExplorationStatsResponse,
    summary="Exploration statistics",
    description="Coverage bitmap, hindsight feedback, rate limiter state, "
    "per-phase exploration stats, and per-module stats.",
)
async def get_exploration() -> ExplorationStatsResponse:
    api = get_api_state()
    engine = api.engine
    orchestrator = api.orchestrator

    phase_exploration: dict[str, dict[str, Any]] = {}
    module_stats: dict[str, dict[str, Any]] = {}
    if orchestrator:
        phase_exploration = orchestrator.get_phase_exploration()
        module_stats = orchestrator.get_module_stats()

    return ExplorationStatsResponse(
        coverage=engine.coverage.get_stats(),
        hindsight=engine.hindsight.get_stats(),
        rate_limiter=engine.rate_limiter.get_stats(),
        phase_exploration=phase_exploration,
        module_stats=module_stats,
    )


# ── Full Report ───────────────────────────────────────────────────────────────


@router.get(
    "/report/full",
    summary="Full attack surface report",
    description="Returns the complete AttackSurfaceReport as JSON. "
    "Warning: this can be large for big scans.",
)
async def get_full_report() -> dict[str, Any]:
    api = get_api_state()
    report = api.engine.attack_surface.build_report(
        target=api.engine.config.target_url,
        scan_duration=api.engine.elapsed,
    )

    # Add module reports if orchestrator available
    if api.orchestrator:
        from prowl.models.report import ModuleReport

        module_reports = []
        for name, stats in api.orchestrator.get_module_stats().items():
            module_reports.append(
                ModuleReport(
                    module_name=name,
                    endpoints_found=stats.get("endpoints_found", 0),
                    requests_made=stats.get("requests_made", 0),
                    errors=stats.get("errors", 0),
                    duration_seconds=stats.get("duration_seconds", 0.0),
                )
            )
        report.module_reports = module_reports

    return report.model_dump()


# ── Hindsight ─────────────────────────────────────────────────────────────────


@router.get(
    "/report/hindsight",
    summary="Hindsight analysis insights",
    description="Returns hindsight feedback insights: patterns detected from "
    "non-success responses (auth boundaries, method hints, etc.).",
)
async def get_hindsight(
    insight_type: str | None = Query(
        None, description="Filter by insight type (auth_redirect, method_not_allowed, etc.)"
    ),
) -> dict[str, Any]:
    api = get_api_state()
    stats = api.engine.hindsight.get_stats()

    if insight_type:
        insights = [
            i for i in api.engine.hindsight.insights
            if getattr(i, "insight_type", "") == insight_type
        ]
        stats["filtered_insights"] = len(insights)

    return stats
