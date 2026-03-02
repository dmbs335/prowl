"""Crawl lifecycle endpoints: start, status, pause, resume, stop, config, phases, modules."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from fastapi import APIRouter, HTTPException

from prowl.api.deps import get_api_state
from prowl.api.schemas import (
    CrawlStartRequest,
    CrawlStatusResponse,
    ModuleStatusResponse,
    OperationResponse,
    PhaseStatusResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _build_status(api: Any) -> CrawlStatusResponse:
    engine = api.engine
    stats = engine.get_stats()
    return CrawlStatusResponse(
        state=str(engine.state),
        target=engine.config.target_url,
        elapsed=engine.elapsed,
        requests_completed=engine.requests_completed,
        requests_failed=engine.requests_failed,
        requests_queued=stats.get("requests_queued", 0),
        requests_dropped=stats.get("requests_dropped", 0),
        queue_size=stats.get("queue_size", 0),
        endpoints_found=engine.endpoints_found,
        unique_urls=stats.get("unique_urls", 0),
        transactions_stored=stats.get("transactions_stored", 0),
        phase_name=api.state.phase_name,
        current_phase=api.state.current_phase,
        coverage=stats.get("coverage", {}),
        hindsight=stats.get("hindsight", {}),
        rate_limiter=stats.get("rate_limiter", {}),
    )


async def _run_pipeline(api: Any) -> None:
    """Background task: run the full pipeline then write output."""
    from prowl.pipeline.orchestrator import PipelineOrchestrator

    orchestrator = api.orchestrator
    engine = api.engine
    config = engine.config
    start = time.time()

    try:
        await orchestrator.run()
    except Exception:
        logger.exception("Pipeline failed")
    finally:
        elapsed = time.time() - start
        # Import and call output writer from cli
        try:
            from prowl.cli import _write_output

            await _write_output(config, engine, orchestrator, elapsed)
        except Exception:
            logger.exception("Output writing failed")

        await engine.shutdown()


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post(
    "/crawl/start",
    response_model=CrawlStatusResponse,
    summary="Start a new crawl",
    description="Launch a new crawl session with full configuration. "
    "The crawl runs as a background task. Use GET /crawl/status to monitor progress.",
)
async def start_crawl(body: CrawlStartRequest) -> CrawlStatusResponse:
    from prowl.core.engine import CrawlEngine, EngineState
    from prowl.core.config import CrawlConfig
    from prowl.dashboard.bridge import DashboardBridge
    from prowl.dashboard.state import DashboardState
    from prowl.intervention.manager import InterventionManager
    from prowl.pipeline.orchestrator import PipelineOrchestrator

    api = get_api_state()

    # Reject if already running
    if api.engine.state in (EngineState.RUNNING, EngineState.PAUSED):
        raise HTTPException(
            status_code=409,
            detail=f"Engine is {api.engine.state}. Stop the current crawl first.",
        )

    # Build config from request
    config = CrawlConfig(**body.model_dump())

    # Create fresh engine and supporting components
    engine = CrawlEngine(config)
    await engine.startup()

    intervention_mgr = InterventionManager(engine.signals)
    dashboard_state = DashboardState()
    bridge = DashboardBridge(engine.signals, dashboard_state)
    orchestrator = PipelineOrchestrator(engine)

    # Update shared state
    api.engine = engine
    api.state = dashboard_state
    api.bridge = bridge
    api.intervention_manager = intervention_mgr
    api.orchestrator = orchestrator

    # Cancel previous background task if any
    if api._background_task and not api._background_task.done():
        api._background_task.cancel()

    # Run pipeline in background
    api._background_task = asyncio.create_task(_run_pipeline(api))

    return _build_status(api)


@router.get(
    "/crawl/status",
    response_model=CrawlStatusResponse,
    summary="Get crawl status",
    description="Returns full crawl status: engine state, request counts, "
    "coverage stats, rate limiter state, current phase.",
)
async def get_status() -> CrawlStatusResponse:
    return _build_status(get_api_state())


@router.post(
    "/crawl/pause",
    response_model=OperationResponse,
    summary="Pause the crawl",
    description="Pause all crawl workers. Queued requests are preserved.",
)
async def pause_crawl() -> OperationResponse:
    api = get_api_state()
    api.engine.pause()
    return OperationResponse(status="paused")


@router.post(
    "/crawl/resume",
    response_model=OperationResponse,
    summary="Resume the crawl",
    description="Resume a paused crawl.",
)
async def resume_crawl() -> OperationResponse:
    api = get_api_state()
    api.engine.resume()
    return OperationResponse(status="resumed")


@router.post(
    "/crawl/stop",
    response_model=OperationResponse,
    summary="Stop the crawl",
    description="Gracefully stop the crawl. Flushes pending data and writes output.",
)
async def stop_crawl() -> OperationResponse:
    api = get_api_state()
    await api.engine.stop()
    return OperationResponse(status="stopped")


@router.get(
    "/crawl/config",
    summary="Get current crawl config",
    description="Returns the CrawlConfig used for the current/last crawl.",
)
async def get_config() -> dict[str, Any]:
    api = get_api_state()
    return api.engine.config.model_dump()


# ── Phases ────────────────────────────────────────────────────────────────────


@router.get(
    "/phases",
    response_model=list[PhaseStatusResponse],
    summary="List all pipeline phases",
    description="Returns all 10 pipeline phases with current state and exploration statistics.",
)
async def list_phases() -> list[PhaseStatusResponse]:
    api = get_api_state()
    orchestrator = api.orchestrator
    if not orchestrator:
        return []

    exploration = orchestrator.get_phase_exploration()

    return [
        PhaseStatusResponse(
            name=phase.name,
            state=str(phase.state),
            modules=phase.modules,
            depends_on=phase.depends_on,
            parallel=phase.parallel,
            exploration=exploration.get(phase.name),
        )
        for phase in orchestrator.phases
    ]


@router.get(
    "/phases/{name}",
    response_model=PhaseStatusResponse,
    summary="Get phase detail",
    description="Returns detail for a specific pipeline phase by name.",
)
async def get_phase(name: str) -> PhaseStatusResponse:
    api = get_api_state()
    orchestrator = api.orchestrator
    if not orchestrator:
        raise HTTPException(404, "No orchestrator running")

    exploration = orchestrator.get_phase_exploration()

    for phase in orchestrator.phases:
        if phase.name == name:
            return PhaseStatusResponse(
                name=phase.name,
                state=str(phase.state),
                modules=phase.modules,
                depends_on=phase.depends_on,
                parallel=phase.parallel,
                exploration=exploration.get(phase.name),
            )
    raise HTTPException(404, f"Phase '{name}' not found")


# ── Modules ───────────────────────────────────────────────────────────────────


@router.get(
    "/modules",
    response_model=list[ModuleStatusResponse],
    summary="List all module stats",
    description="Returns stats for all 13 discovery modules.",
)
async def list_modules() -> list[ModuleStatusResponse]:
    api = get_api_state()
    module_states = api.state.module_states

    orchestrator = api.orchestrator
    module_stats = orchestrator.get_module_stats() if orchestrator else {}

    result = []
    for name, info in module_states.items():
        stats = module_stats.get(name, {})
        result.append(
            ModuleStatusResponse(
                name=name,
                state=info.get("state", "pending"),
                requests_made=stats.get("requests_made", 0),
                endpoints_found=stats.get("endpoints_found", 0),
                errors=stats.get("errors", 0),
                duration_seconds=stats.get("duration_seconds", 0.0),
            )
        )
    return result


@router.get(
    "/modules/{name}",
    response_model=ModuleStatusResponse,
    summary="Get module detail",
    description="Returns detail for a specific module by name.",
)
async def get_module(name: str) -> ModuleStatusResponse:
    api = get_api_state()
    module_states = api.state.module_states

    if name not in module_states:
        raise HTTPException(404, f"Module '{name}' not found")

    info = module_states[name]
    orchestrator = api.orchestrator
    stats = orchestrator.get_module_stats().get(name, {}) if orchestrator else {}

    return ModuleStatusResponse(
        name=name,
        state=info.get("state", "pending"),
        requests_made=stats.get("requests_made", 0),
        endpoints_found=stats.get("endpoints_found", 0),
        errors=stats.get("errors", 0),
        duration_seconds=stats.get("duration_seconds", 0.0),
    )
