"""FastAPI dependency injection for the LLM orchestration API."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from prowl.core.engine import CrawlEngine
    from prowl.dashboard.bridge import DashboardBridge
    from prowl.dashboard.state import DashboardState
    from prowl.intervention.manager import InterventionManager
    from prowl.pipeline.orchestrator import PipelineOrchestrator


@dataclass
class APIState:
    """Shared state holder injected into all API route handlers."""

    engine: CrawlEngine
    state: DashboardState
    bridge: DashboardBridge
    intervention_manager: InterventionManager
    orchestrator: PipelineOrchestrator | None = None
    _background_task: asyncio.Task[Any] | None = field(
        default=None, repr=False
    )


# Module-level singleton, set during app startup
_api_state: APIState | None = None


def set_api_state(state: APIState) -> None:
    global _api_state
    _api_state = state


def get_api_state() -> APIState:
    if _api_state is None:
        raise RuntimeError("API state not initialized")
    return _api_state
