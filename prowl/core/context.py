"""DiscoveryContext -- narrow facade over CrawlEngine for module use.

Modules access engine capabilities through this context rather than
reaching into the engine's internal state directly.  The engine itself
is still stored on modules (self.engine) for backward compatibility,
but new module code should prefer self.ctx.

Groups engine functionality into clear concerns:
  A. Request execution: execute(), submit(), wait_rate_limit()
  B. Endpoint registration: register_endpoint(), discovered_endpoints,
     get_unspidered_endpoints(), mark_spidered()
  C. Attack surface: attack_surface (delegated store)
  D. Storage: transaction_store (delegated store)
  E. Signals: signals (delegated bus)
  F. Configuration: config (delegated, read-only)
  G. Exploration: coverage, scheduler, hindsight
  H. Sessions: sessions (delegated pool)
  I. Scope: scope, dedup (delegated)
  J. Worker state: requests_completed, requests_failed, is_queue_empty,
     active_requests, workers_done
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from prowl.core.attack_surface import AttackSurfaceStore
    from prowl.core.config import CrawlConfig
    from prowl.core.dedup import DeduplicationManager
    from prowl.core.exploration import (
        CoverageBitmap,
        HindsightFeedback,
        SeedScheduler,
        URLTemplateInferrer,
    )
    from prowl.core.rate_limiter import DomainRateLimiter
    from prowl.core.scope import ScopeManager
    from prowl.core.session_pool import SessionPool
    from prowl.core.signals import SignalBus
    from prowl.models.request import CrawlRequest, CrawlResponse
    from prowl.models.target import Endpoint
    from prowl.store.transaction_store import TransactionStore


class DiscoveryContext:
    """Facade that exposes a narrowed view of CrawlEngine for modules.

    All properties delegate to the underlying engine -- this is NOT a
    copy or a separate object graph.  It is a documentation boundary
    that makes the module-engine contract explicit.
    """

    __slots__ = ("_engine",)

    def __init__(self, engine: Any) -> None:
        self._engine = engine

    # ── A. Request execution ──────────────────────────────────────────

    async def execute(self, request: CrawlRequest) -> CrawlResponse:
        """Execute a single HTTP request through the backend."""
        return await self._engine.execute(request)

    async def submit(self, request: CrawlRequest) -> bool:
        """Submit a request to the queue (scope + dedup checked)."""
        return await self._engine.submit(request)

    async def wait_rate_limit(self, url: str = "") -> None:
        """Wait for the adaptive rate limiter before sending a request."""
        await self._engine.rate_limiter.wait(url)

    async def run_workers(self, num_workers: int | None = None) -> None:
        """Start concurrent workers to process the request queue."""
        await self._engine.run_workers(num_workers)

    # ── B. Endpoint registration ──────────────────────────────────────

    async def register_endpoint(self, endpoint: Endpoint) -> None:
        """Register a newly discovered endpoint."""
        await self._engine.register_endpoint(endpoint)

    @property
    def discovered_endpoints(self) -> list[Endpoint]:
        return self._engine.discovered_endpoints

    def get_unspidered_endpoints(self) -> list[Endpoint]:
        return self._engine.get_unspidered_endpoints()

    def mark_spidered(self, url: str) -> None:
        self._engine.mark_spidered(url)

    # ── C. Attack surface ─────────────────────────────────────────────

    @property
    def attack_surface(self) -> AttackSurfaceStore:
        return self._engine.attack_surface

    # ── D. Storage ────────────────────────────────────────────────────

    @property
    def transaction_store(self) -> TransactionStore:
        return self._engine.transaction_store

    # ── E. Signals ────────────────────────────────────────────────────

    @property
    def signals(self) -> SignalBus:
        return self._engine.signals

    # ── F. Configuration (read-only) ──────────────────────────────────

    @property
    def config(self) -> CrawlConfig:
        return self._engine.config

    # ── G. Exploration ────────────────────────────────────────────────

    @property
    def coverage(self) -> CoverageBitmap:
        return self._engine.coverage

    @property
    def scheduler(self) -> SeedScheduler:
        return self._engine.scheduler

    @property
    def hindsight(self) -> HindsightFeedback:
        return self._engine.hindsight

    @property
    def template_inferrer(self) -> URLTemplateInferrer:
        return self._engine.template_inferrer

    # ── H. Sessions ───────────────────────────────────────────────────

    @property
    def sessions(self) -> SessionPool:
        return self._engine.sessions

    # ── I. Scope & Dedup ──────────────────────────────────────────────

    @property
    def scope(self) -> ScopeManager:
        return self._engine.scope

    @property
    def dedup(self) -> DeduplicationManager:
        return self._engine.dedup

    # ── J. Worker state (read-only) ───────────────────────────────────

    @property
    def requests_completed(self) -> int:
        return self._engine.requests_completed

    @property
    def requests_failed(self) -> int:
        return self._engine.requests_failed

    @property
    def elapsed(self) -> float:
        return self._engine.elapsed

    @property
    def is_queue_empty(self) -> bool:
        return self._engine.queue.empty

    @property
    def active_requests(self) -> int:
        return self._engine._active_requests

    @property
    def workers_done(self) -> bool:
        """True if all workers have finished."""
        return bool(self._engine._workers) and all(
            w.done() for w in self._engine._workers
        )
