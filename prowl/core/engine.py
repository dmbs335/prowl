"""CrawlEngine — main orchestrator that ties everything together."""

from __future__ import annotations

import asyncio
import logging
import time
from enum import auto

from prowl._compat import StrEnum
from pathlib import Path
from typing import Any

from prowl.core.config import CrawlConfig
from prowl.core.dedup import DeduplicationManager
from prowl.core.request_queue import RequestQueue
from prowl.core.scope import ScopeManager
from prowl.core.session_pool import SessionPool
from prowl.core.signals import Signal, SignalBus
from prowl.core.exploration import CoverageBitmap, HindsightFeedback, SeedScheduler, URLTemplateInferrer
from prowl.core.attack_surface import AttackSurfaceStore
from prowl.models.request import CrawlRequest, CrawlResponse
from prowl.models.target import Endpoint
from prowl.store.transaction_store import HttpTransaction, TransactionStore

logger = logging.getLogger(__name__)


class EngineState(StrEnum):
    IDLE = auto()
    RUNNING = auto()
    PAUSED = auto()
    STOPPING = auto()
    STOPPED = auto()


class CrawlEngine:
    """Central engine that coordinates backends, modules, and the request queue."""

    def __init__(self, config: CrawlConfig) -> None:
        self.config = config
        self.signals = SignalBus()
        self.dedup = DeduplicationManager()
        self.queue = RequestQueue(self.dedup)
        self.scope = ScopeManager(
            config.target_url,
            include_patterns=config.scope_patterns or None,
            exclude_patterns=config.exclude_patterns or None,
        )
        self.sessions = SessionPool()

        self._state = EngineState.IDLE
        self._backend: Any = None
        self._workers: list[asyncio.Task] = []
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # Not paused by default

        # Transaction store for full HTTP traffic persistence
        self.transaction_store = TransactionStore(
            Path(config.output_dir) / "transactions.db"
        )

        # Attack surface store
        self.attack_surface = AttackSurfaceStore()

        # Exploration strategy components
        self.coverage = CoverageBitmap(
            saturation_window=config.saturation_window,
            saturation_threshold=config.saturation_threshold,
        )
        self.scheduler = SeedScheduler()
        self.hindsight = HindsightFeedback()
        self.template_inferrer = URLTemplateInferrer(scheduler=self.scheduler)

        # Stats
        self.start_time: float = 0.0
        self.requests_completed: int = 0
        self.requests_failed: int = 0
        self.endpoints_found: int = 0
        self.discovered_endpoints: list[Endpoint] = []

    @property
    def state(self) -> EngineState:
        return self._state

    @property
    def elapsed(self) -> float:
        if self.start_time == 0:
            return 0.0
        return time.time() - self.start_time

    async def startup(self) -> None:
        """Initialize the backend based on config."""
        backend_type = self.config.backend.lower()

        if backend_type == "http":
            from prowl.backends.http_backend import HttpBackend

            self._backend = HttpBackend(
                timeout=self.config.request_timeout,
                follow_redirects=self.config.follow_redirects,
                user_agent=self.config.user_agent,
                concurrency=self.config.concurrency,
            )
        elif backend_type == "browser":
            from prowl.backends.browser_backend import BrowserBackend

            self._backend = BrowserBackend(
                headless=self.config.headless,
                timeout=self.config.request_timeout,
                user_agent=self.config.user_agent,
            )
        else:
            from prowl.backends.hybrid_backend import HybridBackend

            self._backend = HybridBackend(
                timeout=self.config.request_timeout,
                follow_redirects=self.config.follow_redirects,
                user_agent=self.config.user_agent,
                concurrency=self.config.concurrency,
                headless=self.config.headless,
            )

        await self._backend.startup()

        # Initialize transaction store and wire auto-persist handler
        await self.transaction_store.initialize()
        self.signals.connect(Signal.REQUEST_COMPLETED, self._persist_transaction)

        self._state = EngineState.IDLE
        logger.info("Engine started with %s backend", backend_type)

    async def shutdown(self) -> None:
        """Stop workers and close backend."""
        self._state = EngineState.STOPPING
        for worker in self._workers:
            worker.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

        if self._backend:
            await self._backend.shutdown()

        # Flush and close transaction store
        await self.transaction_store.close()

        self._state = EngineState.STOPPED
        await self.signals.emit(Signal.ENGINE_STOPPED)

    async def submit(self, request: CrawlRequest) -> bool:
        """Submit a request to the queue (checks scope + dedup)."""
        if not self.scope.is_in_scope(request.url):
            return False
        if request.depth > self.config.max_depth:
            return False

        # Seed scheduling: auto-assign priority if not already set
        if self.config.seed_scheduling and request.priority == 0:
            request.priority = self.scheduler.calculate_priority(
                request.url,
                source_module=request.source_module,
                depth=request.depth,
            )

        added = await self.queue.put(request)
        if added:
            await self.signals.emit(Signal.REQUEST_QUEUED, request=request)
        return added

    async def execute(self, request: CrawlRequest) -> CrawlResponse:
        """Execute a single request through the backend."""
        # Apply auth headers if role specified
        if request.auth_role:
            auth_headers = self.sessions.get_headers_for_role(request.auth_role)
            request.headers.update(auth_headers)

        await self.signals.emit(Signal.REQUEST_STARTED, request=request)
        response = await self._backend.execute(request)

        # Coverage tracking
        if self.config.coverage_guided:
            is_new = self.coverage.is_interesting(
                url=response.url_final or request.url,
                method=request.method.upper(),
                status_code=response.status_code,
                body=response.body,
                content_type=response.content_type,
                auth_role=request.auth_role,
            )
            self.scheduler.record_coverage_hit(request.url, is_new)

            # URL template inference: observe interesting URLs and queue mutations
            if is_new and self.config.url_template_inference and response.is_success:
                final_url = response.url_final or request.url
                template = self.template_inferrer.observe(final_url)
                if template:
                    for mutation_path in self.template_inferrer.generate_mutations(template):
                        # Build full URL from mutation path
                        from urllib.parse import urlparse, urlunparse
                        parsed = urlparse(final_url)
                        mut_url = urlunparse((parsed.scheme, parsed.netloc, mutation_path, "", "", ""))
                        mut_req = CrawlRequest(
                            url=mut_url,
                            method=request.method,
                            source_module=f"{request.source_module}:template_mutation",
                            depth=request.depth,
                        )
                        await self.submit(mut_req)

        # Hindsight feedback for non-success responses
        if self.config.hindsight_feedback and not response.is_success:
            self.hindsight.analyze(
                url=request.url,
                method=request.method.upper(),
                status_code=response.status_code,
                headers=response.headers,
            )

        if response.is_success:
            self.requests_completed += 1
        else:
            self.requests_failed += 1

        # Always emit REQUEST_COMPLETED for transaction persistence and analysis.
        # Non-success responses (4xx, 5xx) are valuable for auth boundary and
        # hindsight analysis.
        await self.signals.emit(Signal.REQUEST_COMPLETED, response=response)

        if not response.is_success:
            await self.signals.emit(
                Signal.REQUEST_FAILED, request=request, response=response
            )

        return response

    async def run_workers(self, num_workers: int | None = None) -> None:
        """Start concurrent workers to process the request queue."""
        self._state = EngineState.RUNNING
        self.start_time = time.time()
        await self.signals.emit(Signal.ENGINE_STARTED)

        n = num_workers or self.config.concurrency
        self._workers = [
            asyncio.create_task(self._worker(i)) for i in range(n)
        ]

    async def _worker(self, worker_id: int) -> None:
        """Worker loop: fetch from queue, execute, process response."""
        while self._state == EngineState.RUNNING:
            # Respect pause
            await self._pause_event.wait()

            try:
                request = await asyncio.wait_for(self.queue.get(), timeout=2.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            try:
                if self.requests_completed + self.requests_failed >= self.config.max_requests:
                    break

                if self.config.request_delay > 0:
                    await asyncio.sleep(self.config.request_delay)

                await self.execute(request)
            except Exception:
                logger.exception("Worker %d error processing %s", worker_id, request.url)
            finally:
                self.queue.task_done()

    async def register_endpoint(self, endpoint: Endpoint) -> None:
        """Register a newly discovered endpoint."""
        self.discovered_endpoints.append(endpoint)
        self.attack_surface.register_endpoint(endpoint)
        self.endpoints_found += 1
        await self.signals.emit(Signal.ENDPOINT_FOUND, endpoint=endpoint)

    def pause(self) -> None:
        """Pause all workers."""
        self._pause_event.clear()
        self._state = EngineState.PAUSED
        logger.info("Engine paused")

    def resume(self) -> None:
        """Resume all workers."""
        self._pause_event.set()
        self._state = EngineState.RUNNING
        logger.info("Engine resumed")

    async def stop(self) -> None:
        """Gracefully stop the engine."""
        await self.shutdown()

    async def _persist_transaction(self, response: CrawlResponse, **_: Any) -> None:
        """Signal handler: persist every completed request/response pair."""
        txn = HttpTransaction(
            request_method=response.request.method.upper(),
            request_url=response.request.url,
            request_headers=response.request.headers,
            request_body=response.request.body,
            request_content_type=response.request.headers.get("content-type", ""),
            response_status=response.status_code,
            response_headers=response.headers,
            response_body=response.body,
            response_content_type=response.content_type,
            response_url_final=response.url_final or response.request.url,
            source_module=response.request.source_module,
            depth=response.request.depth,
            page_type=response.page_type,
            content_hash=response.content_hash,
        )
        await self.transaction_store.store(txn)

    def get_stats(self) -> dict[str, Any]:
        """Return current engine statistics."""
        return {
            "state": self._state,
            "elapsed": self.elapsed,
            "requests_completed": self.requests_completed,
            "requests_failed": self.requests_failed,
            "requests_queued": self.queue.total_queued,
            "requests_dropped": self.queue.total_dropped,
            "queue_size": self.queue.qsize,
            "endpoints_found": self.endpoints_found,
            "unique_urls": self.dedup.url_count,
            "transactions_stored": self.transaction_store.total_stored,
            "coverage": self.coverage.get_stats(),
            "hindsight": self.hindsight.get_stats(),
        }
