"""CrawlEngine -- main orchestrator that ties everything together."""

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
from prowl.core.rate_limiter import DomainRateLimiter
from prowl.core.request_queue import RequestQueue
from prowl.core.scope import ScopeManager
from prowl.core.session_pool import SessionPool
from prowl.core.signals import Signal, SignalBus
from prowl.core.exploration import CoverageBitmap, HindsightFeedback, SeedScheduler, URLTemplateInferrer
from prowl.core.attack_surface import AttackSurfaceStore
from prowl.models.request import CrawlRequest, CrawlResponse, normalize_url
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
        self._active_requests = 0  # in-flight requests taken from queue

        # Approval guardrail (set externally via set_approval_manager)
        self._approval_manager: Any = None

        # BFS color tracking: URLs that the spider has fully processed
        # (links/forms extracted).  Anything in discovered_endpoints but NOT
        # in this set is "white" and eligible for a deep-crawl pass.
        self._spidered_urls: set[str] = set()

        # Transaction store for full HTTP traffic persistence
        self.transaction_store = TransactionStore(
            Path(config.output_dir) / "transactions.db"
        )

        # Attack surface store
        self.attack_surface = AttackSurfaceStore()

        # CDP metrics store (initialized only when cdp_profiling=True)
        self.cdp_store: Any = None

        # Exploration strategy components
        self.coverage = CoverageBitmap(
            saturation_window=config.saturation_window,
            saturation_threshold=config.saturation_threshold,
        )
        self.scheduler = SeedScheduler()
        self.hindsight = HindsightFeedback()
        self.template_inferrer = URLTemplateInferrer(scheduler=self.scheduler)

        # Response classifier for template mutation filtering (lazy-init)
        self._response_classifier: Any = None

        # Per-domain adaptive rate limiter (AIAD)
        self.rate_limiter = DomainRateLimiter(
            initial_delay=config.request_delay or 0.1,
            min_delay=0.01,
            max_delay=10.0,
        )

        # Stats
        self.start_time: float = 0.0
        self.requests_completed: int = 0
        self.requests_failed: int = 0
        self.endpoints_found: int = 0
        self.discovered_endpoints: list[Endpoint] = []
        self._registered_endpoint_keys: set[str] = set()

        # Guardrail skip counters
        self.requests_skipped_scope: int = 0
        self.requests_skipped_dedup: int = 0
        self.requests_skipped_approval: int = 0

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

        # Apply noise filter patterns to scope exclusions
        if self.config.noise_filter:
            from prowl.core.config import BUILTIN_NOISE_PATTERNS

            for pat in BUILTIN_NOISE_PATTERNS:
                self.scope.add_exclude_pattern(pat)
            logger.info("Noise filter: %d builtin patterns applied", len(BUILTIN_NOISE_PATTERNS))

        for pat in self.config.noise_patterns:
            self.scope.add_exclude_pattern(pat)
        if self.config.noise_patterns:
            logger.info("Noise filter: %d custom patterns applied", len(self.config.noise_patterns))

        # Apply auto-merge rules to queue
        for pattern, cap in self.config.auto_merge_rules.items():
            self.queue.add_auto_merge_rule(pattern, cap)

        # CDP profiling: attach instrumentor to browser backend
        if self.config.cdp_profiling:
            from prowl.backends.cdp_instrumentor import CDPInstrumentor
            from prowl.store.cdp_store import CDPMetricsStore

            self.cdp_store = CDPMetricsStore(
                Path(self.config.output_dir) / "cdp_metrics.db"
            )
            await self.cdp_store.initialize()

            instrumentor = CDPInstrumentor(
                collect_network=self.config.cdp_collect_network,
                collect_websockets=self.config.cdp_collect_websockets,
                collect_console=self.config.cdp_collect_console,
                max_network_entries=self.config.cdp_max_network_entries,
            )

            # Attach to browser backend (works for both browser and hybrid)
            if hasattr(self._backend, "set_instrumentor"):
                self._backend.set_instrumentor(instrumentor)
            elif hasattr(self._backend, "_browser"):
                self._backend._browser.set_instrumentor(instrumentor)

            logger.info("CDP profiling enabled")

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

        # Close CDP metrics store
        if self.cdp_store:
            await self.cdp_store.close()

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

        # Focus pattern boost
        if self.config.focus_patterns:
            for pat in self.config.focus_patterns:
                if pat in request.url:
                    request.priority += self.config.focus_boost
                    break

        added = await self.queue.put(request)
        if added:
            await self.signals.emit(Signal.REQUEST_QUEUED, request=request)
        return added

    async def execute(self, request: CrawlRequest) -> CrawlResponse:
        """Execute a single request through the backend.

        Guardrails are enforced here so that ALL callers (queue workers,
        bruteforce, param probing, auth crawl, etc.) go through scope,
        dedup, max-requests, and approval checks.  Requests that fail a
        check get a ``CrawlResponse`` with ``status_code=0`` and a
        descriptive ``page_type`` -- no HTTP request is made.
        """
        # --- Guardrails (enforced for ALL callers) -----------------------

        # 1. Scope check (silent skip)
        if not self.scope.is_in_scope(request.url):
            self.requests_skipped_scope += 1
            return CrawlResponse(
                request=request, status_code=0,
                page_type="out_of_scope",
            )

        # 2. Dedup check (skip for requests that already passed queue dedup)
        if not request.meta.get("_from_queue"):
            if await self.dedup.check_and_mark_url(request.fingerprint):
                self.requests_skipped_dedup += 1
                return CrawlResponse(
                    request=request, status_code=0,
                    page_type="duplicate",
                )

        # 3. Max requests hard limit
        if self.requests_completed + self.requests_failed >= self.config.max_requests:
            return CrawlResponse(
                request=request, status_code=0,
                page_type="max_requests",
            )

        # 4. Approval guardrail (park unsafe requests for user consent)
        if self._approval_manager is not None:
            from prowl.intervention.approval import ApprovalManager
            mgr: ApprovalManager = self._approval_manager
            if mgr.needs_approval(request, self.config.approve_unsafe):
                kind = mgr.classify(request)
                await mgr.submit(request, kind)
                self.requests_skipped_approval += 1
                return CrawlResponse(
                    request=request, status_code=0,
                    page_type="approval_pending",
                )

        # --- End guardrails -----------------------------------------------

        # Apply auth headers: use request's role, or fall back to "default" role
        role = request.auth_role or "default"
        auth_headers = await self.sessions.get_headers_for_role(role)
        if auth_headers:
            request.headers.update(auth_headers)

        await self.signals.emit(Signal.REQUEST_STARTED, request=request)
        response = await self._backend.execute(request)

        # CDP metrics: persist and emit signal
        if self.config.cdp_profiling and "cdp_metrics" in response.meta:
            cdp_m = response.meta.pop("cdp_metrics")
            await self.signals.emit(Signal.CDP_METRICS_COLLECTED, metrics=cdp_m)
            if self.cdp_store:
                await self.cdp_store.store(cdp_m)

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

        # Filter template mutation responses through classifier (soft-404 detection)
        if (":template_mutation" in request.source_module
                and response.is_success
                and self._response_classifier is not None):
            from prowl.core.response_classifier import ResponseClassifier
            classifier: ResponseClassifier = self._response_classifier
            await classifier.ensure_domain_baseline(request.url)
            page_type = classifier.classify(response)
            if page_type not in ("real_content", "auth_required"):
                self.requests_failed += 1
                return response

        # Classify all responses for page_type (soft-404, WAF, etc.)
        if self._response_classifier is not None and not response.page_type:
            response.page_type = self._response_classifier.classify(response)

        # Hindsight feedback for non-success responses
        if self.config.hindsight_feedback and not response.is_success:
            self.hindsight.analyze(
                url=request.url,
                method=request.method.upper(),
                status_code=response.status_code,
                headers=response.headers,
            )

        # Adaptive rate limiting: back off on 429, speed up on success
        if response.status_code == 429:
            await self.rate_limiter.on_rate_limited(request.url)
        elif response.status_code > 0:
            await self.rate_limiter.on_success(request.url)

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

    def set_approval_manager(self, manager: Any) -> None:
        """Attach an ApprovalManager for unsafe-method guardrail."""
        self._approval_manager = manager

    async def _worker(self, worker_id: int) -> None:
        """Worker loop: fetch from queue, execute, process response."""
        while self._state in (EngineState.RUNNING, EngineState.PAUSED):
            # Respect pause
            await self._pause_event.wait()

            try:
                request = await asyncio.wait_for(self.queue.get(), timeout=2.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            self._active_requests += 1
            try:
                # Mark as queue-sourced so execute() skips redundant dedup
                request.meta["_from_queue"] = True

                # Adaptive rate limiting (replaces static request_delay)
                await self.rate_limiter.wait(request.url)

                # Guardrails (scope, dedup, max_requests, approval) are
                # now enforced inside execute() for all callers.
                await self.execute(request)
            except (asyncio.CancelledError, KeyboardInterrupt):
                raise
            except Exception:
                logger.exception("Worker %d error processing %s", worker_id, request.url)
                # Retry once for transient errors (network, timeout)
                try:
                    await self.rate_limiter.wait(request.url)
                    await self.execute(request)
                except Exception:
                    logger.warning("Worker %d retry failed for %s", worker_id, request.url)
            finally:
                self._active_requests -= 1
                self.queue.task_done()

    async def register_endpoint(self, endpoint: Endpoint) -> None:
        """Register a newly discovered endpoint (deduped by method+URL)."""
        key = f"{endpoint.method.upper()}|{normalize_url(endpoint.url)}"
        if key in self._registered_endpoint_keys:
            # Merge tags from new source into existing endpoint
            for existing in self.discovered_endpoints:
                if f"{existing.method.upper()}|{normalize_url(existing.url)}" == key:
                    for tag in endpoint.tags:
                        if tag not in existing.tags:
                            existing.tags.append(tag)
                    break
            return
        self._registered_endpoint_keys.add(key)
        self.discovered_endpoints.append(endpoint)
        self.attack_surface.register_endpoint(endpoint)
        self.endpoints_found += 1
        await self.signals.emit(Signal.ENDPOINT_FOUND, endpoint=endpoint)

    def mark_spidered(self, url: str) -> None:
        """Mark a URL as fully crawled (black) -- links/forms extracted."""
        self._spidered_urls.add(normalize_url(url))

    def get_unspidered_endpoints(self) -> list[Endpoint]:
        """Return white endpoints: registered but never spider-crawled."""
        seen: set[str] = set()
        result: list[Endpoint] = []
        for ep in self.discovered_endpoints:
            norm = normalize_url(ep.url)
            if norm not in self._spidered_urls and norm not in seen:
                seen.add(norm)
                result.append(ep)
        return result

    def pause(self) -> None:
        """Pause all workers."""
        self._pause_event.clear()
        self._state = EngineState.PAUSED
        logger.info("Engine paused")
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.signals.emit(Signal.ENGINE_PAUSED))
        except RuntimeError:
            pass

    def resume(self) -> None:
        """Resume all workers."""
        self._pause_event.set()
        self._state = EngineState.RUNNING
        logger.info("Engine resumed")
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.signals.emit(Signal.ENGINE_RESUMED))
        except RuntimeError:
            pass

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
            "rate_limiter": self.rate_limiter.get_stats(),
            "skipped_scope": self.requests_skipped_scope,
            "skipped_dedup": self.requests_skipped_dedup,
            "skipped_approval": self.requests_skipped_approval,
        }
