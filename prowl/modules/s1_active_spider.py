"""§1 Active Spidering module."""

from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

from prowl.core.signals import Signal
from prowl.models.request import CrawlRequest, FormData, FormField, HttpMethod
from prowl.models.target import Endpoint, Parameter, ParameterLocation
from prowl.modules.base import BaseModule

# Safe default values for form auto-submission (discovery only, never attack payloads)
_SAFE_VALUES: dict[str, str] = {
    "q": "test", "query": "test", "search": "test", "keyword": "test",
    "s": "test", "term": "test",
    "sort": "name", "order": "asc", "orderby": "name",
    "page": "1", "p": "1", "offset": "0",
    "limit": "10", "per_page": "10", "count": "10",
    "filter": "all", "type": "all", "category": "all",
    "lang": "en", "locale": "en",
    "format": "json", "output": "json",
}

# Field names that indicate unsafe forms (login, payment, etc.)
_UNSAFE_FIELDS = frozenset({
    "password", "passwd", "pass", "pwd", "secret",
    "card", "credit_card", "cc_number", "cvv", "cvc", "expiry",
    "ssn", "social_security",
    "token", "csrf", "csrf_token", "_token",
})

# Field names that indicate search/filter forms
_SEARCH_FIELDS = frozenset({
    "q", "query", "search", "keyword", "s", "term", "find",
    "sort", "order", "orderby", "page", "p", "offset",
    "limit", "per_page", "filter", "type", "category",
    "lang", "locale", "format", "output", "min", "max",
    "from", "to", "start", "end", "date",
})

# Partial Order Reduction: collapse threshold for independent GET links
_POR_COLLAPSE_THRESHOLD = 5


class ActiveSpiderModule(BaseModule):
    """§1: Crawl the target by following links, submitting forms, extracting endpoints."""

    name = "s1_spider"
    description = "Active Spidering (BFS link-following, form interaction)"

    def __init__(self, engine: Any) -> None:
        super().__init__(engine)
        # Partial Order Reduction: track seen (depth, prefix) pairs
        self._por_seen_prefix: dict[tuple[int, str], bool] = {}

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        await self.engine.signals.emit(Signal.MODULE_STARTED, module=self.name)

        # Seed with target URL
        seed = CrawlRequest(
            url=self.engine.config.target_url,
            source_module=self.name,
            priority=10,
        )
        await self.engine.submit(seed)

        # Start workers to process queue
        await self.engine.run_workers()

        # Process responses as they come
        self.engine.signals.connect(Signal.REQUEST_COMPLETED, self._on_response)

        # Wait until queue is empty, max requests reached, or workers stopped
        try:
            while self._running:
                total = self.engine.requests_completed + self.engine.requests_failed
                # Stop if max requests reached
                if total >= self.engine.config.max_requests:
                    break
                # Stop if coverage saturated
                if (self.engine.config.saturation_detection
                        and self.engine.coverage.is_saturated):
                    self.logger.info(
                        "Coverage saturated (discovery rate %.1f%%), stopping",
                        self.engine.coverage.discovery_rate * 100,
                    )
                    break
                # Stop if all workers finished
                if self.engine._workers and all(w.done() for w in self.engine._workers):
                    break
                if self.engine.queue.empty and self.engine.requests_completed > 0:
                    # Give a moment for any pending items
                    import asyncio
                    await asyncio.sleep(1.0)
                    if self.engine.queue.empty:
                        break
                import asyncio
                await asyncio.sleep(0.5)
        finally:
            self._running = False
            self.engine.signals.disconnect(Signal.REQUEST_COMPLETED, self._on_response)
            await self.engine.signals.emit(
                Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats()
            )

    async def _on_response(self, **kwargs: Any) -> None:
        """Process a crawl response: extract and enqueue new URLs."""
        response = kwargs.get("response")
        if not response or not response.is_success:
            return

        request = response.request
        self.requests_made += 1

        # Register this URL as an endpoint
        endpoint = Endpoint(
            url=response.url_final or request.url,
            method=request.method.upper(),
            status_code=response.status_code,
            content_type=response.content_type,
            source_module=self.name,
            depth=request.depth,
        )

        # Extract query parameters
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(response.url_final or request.url)
        if parsed.query:
            for name, values in parse_qs(parsed.query).items():
                endpoint.parameters.append(
                    Parameter(
                        name=name,
                        location=ParameterLocation.QUERY,
                        sample_values=values[:3],
                        source_module=self.name,
                    )
                )

        await self.engine.register_endpoint(endpoint)
        self.endpoints_found += 1

        # Enqueue discovered links (with Partial Order Reduction)
        next_depth = request.depth + 1
        link_prefixes = Counter(
            "/".join(urlparse(link.url).path.split("/")[:2])
            for link in response.links
        )

        for link in response.links:
            prefix = "/".join(urlparse(link.url).path.split("/")[:2])
            # POR: if many independent GET links share a prefix at the same depth,
            # only the first representative gets full priority; rest get minimum.
            if link_prefixes[prefix] > _POR_COLLAPSE_THRESHOLD:
                por_key = (next_depth, prefix)
                if not self._por_seen_prefix.get(por_key):
                    self._por_seen_prefix[por_key] = True
                    priority = self.engine.scheduler.calculate_priority(
                        link.url, source_module=self.name, depth=next_depth,
                    )
                else:
                    priority = 1  # lowest — explored only if budget remains
            else:
                priority = max(0, 10 - request.depth)

            child = CrawlRequest(
                url=link.url,
                source_module=self.name,
                depth=next_depth,
                priority=priority,
            )
            await self.engine.submit(child)

        # Enqueue form targets (with smart form submission)
        for form in response.forms:
            if self.engine.config.smart_form_submission:
                form_type = self._classify_form(form)
                if form_type in ("search", "filter"):
                    filled_req = self._build_form_request(form, next_depth)
                    if filled_req:
                        await self.engine.submit(filled_req)
                # Always emit FORM_FOUND so other modules can handle unsafe forms
                await self.engine.signals.emit(
                    Signal.FORM_FOUND, form=form, form_type=form_type,
                )
            else:
                # Legacy: just visit form action URL
                form_request = CrawlRequest(
                    url=form.action,
                    method=form.method,
                    source_module=self.name,
                    depth=next_depth,
                    priority=8,
                )
                await self.engine.submit(form_request)
                await self.engine.signals.emit(Signal.FORM_FOUND, form=form)

        # Track JS files
        for js_url in response.js_files:
            await self.engine.signals.emit(Signal.JS_FILE_FOUND, url=js_url)

    # ── Smart Form Submission helpers ──

    @staticmethod
    def _classify_form(form: FormData) -> str:
        """Classify a form as search, filter, login, or unsafe.

        Returns:
            "search" | "filter" | "login" | "unsafe" | "unknown"
        """
        field_names = {f.name.lower() for f in form.fields}

        # Unsafe: password, payment, CSRF fields
        if field_names & _UNSAFE_FIELDS:
            if "password" in field_names or "passwd" in field_names:
                return "login"
            return "unsafe"

        # Search/filter: majority of fields are search-like
        search_overlap = field_names & _SEARCH_FIELDS
        if search_overlap:
            if any(n in field_names for n in ("q", "query", "search", "keyword", "s", "term")):
                return "search"
            return "filter"

        # GET forms without sensitive fields are generally safe for discovery
        if form.method == HttpMethod.GET:
            return "filter"

        return "unknown"

    @staticmethod
    def _build_form_request(form: FormData, depth: int) -> CrawlRequest | None:
        """Build a CrawlRequest with safe auto-filled values for a search/filter form."""
        filled: dict[str, str] = {}
        for field in form.fields:
            name_lower = field.name.lower()
            if name_lower in _SAFE_VALUES:
                filled[field.name] = _SAFE_VALUES[name_lower]
            elif field.value:
                filled[field.name] = field.value  # use default value if present
            else:
                filled[field.name] = "test"

        if form.method == HttpMethod.GET:
            # Append as query string
            sep = "&" if "?" in form.action else "?"
            url = form.action + sep + urlencode(filled)
            return CrawlRequest(
                url=url,
                method=HttpMethod.GET,
                source_module="s1_spider:form_submit",
                depth=depth,
                priority=8,
            )
        else:
            # POST with form-encoded body
            body = urlencode(filled).encode()
            return CrawlRequest(
                url=form.action,
                method=form.method,
                headers={"content-type": "application/x-www-form-urlencoded"},
                body=body,
                source_module="s1_spider:form_submit",
                depth=depth,
                priority=8,
            )
