"""§3 Parameter Discovery — multi-method, multi-content-type parameter probing.

Discovery Only: uses benign marker values (prowl_probe_xxxx), never attack payloads.
Four-phase discovery:
  A. Collect known params from stored traffic (zero requests)
  B. Hidden param probing across 5 locations (query, body-form, body-json, header, cookie)
  C. HTTP method probing per endpoint
  D. Content-Type acceptance probing
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from prowl.core.signals import Signal
from prowl.models.request import CrawlRequest, CrawlResponse, HttpMethod
from prowl.models.target import Endpoint, Parameter, ParameterLocation
from prowl.modules.base import BaseModule

# Benign marker value (never an attack payload)
_MARKER = "prowl_probe_7f3a"

# Default parameter wordlist
DEFAULT_PARAMS = [
    "id", "page", "q", "search", "query", "name", "user", "username",
    "email", "password", "token", "key", "api_key", "auth", "session",
    "callback", "redirect", "url", "next", "return", "file", "path",
    "dir", "action", "cmd", "command", "exec", "lang", "language",
    "template", "view", "type", "format", "sort", "order", "limit",
    "offset", "from", "to", "start", "end", "date", "filter",
    "category", "tag", "status", "role", "admin", "debug", "test",
    "mode", "config", "version", "v", "include", "require", "load",
    "read", "fetch", "download", "upload", "import", "export",
]

# HTTP methods to probe
_PROBE_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

# Content-Types to probe
_PROBE_CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "application/xml",
]


@dataclass
class BaselineResponse:
    """Baseline response for differential comparison."""

    status_code: int
    content_length: int
    content_hash: str
    header_keys: frozenset[str]
    word_count: int
    response_time_ms: float


class ParamDiscoveryModule(BaseModule):
    """§3: Multi-method parameter discovery with Content-Type variation.

    Discovery Only — no attack payloads, only benign marker values.
    """

    name = "s3_params"
    description = "Parameter Discovery (multi-method, multi-content-type)"

    def __init__(self, engine: Any) -> None:
        super().__init__(engine)
        self._known_params: dict[str, set[str]] = {}  # endpoint_url → {param_names}
        self._endpoint_profiles: dict[str, dict] = {}  # endpoint_url → profile data
        self._params_found: int = 0

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        await self.engine.signals.emit(Signal.MODULE_STARTED, module=self.name)

        try:
            # Phase A: Collect known params from existing traffic
            await self._collect_known_params()

            # Phase B: Hidden param probing
            await self._probe_hidden_params()

            # Phase C: HTTP method probing
            await self._probe_methods()

            # Phase D: Content-Type probing
            await self._probe_content_types()

        finally:
            self._running = False
            await self.engine.signals.emit(
                Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats()
            )

    def get_stats(self) -> dict[str, Any]:
        stats = super().get_stats()
        stats["params_found"] = self._params_found
        stats["known_params_collected"] = sum(len(v) for v in self._known_params.values())
        stats["endpoints_profiled"] = len(self._endpoint_profiles)
        return stats

    # ------------------------------------------------------------------
    # Phase A: Collect known params from stored traffic
    # ------------------------------------------------------------------

    async def _collect_known_params(self) -> None:
        """Extract params already visible in stored HTTP traffic — zero requests."""
        # From query strings in stored URLs
        urls = await self.engine.transaction_store.get_urls()
        for url in urls:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                params = parse_qs(parsed.query)
                if base_url not in self._known_params:
                    self._known_params[base_url] = set()
                self._known_params[base_url].update(params.keys())

        # From discovered endpoints' parameters
        for ep in self.engine.discovered_endpoints:
            if ep.parameters:
                if ep.url not in self._known_params:
                    self._known_params[ep.url] = set()
                for p in ep.parameters:
                    self._known_params[ep.url].add(p.name)

        total = sum(len(v) for v in self._known_params.values())
        self.logger.info("Phase A: collected %d known params from %d endpoints", total, len(self._known_params))

    # ------------------------------------------------------------------
    # Phase B: Hidden param probing
    # ------------------------------------------------------------------

    async def _probe_hidden_params(self) -> None:
        """Fuzz endpoints with param wordlist across multiple locations."""
        wordlist = self._load_wordlist()
        sem = asyncio.Semaphore(self.engine.config.bruteforce_threads)

        # Get endpoints worth probing
        endpoints = self._select_endpoints_for_probing()
        self.logger.info("Phase B: probing %d endpoints with %d params", len(endpoints), len(wordlist))

        tasks: list[asyncio.Task] = []
        for ep in endpoints:
            if not self._running:
                break
            tasks.append(asyncio.create_task(
                self._fuzz_endpoint_params(ep, wordlist, sem)
            ))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _fuzz_endpoint_params(
        self, endpoint: Endpoint, wordlist: list[str], sem: asyncio.Semaphore
    ) -> None:
        """Probe a single endpoint for hidden params across locations."""
        # Get baseline
        baseline = await self._get_baseline(endpoint.url)
        if not baseline:
            return

        # Skip params already known on this endpoint
        known = self._known_params.get(endpoint.url, set())

        for param_name in wordlist:
            if not self._running:
                return
            if param_name in known:
                continue

            async with sem:
                # Probe as query parameter
                await self._probe_single_param(
                    endpoint, param_name, ParameterLocation.QUERY, baseline
                )

    async def _probe_single_param(
        self,
        endpoint: Endpoint,
        param_name: str,
        location: ParameterLocation,
        baseline: BaselineResponse,
    ) -> None:
        """Send a single probe request and compare to baseline."""
        try:
            if location == ParameterLocation.QUERY:
                sep = "&" if "?" in endpoint.url else "?"
                test_url = f"{endpoint.url}{sep}{param_name}={_MARKER}"
                request = CrawlRequest(
                    url=test_url,
                    method=HttpMethod.GET,
                    source_module=self.name,
                    depth=endpoint.depth,
                )
            elif location == ParameterLocation.BODY:
                request = CrawlRequest(
                    url=endpoint.url,
                    method=HttpMethod.POST,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=f"{param_name}={_MARKER}".encode(),
                    source_module=self.name,
                    depth=endpoint.depth,
                )
            elif location == ParameterLocation.HEADER:
                request = CrawlRequest(
                    url=endpoint.url,
                    method=HttpMethod.GET,
                    headers={f"X-{param_name}": _MARKER},
                    source_module=self.name,
                    depth=endpoint.depth,
                )
            else:
                return

            response = await self.engine.execute(request)
            self.requests_made += 1

            is_diff, reason = self._is_different(response, baseline)
            if is_diff:
                param = Parameter(
                    name=param_name,
                    location=location,
                    sample_values=[_MARKER],
                    source_module=self.name,
                )
                await self.engine.signals.emit(
                    Signal.HIDDEN_PARAM_FOUND,
                    endpoint=endpoint,
                    parameter=param,
                    reason=reason,
                )
                self._params_found += 1
                self.logger.info(
                    "Hidden param: %s=%s on %s [%s] (%s)",
                    param_name, location, endpoint.url, reason,
                    endpoint.method,
                )

        except Exception:
            self.errors += 1

    # ------------------------------------------------------------------
    # Phase C: HTTP method probing
    # ------------------------------------------------------------------

    async def _probe_methods(self) -> None:
        """Test which HTTP methods each endpoint accepts."""
        sem = asyncio.Semaphore(self.engine.config.bruteforce_threads)
        endpoints = self._select_endpoints_for_probing()
        self.logger.info("Phase C: method probing on %d endpoints", len(endpoints))

        tasks: list[asyncio.Task] = []
        for ep in endpoints:
            if not self._running:
                break
            tasks.append(asyncio.create_task(self._probe_endpoint_methods(ep, sem)))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_endpoint_methods(
        self, endpoint: Endpoint, sem: asyncio.Semaphore
    ) -> None:
        """Probe all HTTP methods on a single endpoint."""
        accepted: list[str] = []
        allow_header = ""

        for method in _PROBE_METHODS:
            if not self._running:
                return

            async with sem:
                try:
                    request = CrawlRequest(
                        url=endpoint.url,
                        method=HttpMethod(method.lower()),
                        source_module=self.name,
                        depth=endpoint.depth,
                    )
                    response = await self.engine.execute(request)
                    self.requests_made += 1

                    # 405 = method not allowed, skip
                    if response.status_code != 405:
                        accepted.append(method)

                    # Capture Allow header from OPTIONS response
                    if method == "OPTIONS" and "allow" in response.headers:
                        allow_header = response.headers["allow"]

                    # Emit signal for newly discovered methods
                    if method != endpoint.method and response.status_code not in (404, 405, 501):
                        await self.engine.signals.emit(
                            Signal.METHOD_DISCOVERED,
                            endpoint=endpoint,
                            method=method,
                            status_code=response.status_code,
                        )

                except Exception:
                    self.errors += 1

        # Store profile
        profile = self._endpoint_profiles.setdefault(endpoint.url, {})
        profile["accepted_methods"] = accepted
        if allow_header:
            profile["allow_header"] = allow_header

    # ------------------------------------------------------------------
    # Phase D: Content-Type probing
    # ------------------------------------------------------------------

    async def _probe_content_types(self) -> None:
        """Test Content-Type acceptance on endpoints that accept POST."""
        sem = asyncio.Semaphore(self.engine.config.bruteforce_threads)

        # Only probe endpoints confirmed to accept POST
        post_endpoints = [
            ep for ep in self.engine.discovered_endpoints
            if self._endpoint_profiles.get(ep.url, {}).get("accepted_methods")
            and "POST" in self._endpoint_profiles[ep.url]["accepted_methods"]
        ]

        self.logger.info("Phase D: content-type probing on %d POST endpoints", len(post_endpoints))

        tasks: list[asyncio.Task] = []
        for ep in post_endpoints:
            if not self._running:
                break
            tasks.append(asyncio.create_task(self._probe_endpoint_ct(ep, sem)))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_endpoint_ct(
        self, endpoint: Endpoint, sem: asyncio.Semaphore
    ) -> None:
        """Probe content-type acceptance on a single endpoint."""
        accepted: list[str] = []

        for ct in _PROBE_CONTENT_TYPES:
            if not self._running:
                return

            async with sem:
                try:
                    # Send minimal body appropriate for content type
                    if ct == "application/json":
                        body = b'{"_prowl": "probe"}'
                    elif ct == "application/xml":
                        body = b"<prowl>probe</prowl>"
                    elif ct == "multipart/form-data":
                        # Skip multipart for now (boundary handling complexity)
                        continue
                    else:
                        body = b"_prowl=probe"

                    request = CrawlRequest(
                        url=endpoint.url,
                        method=HttpMethod.POST,
                        headers={"Content-Type": ct},
                        body=body,
                        source_module=self.name,
                        depth=endpoint.depth,
                    )
                    response = await self.engine.execute(request)
                    self.requests_made += 1

                    # 415 = Unsupported Media Type
                    if response.status_code != 415:
                        accepted.append(ct)
                        await self.engine.signals.emit(
                            Signal.CONTENT_TYPE_ACCEPTED,
                            endpoint=endpoint,
                            content_type=ct,
                            status_code=response.status_code,
                        )

                except Exception:
                    self.errors += 1

        profile = self._endpoint_profiles.setdefault(endpoint.url, {})
        profile["accepted_content_types"] = accepted

        # Parse CORS from any response
        cors_origins = profile.get("cors_allowed_origins", [])
        profile["cors_allowed_origins"] = cors_origins

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _get_baseline(self, url: str) -> BaselineResponse | None:
        """Get a baseline response for differential comparison."""
        try:
            request = CrawlRequest(
                url=url, method=HttpMethod.GET, source_module=self.name,
            )
            t0 = time.monotonic()
            response = await self.engine.execute(request)
            elapsed = (time.monotonic() - t0) * 1000
            self.requests_made += 1

            body_text = response.body.decode("utf-8", errors="replace")
            return BaselineResponse(
                status_code=response.status_code,
                content_length=len(response.body),
                content_hash=hashlib.sha256(response.body).hexdigest()[:16],
                header_keys=frozenset(k.lower() for k in response.headers),
                word_count=len(body_text.split()),
                response_time_ms=elapsed,
            )
        except Exception:
            self.errors += 1
            return None

    def _is_different(
        self, response: CrawlResponse, baseline: BaselineResponse
    ) -> tuple[bool, str]:
        """Multi-signal differential comparison. Returns (is_different, reason)."""
        # Status code change
        status_bucket = response.status_code // 100
        baseline_bucket = baseline.status_code // 100
        if status_bucket != baseline_bucket:
            return True, f"status_{baseline.status_code}_to_{response.status_code}"

        # Content hash identical = definitely same
        resp_hash = hashlib.sha256(response.body).hexdigest()[:16]
        if resp_hash == baseline.content_hash:
            return False, ""

        # Content length significant change (>5% AND >50 bytes)
        length_diff = abs(len(response.body) - baseline.content_length)
        if length_diff > max(baseline.content_length * 0.05, 50):
            return True, f"length_diff_{length_diff}"

        # Word count change (>3 words)
        body_text = response.body.decode("utf-8", errors="replace")
        word_diff = abs(len(body_text.split()) - baseline.word_count)
        if word_diff > 3:
            return True, f"word_diff_{word_diff}"

        # New response headers appeared
        resp_headers = frozenset(k.lower() for k in response.headers)
        new_headers = resp_headers - baseline.header_keys
        # Filter out noise headers
        noise = {"date", "age", "x-request-id", "x-trace-id", "cf-ray"}
        new_headers -= noise
        if new_headers:
            return True, f"new_headers_{','.join(sorted(new_headers))}"

        return False, ""

    def _select_endpoints_for_probing(self) -> list[Endpoint]:
        """Select endpoints worth probing (2xx/3xx, not static assets)."""
        endpoints = [
            ep for ep in self.engine.discovered_endpoints
            if ep.status_code
            and ep.status_code < 400
            and not any(ep.url.endswith(ext) for ext in (".css", ".js", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico"))
        ]
        # Limit to configured max
        max_ep = getattr(self.engine.config, "param_max_endpoints", 100)
        return endpoints[:max_ep]

    def _load_wordlist(self) -> list[str]:
        """Load parameter wordlist from config or use default."""
        if self.engine.config.wordlist_params:
            path = Path(self.engine.config.wordlist_params)
            if path.is_file():
                return [
                    line.strip()
                    for line in path.read_text().splitlines()
                    if line.strip() and not line.startswith("#")
                ]
        return DEFAULT_PARAMS
