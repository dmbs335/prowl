"""§4 JavaScript Analysis module."""

from __future__ import annotations

import re
from typing import Any

import httpx

from prowl.core.signals import Signal
from prowl.models.target import Endpoint, Parameter, ParameterLocation, Secret
from prowl.modules.base import BaseModule

# Regex patterns for JS analysis
ENDPOINT_PATTERNS = [
    re.compile(r"""['"`](/api/[a-zA-Z0-9_/\-{}:.]+)['"`]"""),
    re.compile(r"""['"`](/v[0-9]+/[a-zA-Z0-9_/\-{}:.]+)['"`]"""),
    re.compile(r"""fetch\s*\(\s*['"`](https?://[^'"`\s]+)['"`]"""),
    re.compile(r"""axios\.[a-z]+\s*\(\s*['"`](https?://[^'"`\s]+|/[^'"`\s]+)['"`]"""),
    re.compile(r"""\.open\s*\(\s*['"`][A-Z]+['"`]\s*,\s*['"`](https?://[^'"`\s]+|/[^'"`\s]+)['"`]"""),
    re.compile(r"""url:\s*['"`](https?://[^'"`\s]+|/[^'"`\s]+)['"`]"""),
    re.compile(r"""path:\s*['"`](/[a-zA-Z0-9_/\-{}:.]+)['"`]"""),
    re.compile(r"""endpoint:\s*['"`](https?://[^'"`\s]+|/[^'"`\s]+)['"`]"""),
]

SECRET_PATTERNS = [
    (re.compile(r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})['"`]""", re.I), "api_key"),
    (re.compile(r"""(?:secret|token|auth)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})['"`]""", re.I), "secret_token"),
    (re.compile(r"""(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*['"`](AKIA[A-Z0-9]{16})['"`]""", re.I), "aws_key"),
    (re.compile(r"""(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`]{8,})['"`]""", re.I), "password"),
    (re.compile(r"""(?:firebase|supabase)[a-zA-Z]*\s*[:=]\s*['"`](https?://[^'"`\s]+)['"`]""", re.I), "service_url"),
    (re.compile(r"""eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"""), "jwt_token"),
]

ROUTE_PATTERNS = [
    # React Router
    re.compile(r"""<Route\s+[^>]*path\s*=\s*['"`]([^'"`]+)['"`]"""),
    # Vue Router
    re.compile(r"""path:\s*['"`](/[^'"`]*)['"`]"""),
    # Angular
    re.compile(r"""path:\s*'([^']*)'"""),
    # Next.js
    re.compile(r"""router\.push\s*\(\s*['"`](/[^'"`]+)['"`]"""),
]


class JSAnalysisModule(BaseModule):
    """§4: Analyze JavaScript files for endpoints, secrets, and routes."""

    name = "s4_js"
    description = "JavaScript Analysis (endpoint extraction, secret detection, route mapping)"

    def __init__(self, engine: Any) -> None:
        super().__init__(engine)
        self._analyzed_urls: set[str] = set()

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        await self.engine.signals.emit(Signal.MODULE_STARTED, module=self.name)

        # Collect JS file URLs from previously discovered endpoints
        js_urls: set[str] = set()

        # Listen for JS file signals from spider
        async def on_js_found(**kw: Any) -> None:
            url = kw.get("url", "")
            if url:
                js_urls.add(url)

        self.engine.signals.connect(Signal.JS_FILE_FOUND, on_js_found)

        # Also scan known endpoints' JS files
        for ep in self.engine.discovered_endpoints:
            if ep.url.endswith(".js") or ".js?" in ep.url:
                js_urls.add(ep.url)

        try:
            for url in js_urls:
                if not self._running:
                    break
                if url in self._analyzed_urls:
                    continue
                await self._analyze_js_file(url)
                self._analyzed_urls.add(url)
        finally:
            self._running = False
            self.engine.signals.disconnect(Signal.JS_FILE_FOUND, on_js_found)
            await self.engine.signals.emit(
                Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats()
            )

    async def _analyze_js_file(self, url: str) -> None:
        """Download and analyze a single JS file."""
        self.logger.info("Analyzing: %s", url)

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(url)
                self.requests_made += 1

                if resp.status_code != 200:
                    return

                # Size check
                if len(resp.content) > self.engine.config.js_max_file_size:
                    self.logger.warning("Skipping large JS file: %s (%d bytes)", url, len(resp.content))
                    return

                content = resp.text
                await self._extract_endpoints(content, url)
                await self._extract_secrets(content, url)
                await self._extract_routes(content, url)

            except Exception as e:
                self.errors += 1
                self.logger.warning("Failed to analyze %s: %s", url, e)

    async def _extract_endpoints(self, content: str, source_url: str) -> None:
        """Extract API endpoints from JS content."""
        from urllib.parse import urljoin

        found: set[str] = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(content):
                path = match.group(1)
                if path in found:
                    continue
                found.add(path)

                # Resolve relative paths
                if path.startswith("/"):
                    full_url = urljoin(self.engine.config.target_url, path)
                elif path.startswith("http"):
                    full_url = path
                else:
                    continue

                endpoint = Endpoint(
                    url=full_url,
                    source_module=self.name,
                    tags=["js_extracted"],
                )
                await self.engine.register_endpoint(endpoint)
                self.endpoints_found += 1

    async def _extract_secrets(self, content: str, source_url: str) -> None:
        """Extract secrets/credentials from JS content."""
        for pattern, kind in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
                secret = Secret(
                    kind=kind,
                    value=value[:200],
                    source_url=source_url,
                )
                await self.engine.signals.emit(Signal.SECRET_FOUND, secret=secret)
                self.logger.warning("Secret found [%s] in %s", kind, source_url)

    async def _extract_routes(self, content: str, source_url: str) -> None:
        """Extract client-side routes from JS frameworks."""
        from urllib.parse import urljoin

        found: set[str] = set()
        for pattern in ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                path = match.group(1)
                if path in found or not path.startswith("/"):
                    continue
                found.add(path)

                full_url = urljoin(self.engine.config.target_url, path)
                endpoint = Endpoint(
                    url=full_url,
                    source_module=self.name,
                    tags=["js_route"],
                )
                await self.engine.register_endpoint(endpoint)
                self.endpoints_found += 1
