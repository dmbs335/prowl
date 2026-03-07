"""Post-crawl CDP security intelligence analysis.

Reads stored CDP metrics, identifies hidden API endpoints not found by
other modules, flags console-leaked sensitive info, audits security
headers, and feeds newly discovered endpoints back into the attack surface.
No additional HTTP requests are made.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from prowl.core.signals import Signal
from prowl.models.cdp_metrics import CDPCrawlSummary, PageCDPMetrics
from prowl.modules.base import BaseModule

logger = logging.getLogger(__name__)

# Patterns in console messages that may indicate sensitive info leaks
_SENSITIVE_PATTERNS = [
    re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"(?:token|bearer)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"(?:secret|password|passwd)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"https?://[^\s\"'<>]+/api/", re.IGNORECASE),
    re.compile(r"https?://[^\s\"'<>]+/graphql", re.IGNORECASE),
    re.compile(r"https?://[^\s\"'<>]+/v\d+/", re.IGNORECASE),
    re.compile(r"wss?://[^\s\"'<>]+", re.IGNORECASE),
    re.compile(r"(?:internal|staging|dev)\.\w+\.\w+", re.IGNORECASE),
]


class CDPAnalysisModule(BaseModule):
    """Security analysis of collected CDP intelligence."""

    name = "s14_cdp"
    description = "CDP security intelligence - hidden APIs, console leaks, header audit"

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        await self.engine.signals.emit(Signal.MODULE_STARTED, module=self.name)

        if not self.engine.cdp_store:
            self.logger.info("CDP profiling disabled, skipping analysis")
            self._running = False
            return

        # Read all stored metrics
        metrics_list: list[PageCDPMetrics] = []
        async for m in self.engine.cdp_store.get_all():
            metrics_list.append(m)

        if not metrics_list:
            self.logger.info("No CDP metrics collected")
            self._running = False
            await self.engine.signals.emit(
                Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats()
            )
            return

        # Compute security-focused aggregates
        summary = self.compute_summary(metrics_list)

        # Feed discovered API endpoints back into attack surface
        await self._register_discovered_endpoints(summary)

        # Emit signal with summary
        await self.engine.signals.emit(
            Signal.CDP_ANALYSIS_COMPLETE, summary=summary
        )

        self.logger.info(
            "CDP analysis: %d pages, %d API endpoints, %d WS endpoints, "
            "%d console leaks, %d header issues",
            summary.total_pages_profiled,
            len(summary.discovered_api_endpoints),
            len(summary.ws_endpoints),
            len(summary.interesting_console_messages),
            len(summary.security_header_issues),
        )

        self._running = False
        await self.engine.signals.emit(
            Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats()
        )

    def compute_summary(self, metrics: list[PageCDPMetrics]) -> CDPCrawlSummary:
        """Aggregate per-page security intelligence into crawl-wide summary."""
        summary = CDPCrawlSummary(total_pages_profiled=len(metrics))

        seen_api_urls: set[str] = set()
        seen_ws_urls: set[str] = set()
        seen_third_party: set[str] = set()
        all_redirect_targets: set[str] = set()

        for m in metrics:
            summary.total_sub_requests += m.total_requests

            # Collect unique API endpoints
            for api in m.api_calls:
                api_key = f"{api.method}|{api.url}"
                if api_key not in seen_api_urls:
                    seen_api_urls.add(api_key)
                    summary.discovered_api_endpoints.append({
                        "url": api.url,
                        "method": api.method,
                        "resource_type": api.resource_type,
                        "mime_type": api.mime_type,
                        "initiator_url": api.initiator_url,
                        "status_code": api.status_code,
                        "found_on": m.request_url,
                    })
            summary.total_api_calls += len(m.api_calls)

            # WebSocket endpoints
            for ws in m.websocket_sessions:
                if ws.url and ws.url not in seen_ws_urls:
                    seen_ws_urls.add(ws.url)
                    summary.ws_endpoints.append(ws.url)

            # Console leak analysis
            for msg in m.console_messages + m.js_errors:
                for pattern in _SENSITIVE_PATTERNS:
                    if pattern.search(msg.text):
                        summary.interesting_console_messages.append({
                            "level": msg.level,
                            "text": msg.text[:500],
                            "url": msg.url,
                            "line": msg.line,
                            "found_on": m.request_url,
                            "pattern": pattern.pattern[:60],
                        })
                        break

            summary.total_js_errors += len(m.js_errors)

            # Security header audit
            self._audit_security_headers(summary, m)

            # Third-party domains
            for req in m.discovered_requests:
                if req.is_third_party and req.url:
                    try:
                        host = urlparse(req.url).netloc
                        if host and host not in seen_third_party:
                            seen_third_party.add(host)
                    except Exception:
                        pass

            # Redirect chain targets
            for redirect_url in m.redirect_chain:
                all_redirect_targets.add(redirect_url)

        summary.third_party_domains = sorted(seen_third_party)
        summary.redirect_targets = sorted(all_redirect_targets)

        return summary

    def _audit_security_headers(
        self, summary: CDPCrawlSummary, m: PageCDPMetrics
    ) -> None:
        """Check security headers for misconfigurations."""
        h = m.security_headers

        # No CSP
        if not h.csp and not h.csp_report_only:
            summary.pages_without_csp += 1

        # No HSTS
        if not h.strict_transport_security:
            summary.pages_without_hsts += 1

        # Permissive CORS
        if h.cors_allow_origin == "*":
            summary.pages_with_permissive_cors += 1
            summary.security_header_issues.append({
                "url": m.request_url,
                "issue": "CORS wildcard: Access-Control-Allow-Origin: *",
                "severity": "medium",
            })

        # CORS with credentials + wildcard (critical misconfiguration)
        if (
            h.cors_allow_origin == "*"
            and h.cors_allow_credentials.lower() == "true"
        ):
            summary.security_header_issues.append({
                "url": m.request_url,
                "issue": "CORS wildcard with credentials (browser ignores, but server misconfigured)",
                "severity": "high",
            })

        # No X-Frame-Options and no frame-ancestors in CSP
        if not h.x_frame_options and "frame-ancestors" not in h.csp:
            summary.security_header_issues.append({
                "url": m.request_url,
                "issue": "No clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
                "severity": "low",
            })

        # No X-Content-Type-Options
        if not h.x_content_type_options:
            summary.security_header_issues.append({
                "url": m.request_url,
                "issue": "Missing X-Content-Type-Options: nosniff",
                "severity": "low",
            })

    async def _register_discovered_endpoints(
        self, summary: CDPCrawlSummary
    ) -> None:
        """Feed CDP-discovered API endpoints back into the engine's attack surface."""
        from prowl.models.target import Endpoint

        registered = 0
        for api in summary.discovered_api_endpoints:
            url = api.get("url", "")
            if not url or not self.engine.scope.is_in_scope(url):
                continue

            ep = Endpoint(
                url=url,
                method=api.get("method", "GET"),
                source="cdp_analysis",
                tags=["cdp-discovered", f"type:{api.get('resource_type', '')}"],
            )
            await self.engine.register_endpoint(ep)
            registered += 1

        # Also register WebSocket endpoints
        for ws_url in summary.ws_endpoints:
            if not self.engine.scope.is_in_scope(ws_url):
                continue
            ep = Endpoint(
                url=ws_url,
                method="WEBSOCKET",
                source="cdp_analysis",
                tags=["cdp-discovered", "websocket"],
            )
            await self.engine.register_endpoint(ep)
            registered += 1

        summary.unique_cdp_endpoints = registered
        self.endpoints_found = registered
        self.logger.info(
            "CDP registered %d new endpoints into attack surface", registered
        )
