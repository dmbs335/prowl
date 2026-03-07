"""CDP-based security intelligence for Playwright pages.

Attaches to a Playwright page via CDPSession to capture network requests,
WebSocket connections, console output, and security headers that are
invisible to standard Playwright APIs.  Focused on attack surface discovery.

Bracket pattern:
    attach(page)   -- before navigation
    [navigation]
    collect()      -- after navigation + networkidle
    detach()       -- in finally block
"""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlparse

from prowl.models.cdp_metrics import (
    ConsoleMessage,
    DiscoveredRequest,
    PageCDPMetrics,
    SecurityHeaders,
    WebSocketSession,
)

logger = logging.getLogger(__name__)

# Resource types that indicate API calls
_API_RESOURCE_TYPES = {"XHR", "Fetch"}

# MIME types that indicate API responses
_API_MIME_TYPES = {
    "application/json",
    "application/graphql+json",
    "application/graphql-response+json",
    "application/x-ndjson",
    "text/event-stream",
}

# Security-relevant response header names (lowercase)
_SECURITY_HEADER_NAMES = {
    "content-security-policy",
    "content-security-policy-report-only",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
}


class CDPInstrumentor:
    """Collects per-page security intelligence via Chrome DevTools Protocol."""

    def __init__(
        self,
        *,
        collect_network: bool = True,
        collect_websockets: bool = True,
        collect_console: bool = True,
        max_network_entries: int = 500,
    ) -> None:
        self._collect_network = collect_network
        self._collect_websockets = collect_websockets
        self._collect_console = collect_console
        self._max_network_entries = max_network_entries

        # Per-page state (reset on each attach)
        self._cdp: Any = None
        self._attached = False
        self._nav_start: float = 0.0
        self._target_origin: str = ""

        # Network event accumulators
        self._requests: dict[str, dict[str, Any]] = {}
        self._loading: dict[str, dict[str, Any]] = {}
        self._redirect_chain: list[str] = []
        self._main_doc_headers: dict[str, str] = {}

        # WebSocket accumulators
        self._ws_sessions: dict[str, WebSocketSession] = {}

        # Console accumulators
        self._console_messages: list[ConsoleMessage] = []
        self._js_errors: list[ConsoleMessage] = []

    async def attach(self, page: Any) -> None:
        """Create CDP session and enable domains before navigation."""
        try:
            self._cdp = await page.context.new_cdp_session(page)
        except Exception as e:
            logger.debug("Failed to create CDP session: %s", e)
            return

        # Determine target origin for third-party classification
        try:
            parsed = urlparse(page.url if page.url != "about:blank" else "")
            self._target_origin = parsed.netloc
        except Exception:
            pass

        try:
            # Enable Network domain for request/response/WebSocket capture
            if self._collect_network or self._collect_websockets:
                await self._cdp.send("Network.enable")

                if self._collect_network:
                    self._cdp.on(
                        "Network.requestWillBeSent",
                        self._on_request_will_be_sent,
                    )
                    self._cdp.on(
                        "Network.responseReceived", self._on_response_received
                    )
                    self._cdp.on(
                        "Network.loadingFinished", self._on_loading_finished
                    )

                if self._collect_websockets:
                    self._cdp.on(
                        "Network.webSocketCreated", self._on_ws_created
                    )
                    self._cdp.on(
                        "Network.webSocketFrameSent", self._on_ws_frame_sent
                    )
                    self._cdp.on(
                        "Network.webSocketFrameReceived",
                        self._on_ws_frame_received,
                    )

            # Enable Runtime domain for console output capture
            if self._collect_console:
                await self._cdp.send("Runtime.enable")
                self._cdp.on(
                    "Runtime.consoleAPICalled", self._on_console_api_called
                )
                self._cdp.on(
                    "Runtime.exceptionThrown", self._on_exception_thrown
                )

            self._nav_start = time.time()
            self._attached = True

        except Exception as e:
            logger.debug("CDP domain enable failed: %s", e)
            await self._safe_detach()

    async def collect(self) -> PageCDPMetrics:
        """Collect all accumulated security intelligence after navigation."""
        if not self._attached or not self._cdp:
            return PageCDPMetrics()

        nav_duration = (time.time() - self._nav_start) * 1000

        # Build discovered requests and classify
        discovered: list[DiscoveredRequest] = []
        api_calls: list[DiscoveredRequest] = []
        third_party_count = 0

        if self._collect_network:
            for req_id, req_data in list(self._requests.items()):
                if len(discovered) >= self._max_network_entries:
                    break

                entry = self._build_discovered_request(req_id, req_data)
                discovered.append(entry)

                if entry.is_api_call:
                    api_calls.append(entry)
                if entry.is_third_party:
                    third_party_count += 1

        # Extract security headers from main document response
        security_headers = self._extract_security_headers()

        # WebSocket sessions
        ws_sessions: list[WebSocketSession] = []
        if self._collect_websockets:
            ws_sessions = list(self._ws_sessions.values())

        return PageCDPMetrics(
            discovered_requests=discovered,
            api_calls=api_calls,
            total_requests=len(self._requests),
            third_party_requests=third_party_count,
            websocket_sessions=ws_sessions,
            console_messages=self._console_messages[:200],
            js_errors=self._js_errors[:100],
            security_headers=security_headers,
            redirect_chain=self._redirect_chain,
            navigation_duration_ms=nav_duration,
        )

    async def detach(self) -> None:
        """Detach CDP session. Safe to call multiple times."""
        await self._safe_detach()

    # ------------------------------------------------------------------
    # Network event handlers
    # ------------------------------------------------------------------

    def _on_request_will_be_sent(self, params: dict) -> None:
        req_id = params.get("requestId", "")
        request = params.get("request", {})
        initiator = params.get("initiator", {})

        # Track redirect chain for document navigations
        if params.get("redirectResponse"):
            redirect_url = request.get("url", "")
            if redirect_url:
                self._redirect_chain.append(redirect_url)

        self._requests[req_id] = {
            "url": request.get("url", ""),
            "method": request.get("method", "GET"),
            "type": params.get("type", ""),
            "initiator_type": initiator.get("type", ""),
            "initiator_url": initiator.get("url", ""),
            "timestamp": params.get("timestamp", 0),
        }

    def _on_response_received(self, params: dict) -> None:
        req_id = params.get("requestId", "")
        response = params.get("response", {})
        if req_id not in self._requests:
            return

        resp_headers = response.get("headers", {})

        # Store security-relevant headers from main document (Document type)
        req_type = params.get("type", "")
        if req_type == "Document" and not self._main_doc_headers:
            self._main_doc_headers = {
                k.lower(): v for k, v in resp_headers.items()
            }

        self._requests[req_id]["response"] = {
            "status": response.get("status", 0),
            "mime_type": response.get("mimeType", ""),
            "protocol": response.get("protocol", ""),
            "from_cache": response.get("fromDiskCache", False),
            "from_sw": response.get("fromServiceWorker", False),
            "headers": {
                k.lower(): v
                for k, v in resp_headers.items()
                if k.lower() in _SECURITY_HEADER_NAMES
            },
        }

    def _on_loading_finished(self, params: dict) -> None:
        req_id = params.get("requestId", "")
        self._loading[req_id] = {
            "timestamp": params.get("timestamp", 0),
        }

    # ------------------------------------------------------------------
    # WebSocket event handlers
    # ------------------------------------------------------------------

    def _on_ws_created(self, params: dict) -> None:
        req_id = params.get("requestId", "")
        url = params.get("url", "")
        self._ws_sessions[req_id] = WebSocketSession(url=url)

    def _on_ws_frame_sent(self, params: dict) -> None:
        req_id = params.get("requestId", "")
        session = self._ws_sessions.get(req_id)
        if not session:
            return
        response = params.get("response", {})
        payload = response.get("payloadData", "")
        session.frames_sent += 1
        session.bytes_sent += len(payload.encode("utf-8", errors="ignore"))

    def _on_ws_frame_received(self, params: dict) -> None:
        req_id = params.get("requestId", "")
        session = self._ws_sessions.get(req_id)
        if not session:
            return
        response = params.get("response", {})
        payload = response.get("payloadData", "")
        session.frames_received += 1
        session.bytes_received += len(
            payload.encode("utf-8", errors="ignore")
        )

    # ------------------------------------------------------------------
    # Console event handlers
    # ------------------------------------------------------------------

    def _on_console_api_called(self, params: dict) -> None:
        level = params.get("type", "log")
        args = params.get("args", [])

        parts = []
        for arg in args:
            val = arg.get("value")
            if val is not None:
                parts.append(str(val))
            else:
                desc = arg.get("description", "")
                if desc:
                    parts.append(desc)

        text = " ".join(parts)
        if not text:
            return

        # Source location
        stack = params.get("stackTrace", {})
        call_frames = stack.get("callFrames", [])
        source_url = ""
        line = 0
        if call_frames:
            source_url = call_frames[0].get("url", "")
            line = call_frames[0].get("lineNumber", 0)

        msg = ConsoleMessage(
            level=level,
            text=text[:2000],
            url=source_url,
            line=line,
        )
        self._console_messages.append(msg)

    def _on_exception_thrown(self, params: dict) -> None:
        exc_details = params.get("exceptionDetails", {})
        exception = exc_details.get("exception", {})

        text = exception.get("description", "") or exc_details.get("text", "")
        source_url = exc_details.get("url", "")
        line = exc_details.get("lineNumber", 0)

        if text:
            msg = ConsoleMessage(
                level="error",
                text=text[:2000],
                url=source_url,
                line=line,
            )
            self._js_errors.append(msg)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_discovered_request(
        self, req_id: str, req_data: dict
    ) -> DiscoveredRequest:
        """Build DiscoveredRequest from accumulated network event data."""
        resp_data = req_data.get("response", {})
        url = req_data.get("url", "")
        resource_type = req_data.get("type", "")
        mime_type = resp_data.get("mime_type", "")

        # Classify as API call
        is_api = resource_type in _API_RESOURCE_TYPES or any(
            mime_type.startswith(m) for m in _API_MIME_TYPES if mime_type
        )

        # Classify as third-party
        is_third_party = False
        if self._target_origin and url:
            try:
                parsed = urlparse(url)
                req_host = parsed.netloc
                is_third_party = (
                    req_host != self._target_origin
                    and not req_host.endswith("." + self._target_origin)
                )
            except Exception:
                pass

        return DiscoveredRequest(
            url=url,
            method=req_data.get("method", "GET"),
            resource_type=resource_type,
            initiator_type=req_data.get("initiator_type", ""),
            initiator_url=req_data.get("initiator_url", ""),
            status_code=resp_data.get("status", 0),
            mime_type=mime_type,
            protocol=resp_data.get("protocol", ""),
            from_cache=resp_data.get("from_cache", False),
            from_service_worker=resp_data.get("from_sw", False),
            response_headers=resp_data.get("headers", {}),
            is_api_call=is_api,
            is_third_party=is_third_party,
        )

    def _extract_security_headers(self) -> SecurityHeaders:
        """Extract security headers from the main document response."""
        h = self._main_doc_headers
        if not h:
            return SecurityHeaders()

        return SecurityHeaders(
            csp=h.get("content-security-policy", ""),
            csp_report_only=h.get(
                "content-security-policy-report-only", ""
            ),
            cors_allow_origin=h.get("access-control-allow-origin", ""),
            cors_allow_credentials=h.get(
                "access-control-allow-credentials", ""
            ),
            x_frame_options=h.get("x-frame-options", ""),
            strict_transport_security=h.get(
                "strict-transport-security", ""
            ),
            x_content_type_options=h.get("x-content-type-options", ""),
            referrer_policy=h.get("referrer-policy", ""),
            permissions_policy=h.get("permissions-policy", ""),
        )

    async def _safe_detach(self) -> None:
        """Detach CDP session, ignoring errors."""
        if self._cdp:
            try:
                await self._cdp.detach()
            except Exception:
                pass
        self._cdp = None
        self._attached = False
