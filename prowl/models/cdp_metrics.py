"""CDP security intelligence data models.

Models for capturing attack-surface-relevant data via Chrome DevTools
Protocol: hidden API endpoints, WebSocket channels, console leaks,
security header misconfigurations, and redirect chains.
"""

from __future__ import annotations

import time

from pydantic import BaseModel, Field


class DiscoveredRequest(BaseModel):
    """A network request captured via CDP -- potential attack surface."""

    url: str = ""
    method: str = "GET"
    resource_type: str = ""
    initiator_type: str = ""  # script, parser, other
    initiator_url: str = ""  # which script triggered this request
    status_code: int = 0
    mime_type: str = ""
    protocol: str = ""
    from_cache: bool = False
    from_service_worker: bool = False
    response_headers: dict[str, str] = Field(default_factory=dict)
    is_api_call: bool = False  # heuristic: XHR/fetch with JSON/GraphQL
    is_third_party: bool = False


class WebSocketSession(BaseModel):
    """WebSocket connection -- real-time attack surface."""

    url: str = ""
    frames_sent: int = 0
    frames_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0


class ConsoleMessage(BaseModel):
    """Console output captured via Runtime domain."""

    level: str = ""  # log, warning, error, info, debug
    text: str = ""
    url: str = ""  # source URL
    line: int = 0


class SecurityHeaders(BaseModel):
    """Security-relevant response headers for the main document."""

    csp: str = ""
    csp_report_only: str = ""
    cors_allow_origin: str = ""
    cors_allow_credentials: str = ""
    x_frame_options: str = ""
    strict_transport_security: str = ""
    x_content_type_options: str = ""
    referrer_policy: str = ""
    permissions_policy: str = ""


class PageCDPMetrics(BaseModel):
    """All CDP-captured security intelligence for one page navigation."""

    request_url: str = ""
    final_url: str = ""
    timestamp: float = Field(default_factory=time.time)

    # Network: discovered sub-requests (hidden APIs, XHRs, fetches)
    discovered_requests: list[DiscoveredRequest] = Field(default_factory=list)
    api_calls: list[DiscoveredRequest] = Field(default_factory=list)
    total_requests: int = 0
    third_party_requests: int = 0

    # WebSocket endpoints
    websocket_sessions: list[WebSocketSession] = Field(default_factory=list)

    # Console intelligence
    console_messages: list[ConsoleMessage] = Field(default_factory=list)
    js_errors: list[ConsoleMessage] = Field(default_factory=list)

    # Security headers from main document response
    security_headers: SecurityHeaders = Field(default_factory=SecurityHeaders)

    # Redirect chain
    redirect_chain: list[str] = Field(default_factory=list)

    # Navigation
    navigation_duration_ms: float = 0.0


class CDPCrawlSummary(BaseModel):
    """Aggregate security intelligence across entire crawl."""

    total_pages_profiled: int = 0

    # Hidden API endpoints discovered (deduplicated)
    discovered_api_endpoints: list[dict] = Field(default_factory=list)
    total_api_calls: int = 0

    # WebSocket endpoints
    ws_endpoints: list[str] = Field(default_factory=list)

    # Console leaks (potential sensitive info)
    interesting_console_messages: list[dict] = Field(default_factory=list)
    total_js_errors: int = 0

    # Security header analysis
    pages_without_csp: int = 0
    pages_without_hsts: int = 0
    pages_with_permissive_cors: int = 0
    security_header_issues: list[dict] = Field(default_factory=list)

    # Third-party domains contacted
    third_party_domains: list[str] = Field(default_factory=list)

    # Total sub-requests across all pages
    total_sub_requests: int = 0

    # Redirect chains with interesting targets
    redirect_targets: list[str] = Field(default_factory=list)

    # New endpoints found via CDP (not found by spider/other modules)
    unique_cdp_endpoints: int = 0
