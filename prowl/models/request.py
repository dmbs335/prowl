"""HTTP request/response models for discovery."""

from __future__ import annotations

import hashlib
from enum import auto

from prowl._compat import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class HttpMethod(StrEnum):
    GET = auto()
    POST = auto()
    PUT = auto()
    DELETE = auto()
    PATCH = auto()
    HEAD = auto()
    OPTIONS = auto()


class CrawlRequest(BaseModel):
    """A single discovery request to be processed by a backend."""

    url: str
    method: HttpMethod = HttpMethod.GET
    headers: dict[str, str] = Field(default_factory=dict)
    body: bytes | None = None
    priority: int = 0
    depth: int = 0
    source_module: str = ""
    require_browser: bool = False
    auth_role: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """URL + method + body hash + auth_role fingerprint for dedup."""
        raw = f"{self.method.upper()}|{self.url}"
        if self.body and self.method.upper() in ("POST", "PUT", "PATCH"):
            body_hash = hashlib.sha256(self.body).hexdigest()[:8]
            raw += f"|{body_hash}"
        if self.auth_role:
            raw += f"|@{self.auth_role}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class FormField(BaseModel):
    """A form field discovered on a page."""

    name: str
    field_type: str = "text"
    value: str = ""
    required: bool = False


class FormData(BaseModel):
    """A form discovered on a page."""

    action: str
    method: HttpMethod = HttpMethod.GET
    fields: list[FormField] = Field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"


class LinkData(BaseModel):
    """A link discovered on a page."""

    url: str
    text: str = ""
    source: str = ""
    tag: str = "a"
    attributes: dict[str, str] = Field(default_factory=dict)


class CrawlResponse(BaseModel):
    """Response from a discovery request."""

    request: CrawlRequest
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: bytes = b""
    content_type: str = ""
    url_final: str = ""

    # Extracted data
    links: list[LinkData] = Field(default_factory=list)
    forms: list[FormData] = Field(default_factory=list)
    js_files: list[str] = Field(default_factory=list)
    rendered_dom: str | None = None

    # Discovery context — populated by DiscoveryEngine after each response
    page_type: str = ""  # real_content, custom_404, waf_block, error, redirect, auth_required
    tech_indicators: list[str] = Field(default_factory=list)

    @property
    def content_hash(self) -> str:
        """SHA256 hash of response body for content-based dedup."""
        return hashlib.sha256(self.body).hexdigest()

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def headers_signature(self) -> str:
        """Normalized hash of key response headers for fingerprinting."""
        keys = sorted(k.lower() for k in self.headers if k.lower() in {
            "server", "x-powered-by", "x-aspnet-version", "x-generator",
            "content-type", "x-frame-options", "x-content-type-options",
        })
        raw = "|".join(f"{k}={self.headers.get(k, '')}" for k in keys)
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    model_config = {"arbitrary_types_allowed": True}
