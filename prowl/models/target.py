"""Discovery target models - endpoints, parameters, secrets, attack surface."""

from __future__ import annotations

import hashlib
from enum import auto

from prowl._compat import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ParameterLocation(StrEnum):
    QUERY = auto()
    BODY = auto()
    HEADER = auto()
    COOKIE = auto()
    PATH = auto()
    GRAPHQL_ARG = auto()


class Parameter(BaseModel):
    """A discovered parameter on an endpoint."""

    name: str
    location: ParameterLocation = ParameterLocation.QUERY
    sample_values: list[str] = Field(default_factory=list)
    param_type: str = "string"
    required: bool = False
    source_module: str = ""


class InputVector(BaseModel):
    """An input point that accepts user data - the atomic unit of attack surface."""

    endpoint_url: str
    name: str
    location: ParameterLocation = ParameterLocation.QUERY
    input_type: str = "string"  # string, integer, file, json, xml
    is_reflected: bool = False  # value appears in response (XSS candidate)
    is_stored: bool | None = None
    sample_values: list[str] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)
    risk_indicators: list[str] = Field(default_factory=list)
    source_module: str = ""

    @property
    def fingerprint(self) -> str:
        raw = f"{self.endpoint_url}|{self.name}|{self.location}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class EndpointProfile(BaseModel):
    """Extended endpoint metadata discovered through method/content-type probing."""

    accepted_methods: list[str] = Field(default_factory=list)
    accepted_content_types: list[str] = Field(default_factory=list)
    cors_allowed_origins: list[str] = Field(default_factory=list)
    allow_header: str = ""
    rate_limit_headers: dict[str, str] = Field(default_factory=dict)


class Endpoint(BaseModel):
    """A discovered endpoint (URL + method + parameters)."""

    url: str
    method: str = "GET"
    parameters: list[Parameter] = Field(default_factory=list)
    status_code: int | None = None
    content_type: str = ""
    source_module: str = ""
    depth: int = 0
    tags: list[str] = Field(default_factory=list)

    # Discovery-enriched fields
    page_type: str = ""  # login, error, api_json, admin, static, custom_404
    requires_auth: bool = False
    input_vectors: list[InputVector] = Field(default_factory=list)
    tech_indicators: list[str] = Field(default_factory=list)

    # Phase 1 additions
    profile: EndpointProfile | None = None
    path_template: str = ""  # e.g., "/api/users/{id}"
    normalized_url: str = ""  # URL with query values stripped

    @property
    def param_count(self) -> int:
        return len(self.parameters)

    @property
    def fingerprint(self) -> str:
        raw = f"{self.method.upper()}|{self.url}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class AuthBoundary(BaseModel):
    """A transition point between access levels."""

    url: str
    method: str = "GET"
    unauth_status: int = 0
    auth_status: int = 0
    unauth_content_hash: str = ""
    auth_content_hash: str = ""
    requires_role: str = ""
    boundary_type: str = ""  # redirect_to_login, 403_forbidden, content_difference
    access_matrix: dict[str, int] = Field(default_factory=dict)  # role → status_code


class ResponseFingerprint(BaseModel):
    """Response pattern for clustering and classification."""

    status_code: int
    content_length: int
    content_hash: str
    headers_signature: str = ""
    page_type: str = ""  # login, error, api_json, admin, static, custom_404
    tech_indicators: list[str] = Field(default_factory=list)


class TechFingerprint(BaseModel):
    """Detected technology with evidence."""

    name: str  # Spring Boot, WordPress, React, ...
    version: str = ""
    category: str = ""  # framework, server, cms, frontend, waf
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    implied_paths: list[str] = Field(default_factory=list)


class Secret(BaseModel):
    """A discovered secret (API key, token, etc.)."""

    kind: str
    value: str
    source_url: str
    source_file: str = ""
    line: int | None = None
    entropy: float = 0.0
    risk_indicators: list[str] = Field(default_factory=list)


class APISchema(BaseModel):
    """A discovered API schema (OpenAPI, GraphQL, WSDL)."""

    schema_type: str
    url: str
    endpoints: list[Endpoint] = Field(default_factory=list)
    raw_content: str = ""
    auth_schemes: list[str] = Field(default_factory=list)


# Keep backward compatibility alias
TechStack = TechFingerprint
