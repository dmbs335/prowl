"""Discovery report models."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .target import (
    APISchema,
    AuthBoundary,
    Endpoint,
    InputVector,
    Secret,
    TechFingerprint,
)


class ModuleReport(BaseModel):
    """Report from a single discovery module."""

    module_name: str
    endpoints_found: int = 0
    parameters_found: int = 0
    secrets_found: int = 0
    requests_made: int = 0
    errors: int = 0
    duration_seconds: float = 0.0


class RiskSummary(BaseModel):
    """Aggregate risk scoring for the attack surface."""

    total_endpoints: int = 0
    total_input_vectors: int = 0
    high_risk_vectors: int = 0  # ssrf, sqli, cmdi, ssti candidates
    auth_boundaries_found: int = 0
    unprotected_admin_paths: int = 0
    exposed_debug_endpoints: int = 0
    secrets_found: int = 0
    score: float = 0.0  # 0-100 composite risk score


class AttackSurfaceReport(BaseModel):
    """Top-level output: the complete attack surface map."""

    target: str
    scan_duration: float = 0.0
    endpoints: list[Endpoint] = Field(default_factory=list)
    input_vectors: list[InputVector] = Field(default_factory=list)
    auth_boundaries: list[AuthBoundary] = Field(default_factory=list)
    tech_stack: list[TechFingerprint] = Field(default_factory=list)
    api_schemas: list[APISchema] = Field(default_factory=list)
    secrets: list[Secret] = Field(default_factory=list)
    module_reports: list[ModuleReport] = Field(default_factory=list)
    risk_summary: RiskSummary = Field(default_factory=RiskSummary)


# Keep backward compatibility alias
CrawlReport = AttackSurfaceReport
