"""AttackSurfaceStore — central repository for all discovery results."""

from __future__ import annotations

import logging
from typing import Any

from prowl.models.report import AttackSurfaceReport, RiskSummary
from prowl.models.target import (
    APISchema,
    AuthBoundary,
    Endpoint,
    InputVector,
    Secret,
    TechFingerprint,
)

logger = logging.getLogger(__name__)

# Parameter names that indicate high-risk input vectors
RISK_PARAM_PATTERNS: dict[str, list[str]] = {
    "ssrf_candidate": ["url", "uri", "host", "target", "proxy", "redirect", "next", "return", "callback", "fetch", "load"],
    "lfi_candidate": ["file", "path", "dir", "include", "require", "read", "template", "view", "source"],
    "sqli_candidate": ["id", "user", "username", "email", "name", "query", "search", "filter", "sort", "order"],
    "cmdi_candidate": ["cmd", "command", "exec", "action", "run"],
    "ssti_candidate": ["template", "view", "render", "lang", "language"],
    "redirect_candidate": ["redirect", "url", "next", "return", "callback", "goto", "to"],
}


class AttackSurfaceStore:
    """Central repository collecting all discovery findings across modules."""

    def __init__(self) -> None:
        self._endpoints: dict[str, Endpoint] = {}  # fingerprint → Endpoint
        self._input_vectors: dict[str, InputVector] = {}  # fingerprint → InputVector
        self._auth_boundaries: list[AuthBoundary] = []
        self._tech_stack: dict[str, TechFingerprint] = {}  # name_lower → TechFingerprint
        self._secrets: list[Secret] = []
        self._api_schemas: list[APISchema] = []

    # --- Endpoints ---

    def register_endpoint(self, endpoint: Endpoint) -> bool:
        """Register an endpoint, returns True if new."""
        fp = endpoint.fingerprint
        if fp in self._endpoints:
            existing = self._endpoints[fp]
            # Merge tags
            for tag in endpoint.tags:
                if tag not in existing.tags:
                    existing.tags.append(tag)
            # Merge parameters
            existing_names = {p.name for p in existing.parameters}
            for p in endpoint.parameters:
                if p.name not in existing_names:
                    existing.parameters.append(p)
            # Update fields if richer info available
            if endpoint.page_type and not existing.page_type:
                existing.page_type = endpoint.page_type
            if endpoint.status_code and not existing.status_code:
                existing.status_code = endpoint.status_code
            return False
        self._endpoints[fp] = endpoint
        return True

    @property
    def endpoints(self) -> list[Endpoint]:
        return list(self._endpoints.values())

    @property
    def endpoint_count(self) -> int:
        return len(self._endpoints)

    def get_endpoints_by_tag(self, tag: str) -> list[Endpoint]:
        return [ep for ep in self._endpoints.values() if tag in ep.tags]

    def get_endpoints_by_page_type(self, page_type: str) -> list[Endpoint]:
        return [ep for ep in self._endpoints.values() if ep.page_type == page_type]

    def get_auth_required_endpoints(self) -> list[Endpoint]:
        return [ep for ep in self._endpoints.values() if ep.requires_auth]

    # --- Input Vectors ---

    def register_input_vector(self, iv: InputVector) -> bool:
        """Register an input vector, returns True if new. Auto-tags risk indicators."""
        # Auto-tag risk indicators based on parameter name
        name_lower = iv.name.lower()
        for risk_type, patterns in RISK_PARAM_PATTERNS.items():
            if name_lower in patterns and risk_type not in iv.risk_indicators:
                iv.risk_indicators.append(risk_type)

        fp = iv.fingerprint
        if fp in self._input_vectors:
            existing = self._input_vectors[fp]
            # Merge risk indicators
            for ri in iv.risk_indicators:
                if ri not in existing.risk_indicators:
                    existing.risk_indicators.append(ri)
            # Update reflection status
            if iv.is_reflected and not existing.is_reflected:
                existing.is_reflected = True
            return False
        self._input_vectors[fp] = iv
        return True

    @property
    def input_vectors(self) -> list[InputVector]:
        return list(self._input_vectors.values())

    @property
    def input_vector_count(self) -> int:
        return len(self._input_vectors)

    def get_high_risk_vectors(self) -> list[InputVector]:
        return [iv for iv in self._input_vectors.values() if iv.risk_indicators]

    # --- Auth Boundaries ---

    def register_auth_boundary(self, ab: AuthBoundary) -> None:
        # Dedup by url+method
        for existing in self._auth_boundaries:
            if existing.url == ab.url and existing.method == ab.method:
                # Merge access matrix
                existing.access_matrix.update(ab.access_matrix)
                return
        self._auth_boundaries.append(ab)

    @property
    def auth_boundaries(self) -> list[AuthBoundary]:
        return list(self._auth_boundaries)

    # --- Tech Stack ---

    def merge_tech(self, fp: TechFingerprint) -> None:
        """Merge a tech fingerprint, combining evidence and boosting confidence."""
        key = fp.name.lower()
        if key in self._tech_stack:
            existing = self._tech_stack[key]
            # Merge evidence (dedup)
            for ev in fp.evidence:
                if ev not in existing.evidence:
                    existing.evidence.append(ev)
            # Merge implied paths
            for p in fp.implied_paths:
                if p not in existing.implied_paths:
                    existing.implied_paths.append(p)
            # Boost confidence (cap at 1.0)
            existing.confidence = min(1.0, existing.confidence + fp.confidence * 0.3)
            # Update version if more specific
            if fp.version and not existing.version:
                existing.version = fp.version
        else:
            self._tech_stack[key] = fp

    @property
    def tech_stack(self) -> list[TechFingerprint]:
        return list(self._tech_stack.values())

    def get_tech_implied_paths(self) -> list[str]:
        """Return all paths implied by detected technologies (for SmartProber)."""
        paths: list[str] = []
        for tech in self._tech_stack.values():
            for p in tech.implied_paths:
                if p not in paths:
                    paths.append(p)
        return paths

    def has_tech(self, name: str) -> bool:
        return name.lower() in self._tech_stack

    # --- Secrets ---

    def register_secret(self, secret: Secret) -> None:
        # Simple dedup by value
        for existing in self._secrets:
            if existing.value == secret.value:
                return
        self._secrets.append(secret)

    @property
    def secrets(self) -> list[Secret]:
        return list(self._secrets)

    # --- API Schemas ---

    def register_api_schema(self, schema: APISchema) -> None:
        for existing in self._api_schemas:
            if existing.url == schema.url and existing.schema_type == schema.schema_type:
                return
        self._api_schemas.append(schema)

    @property
    def api_schemas(self) -> list[APISchema]:
        return list(self._api_schemas)

    # --- Report Generation ---

    def build_report(self, target: str, scan_duration: float = 0.0) -> AttackSurfaceReport:
        """Build the final attack surface report with risk scoring."""
        high_risk = self.get_high_risk_vectors()
        admin_endpoints = [
            ep for ep in self._endpoints.values()
            if ep.page_type == "admin" and not ep.requires_auth
        ]
        debug_endpoints = [
            ep for ep in self._endpoints.values()
            if any(t in ep.tags for t in ("debug", "actuator", "phpinfo"))
        ]

        risk_summary = RiskSummary(
            total_endpoints=self.endpoint_count,
            total_input_vectors=self.input_vector_count,
            high_risk_vectors=len(high_risk),
            auth_boundaries_found=len(self._auth_boundaries),
            unprotected_admin_paths=len(admin_endpoints),
            exposed_debug_endpoints=len(debug_endpoints),
            secrets_found=len(self._secrets),
            score=self._compute_risk_score(high_risk, admin_endpoints, debug_endpoints),
        )

        return AttackSurfaceReport(
            target=target,
            scan_duration=scan_duration,
            endpoints=self.endpoints,
            input_vectors=self.input_vectors,
            auth_boundaries=self.auth_boundaries,
            tech_stack=self.tech_stack,
            api_schemas=self.api_schemas,
            secrets=self.secrets,
            risk_summary=risk_summary,
        )

    def _compute_risk_score(
        self,
        high_risk: list[InputVector],
        admin_endpoints: list[Endpoint],
        debug_endpoints: list[Endpoint],
    ) -> float:
        """Compute a 0-100 composite risk score."""
        score = 0.0

        # High-risk input vectors (up to 40 points)
        score += min(40.0, len(high_risk) * 2.0)

        # Secrets found (up to 20 points)
        score += min(20.0, len(self._secrets) * 5.0)

        # Unprotected admin (up to 15 points)
        score += min(15.0, len(admin_endpoints) * 5.0)

        # Exposed debug endpoints (up to 15 points)
        score += min(15.0, len(debug_endpoints) * 5.0)

        # Missing auth boundaries on sensitive endpoints (up to 10 points)
        auth_required = [ep for ep in self._endpoints.values() if ep.requires_auth]
        if auth_required:
            bounded = {ab.url for ab in self._auth_boundaries}
            unbounded = [ep for ep in auth_required if ep.url not in bounded]
            score += min(10.0, len(unbounded) * 2.0)

        return min(100.0, score)

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics."""
        return {
            "endpoints": self.endpoint_count,
            "input_vectors": self.input_vector_count,
            "auth_boundaries": len(self._auth_boundaries),
            "tech_detected": len(self._tech_stack),
            "secrets": len(self._secrets),
            "api_schemas": len(self._api_schemas),
            "high_risk_vectors": len(self.get_high_risk_vectors()),
        }
