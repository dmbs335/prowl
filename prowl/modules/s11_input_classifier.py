"""Input Vector Classifier — converts discovered parameters into classified
InputVectors with reflection detection, type inference, and contextual
risk scoring.

No additional HTTP requests.  All analysis is performed on endpoints
already registered in AttackSurfaceStore and traffic in TransactionStore.
"""

from __future__ import annotations

import re
import logging
from typing import Any
from urllib.parse import urlparse, parse_qs

from prowl.core.signals import Signal
from prowl.models.target import InputVector, ParameterLocation
from prowl.modules.base import BaseModule

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type inference patterns
# ---------------------------------------------------------------------------

_TYPE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("integer", re.compile(r"^-?\d+$")),
    ("float", re.compile(r"^-?\d+\.\d+$")),
    ("boolean", re.compile(r"^(?:true|false|0|1|yes|no)$", re.I)),
    ("email", re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")),
    ("uuid", re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)),
    ("url", re.compile(r"^https?://")),
    ("date", re.compile(r"^\d{4}-\d{2}-\d{2}")),
    ("jwt", re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+")),
    ("json", re.compile(r"^\s*[\[{]")),
    ("base64", re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")),
    ("hex", re.compile(r"^[0-9a-fA-F]{8,}$")),
    ("path", re.compile(r"^[/\\]|\.\./")),
]

# ---------------------------------------------------------------------------
# Context risk patterns (endpoint URL + param name → risk)
# ---------------------------------------------------------------------------

_ENDPOINT_RISK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("admin_context", re.compile(r"/admin|/manage|/dashboard|/internal", re.I)),
    ("api_context", re.compile(r"/api/|/v\d+/|/graphql", re.I)),
    ("upload_context", re.compile(r"/upload|/import|/attach|/file", re.I)),
    ("auth_context", re.compile(r"/login|/auth|/token|/session|/oauth", re.I)),
    ("search_context", re.compile(r"/search|/query|/find|/lookup", re.I)),
    ("debug_context", re.compile(r"/debug|/test|/dev|/actuator|/phpinfo", re.I)),
]

# Param name → likely type override
_NAME_TYPE_HINTS: dict[str, str] = {
    "id": "integer", "user_id": "integer", "page": "integer", "limit": "integer",
    "offset": "integer", "count": "integer", "size": "integer", "num": "integer",
    "email": "email", "mail": "email",
    "url": "url", "uri": "url", "link": "url", "redirect": "url",
    "callback": "url", "next": "url", "return": "url", "goto": "url",
    "file": "path", "path": "path", "dir": "path", "filename": "path",
    "token": "string", "key": "string", "api_key": "string",
    "password": "string", "secret": "string",
    "enabled": "boolean", "active": "boolean", "debug": "boolean",
    "date": "date", "start_date": "date", "end_date": "date",
    "json": "json", "data": "json", "body": "json", "payload": "json",
}

# Cross-reference: tech + param name → elevated risk
_TECH_RISK_MAP: dict[str, list[tuple[re.Pattern[str], str]]] = {
    "php": [
        (re.compile(r"file|path|include|require|page|dir", re.I), "lfi_elevated_php"),
        (re.compile(r"cmd|exec|system|shell", re.I), "cmdi_elevated_php"),
    ],
    "java": [
        (re.compile(r"class|bean|type|object", re.I), "deserialization_risk_java"),
    ],
    "aspnet": [
        (re.compile(r"__VIEWSTATE|__EVENTVALIDATION", re.I), "viewstate_deserialization"),
    ],
    "rails": [
        (re.compile(r"template|render|partial", re.I), "ssti_elevated_rails"),
    ],
    "django": [
        (re.compile(r"template|render", re.I), "ssti_elevated_django"),
    ],
    "wordpress": [
        (re.compile(r"action|plugin|theme", re.I), "wp_plugin_abuse"),
    ],
}


class InputClassifierModule(BaseModule):
    """Classifies all discovered parameters into typed, risk-scored InputVectors."""

    name = "s11_input"
    description = "Input vector classifier — type inference, reflection, risk scoring"

    def __init__(self, engine: Any) -> None:
        super().__init__(engine)
        self._reflected_count = 0
        self._classified_count = 0

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        self.logger.info("Starting input vector classification")

        # Collect detected tech names for cross-referencing
        detected_tech = {
            t.name.lower()
            for t in self.engine.attack_surface.tech_stack
        }

        # Build reflection index: url → response body text (from TransactionStore)
        reflection_index: dict[str, str] = {}
        async for txn in self.engine.transaction_store.get_all_transactions():
            if not self._running:
                break
            if txn.response_body and len(txn.response_body) < 500_000:
                text = txn.response_body.decode("utf-8", errors="replace")
                reflection_index[txn.request_url] = text
                # Also index query parameter values from this URL
                qs = parse_qs(urlparse(txn.request_url).query)
                for vals in qs.values():
                    for v in vals:
                        if len(v) >= 4 and v in text:
                            # Value appears in response body — potential reflection
                            pass  # handled per-parameter below

        # Process all endpoints
        endpoints = self.engine.attack_surface.endpoints
        self.logger.info("Processing %d endpoints", len(endpoints))

        for ep in endpoints:
            if not self._running:
                break

            endpoint_risks = self._get_endpoint_risks(ep.url)

            for param in ep.parameters:
                iv = self._classify_parameter(
                    ep.url, ep.method, param.name, param.location,
                    param.sample_values, endpoint_risks, detected_tech,
                    reflection_index,
                )
                is_new = self.engine.attack_surface.register_input_vector(iv)
                if is_new:
                    self._classified_count += 1
                    await self.engine.signals.emit(
                        Signal.INPUT_VECTOR_FOUND, input_vector=iv,
                    )

        self.endpoints_found = self._classified_count
        self._running = False
        self.logger.info(
            "Input classification complete — %d vectors classified, %d reflected",
            self._classified_count, self._reflected_count,
        )

    def _classify_parameter(
        self,
        url: str,
        method: str,
        name: str,
        location: ParameterLocation,
        sample_values: list[str],
        endpoint_risks: list[str],
        detected_tech: set[str],
        reflection_index: dict[str, str],
    ) -> InputVector:
        """Build a fully classified InputVector from a parameter."""

        # Type inference
        input_type = self._infer_type(name, sample_values)

        # Reflection check
        is_reflected = self._check_reflection(url, name, sample_values, reflection_index)
        if is_reflected:
            self._reflected_count += 1

        # Risk indicators
        risk_indicators: list[str] = list(endpoint_risks)

        # Reflection = XSS candidate
        if is_reflected:
            risk_indicators.append("reflected_xss_candidate")

        # Tech cross-reference
        for tech_name, patterns in _TECH_RISK_MAP.items():
            if tech_name in detected_tech:
                for pat, risk_tag in patterns:
                    if pat.search(name):
                        risk_indicators.append(risk_tag)

        # Type-based risks
        if input_type == "url":
            risk_indicators.append("ssrf_candidate")
        elif input_type == "path":
            risk_indicators.append("lfi_candidate")
        elif input_type == "json":
            risk_indicators.append("injection_candidate")

        # Method-based context
        if method.upper() in ("PUT", "DELETE", "PATCH"):
            risk_indicators.append("state_changing_method")

        # Dedup risk indicators
        risk_indicators = list(dict.fromkeys(risk_indicators))

        return InputVector(
            endpoint_url=url,
            name=name,
            location=location,
            input_type=input_type,
            is_reflected=is_reflected,
            sample_values=sample_values[:5],
            risk_indicators=risk_indicators,
            source_module=self.name,
        )

    def _infer_type(self, name: str, sample_values: list[str]) -> str:
        """Infer parameter type from name hints and sample values."""

        # Name-based hints first
        name_lower = name.lower().replace("-", "_")
        if name_lower in _NAME_TYPE_HINTS:
            return _NAME_TYPE_HINTS[name_lower]

        # Sample-value-based inference
        if not sample_values:
            return "string"

        type_votes: dict[str, int] = {}
        for val in sample_values[:10]:
            for type_name, pattern in _TYPE_PATTERNS:
                if pattern.match(val):
                    type_votes[type_name] = type_votes.get(type_name, 0) + 1
                    break

        if type_votes:
            return max(type_votes, key=type_votes.get)  # type: ignore[arg-type]
        return "string"

    def _check_reflection(
        self,
        url: str,
        param_name: str,
        sample_values: list[str],
        reflection_index: dict[str, str],
    ) -> bool:
        """Check if any sample value appears in the response body (reflection)."""
        response_text = reflection_index.get(url, "")
        if not response_text:
            return False

        for val in sample_values:
            # Skip very short or generic values
            if len(val) < 4:
                continue
            # Skip pure numbers (too many false positives)
            if val.isdigit() and len(val) < 6:
                continue
            if val in response_text:
                return True
        return False

    @staticmethod
    def _get_endpoint_risks(url: str) -> list[str]:
        """Derive context-based risk tags from the endpoint URL."""
        risks = []
        for tag, pattern in _ENDPOINT_RISK_PATTERNS:
            if pattern.search(url):
                risks.append(tag)
        return risks
