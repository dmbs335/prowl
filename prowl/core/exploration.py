"""Coverage-guided exploration strategies inspired by fuzzing, symbolic execution, and RL.

CoverageBitmap      - AFL-style coverage tracking for web endpoints
SeedScheduler       - Priority scoring for exploration requests
URLTemplateInferrer - Concolic URL template inference and mutation (discovery only)
HindsightFeedback   - Learn from "failed" requests (403, 405, 500, redirects)
"""

from __future__ import annotations

import hashlib
import logging
import random
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from prowl.core.state_tracker import structural_hash

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Coverage Bitmap (from AFL)
# ---------------------------------------------------------------------------


class CoverageBitmap:
    """AFL-style coverage tracking adapted for web crawling.

    A "coverage tuple" = (endpoint_template, method, status_bucket, structural_hash).
    New tuples = "interesting" responses worth exploring further.
    """

    _MAX_CORPUS_SIZE = 10_000

    def __init__(
        self,
        saturation_window: int = 200,
        saturation_threshold: float = 0.02,
    ) -> None:
        self._seen: set[tuple[str, str, int, str, str]] = set()
        self._corpus: deque[dict[str, Any]] = deque(maxlen=self._MAX_CORPUS_SIZE)
        self._total_checked: int = 0
        # Saturation detection (sliding window)
        self._sat_window: deque[bool] = deque(maxlen=saturation_window)
        self._sat_window_size: int = saturation_window
        self._sat_threshold: float = saturation_threshold

    @property
    def coverage_count(self) -> int:
        return len(self._seen)

    @property
    def corpus_size(self) -> int:
        return len(self._corpus)

    def is_interesting(
        self,
        url: str,
        method: str,
        status_code: int,
        body: bytes,
        content_type: str,
        auth_role: str | None = None,
    ) -> bool:
        """Check if this response represents new coverage."""
        self._total_checked += 1

        sig = (
            self._normalize_to_template(url),
            method.upper(),
            status_code // 100,
            structural_hash(body, content_type),
            auth_role or "",
        )

        is_new = sig not in self._seen
        if is_new:
            self._seen.add(sig)
            self._corpus.append({
                "url": url,
                "method": method,
                "status": status_code,
                "template": sig[0],
                "auth_role": auth_role or "",
            })

        # Update saturation window (deque maxlen auto-evicts oldest)
        self._sat_window.append(is_new)

        return is_new

    @property
    def is_saturated(self) -> bool:
        """True when coverage growth rate drops below threshold."""
        if len(self._sat_window) < self._sat_window_size:
            return False
        return self.discovery_rate < self._sat_threshold

    @property
    def discovery_rate(self) -> float:
        """Fraction of recent requests that produced new coverage."""
        if not self._sat_window:
            return 1.0
        return sum(self._sat_window) / len(self._sat_window)

    def get_stats(self) -> dict[str, Any]:
        return {
            "unique_coverage": len(self._seen),
            "corpus_size": len(self._corpus),
            "total_checked": self._total_checked,
            "discovery_rate": round(self.discovery_rate, 4),
            "saturated": self.is_saturated,
        }

    @staticmethod
    def _normalize_to_template(url: str) -> str:
        """Normalize a URL to a template by replacing dynamic segments.

        /api/users/123            → /api/users/{id}
        /api/users/abc-def        → /api/users/{slug}
        /products/42              → /products/{id}
        /api/users?role=admin     → /api/users?role=
        /api/users?role=x&sort=y  → /api/users?role=&sort=
        """
        parsed = urlparse(url)
        segments = parsed.path.strip("/").split("/")
        normalized = []

        for seg in segments:
            if not seg:
                continue
            # Pure integer → {id}
            if seg.isdigit():
                normalized.append("{id}")
            # UUID pattern → {uuid}
            elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", seg, re.I):
                normalized.append("{uuid}")
            # Hex hash (8+ chars) → {hash}
            elif re.match(r"^[0-9a-f]{8,}$", seg, re.I) and len(seg) >= 8:
                normalized.append("{hash}")
            # Slug with digits mixed in → {slug}
            elif re.match(r"^[a-z0-9]+-[a-z0-9]+(-[a-z0-9]+)+$", seg, re.I):
                normalized.append("{slug}")
            else:
                normalized.append(seg)

        template = "/" + "/".join(normalized)

        # Parameter-aware: include sorted query param names (not values)
        # /api/users?role=admin → /api/users?role=
        # This distinguishes different parameter combinations as separate coverage.
        if parsed.query:
            from urllib.parse import parse_qs
            param_names = sorted(parse_qs(parsed.query).keys())
            if param_names:
                template += "?" + "&".join(f"{p}=" for p in param_names)

        return template


# ---------------------------------------------------------------------------
# Seed Scheduler (from AFL Power Schedules)
# ---------------------------------------------------------------------------


class SeedScheduler:
    """Dynamic priority scoring for crawl requests.

    Combines heuristic scoring (cold-start, security relevance) with
    Thompson Sampling (MAB) for explore/exploit balance.

    Each URL template is a bandit arm with Beta(α, β) posterior.
    α = new-coverage hits + 1, β = no-new-coverage hits + 1.
    Priority = heuristic_score + sample(Beta(α, β)) * 10.

    Cold-start: heuristic dominates (security patterns, rare-edge bonus).
    Data accumulates: Thompson dominates - no hyperparameter tuning needed.
    (Validated: T-Scheduler, AsiaCCS 2024)
    """

    def __init__(self) -> None:
        self._endpoint_hit_count: dict[str, int] = defaultdict(int)
        self._module_discovery_rate: dict[str, float] = defaultdict(float)
        # Thompson Sampling posteriors per URL template
        self._ts_alpha: dict[str, int] = defaultdict(lambda: 1)  # successes + prior
        self._ts_beta: dict[str, int] = defaultdict(lambda: 1)   # failures + prior

    # Security-relevant URL patterns (higher priority)
    _SECURITY_PATTERNS = [
        (re.compile(r"/admin", re.I), 5.0),
        (re.compile(r"/api/internal", re.I), 5.0),
        (re.compile(r"/debug", re.I), 4.0),
        (re.compile(r"/graphql", re.I), 3.0),
        (re.compile(r"/upload", re.I), 3.0),
        (re.compile(r"/auth|/login|/oauth", re.I), 3.0),
        (re.compile(r"/api/", re.I), 2.0),
        (re.compile(r"/config|/settings", re.I), 2.0),
        (re.compile(r"/actuator|/health|/metrics", re.I), 2.0),
    ]

    def calculate_priority(self, url: str, source_module: str = "", depth: int = 0) -> int:
        """Calculate exploration priority for a request (higher = more urgent).

        Hybrid scoring: heuristic (cold-start) + Thompson Sampling (data-driven).
        """
        score = 10.0  # base priority

        # ── Heuristic component (dominates during cold-start) ──

        # Rare edge bonus: endpoints visited less often get higher priority
        template = CoverageBitmap._normalize_to_template(url)
        hit_count = self._endpoint_hit_count.get(template, 0)
        if hit_count == 0:
            score += 8.0  # never visited - highest bonus
        elif hit_count < 3:
            score += 4.0
        else:
            score -= min(hit_count, 10)  # diminishing returns

        # Security relevance bonus
        for pattern, bonus in self._SECURITY_PATTERNS:
            if pattern.search(url):
                score += bonus
                break

        # Depth penalty (deeper = lower priority, but still explored)
        score -= depth * 0.5

        # Discovery rate bonus
        if source_module and self._module_discovery_rate.get(source_module, 0) > 0.3:
            score += 3.0

        # ── Thompson Sampling component (dominates with data) ──
        # Sample from Beta posterior - templates that produced new coverage
        # get higher samples on average, steering exploration toward them.
        alpha = self._ts_alpha[template]
        beta = self._ts_beta[template]
        thompson = random.betavariate(alpha, beta)
        score += thompson * 10.0  # scale to [0, 10]

        return max(1, int(score))

    def record_coverage_hit(self, url: str, is_new_coverage: bool) -> None:
        """Record a coverage observation and update Beta posterior.

        Args:
            url: The URL that was visited.
            is_new_coverage: True if the response produced new coverage.
        """
        template = CoverageBitmap._normalize_to_template(url)
        self._endpoint_hit_count[template] += 1
        if is_new_coverage:
            self._ts_alpha[template] += 1
        else:
            self._ts_beta[template] += 1

    def record_hit(self, url: str) -> None:
        """Record that an endpoint was visited (backward-compat, no coverage info)."""
        self.record_coverage_hit(url, is_new_coverage=False)

    def update_discovery_rate(self, module: str, new_per_request: float) -> None:
        """Update the discovery rate for a module (new coverage / requests)."""
        self._module_discovery_rate[module] = new_per_request


# ---------------------------------------------------------------------------
# URL Template Inference (from Symbolic Execution / Concolic)
# ---------------------------------------------------------------------------


@dataclass
class PathTemplate:
    """An inferred URL template with typed parameter slots."""

    template: str  # "/api/users/{id}"
    param_slots: dict[str, str] = field(default_factory=dict)  # {id: "integer"}
    observed_urls: list[str] = field(default_factory=list)


class URLTemplateInferrer:
    """Infer URL templates from observed URLs and generate discovery mutations.

    Discovery Only: generates boundary values and semantic variants,
    NEVER attack payloads.

    Uses AFLFast-style power schedule: productive templates (those that
    generated new coverage) get more mutation budget.
    """

    def __init__(self, scheduler: SeedScheduler | None = None) -> None:
        self._templates: dict[str, PathTemplate] = {}  # normalized → template
        self._scheduler = scheduler

    def observe(self, url: str) -> PathTemplate | None:
        """Observe a URL and update/create templates. Returns template if new."""
        normalized = CoverageBitmap._normalize_to_template(url)

        if normalized in self._templates:
            self._templates[normalized].observed_urls.append(url)
            return None

        # Infer parameter types from the original URL
        parsed = urlparse(url)
        segments = parsed.path.strip("/").split("/")
        norm_segments = normalized.strip("/").split("/")

        param_slots: dict[str, str] = {}
        for orig, norm in zip(segments, norm_segments):
            if norm.startswith("{") and norm.endswith("}"):
                param_name = norm[1:-1]
                if orig.isdigit():
                    param_slots[param_name] = "integer"
                elif re.match(r"^[0-9a-f-]{36}$", orig, re.I):
                    param_slots[param_name] = "uuid"
                else:
                    param_slots[param_name] = "string"

        template = PathTemplate(
            template=normalized,
            param_slots=param_slots,
            observed_urls=[url],
        )
        self._templates[normalized] = template
        return template

    def get_energy(self, template: PathTemplate) -> int:
        """AFLFast-style power schedule: productive templates get more mutation budget.

        energy(t) = min(base^j / freq, MAX_ENERGY)
        where j = new-coverage hits for this template, freq = relative coverage frequency.
        """
        if not self._scheduler:
            return 30  # no scheduler → no cap

        alpha = self._scheduler._ts_alpha.get(template.template, 1)
        total_alpha = sum(self._scheduler._ts_alpha.values()) or 1
        freq = alpha / total_alpha

        base_energy = 3
        energy = min(int(base_energy ** min(alpha, 5) / max(freq, 0.01)), 30)
        return max(1, energy)

    def generate_mutations(self, template: PathTemplate) -> list[str]:
        """Generate discovery-only URL mutations from a template.

        NEVER generates attack payloads - only:
        - Boundary values (0, -1, 999999)
        - Semantic variants (me, self, admin)
        - Version variants (v1 → v2, v3)

        Mutation count is capped by AFLFast energy schedule.
        """
        if not template.param_slots:
            return []

        mutations: list[str] = []
        base_template = template.template

        for param_name, param_type in template.param_slots.items():
            placeholder = "{" + param_name + "}"

            if param_type == "integer":
                for val in ["0", "1", "2", "-1", "999999", "2147483647"]:
                    mutations.append(base_template.replace(placeholder, val))
                # Semantic ID variants
                for val in ["me", "self", "current", "admin"]:
                    mutations.append(base_template.replace(placeholder, val))

            elif param_type == "uuid":
                # Try a zeroed UUID
                mutations.append(base_template.replace(
                    placeholder, "00000000-0000-0000-0000-000000000000"
                ))

            elif param_type == "string":
                for val in ["admin", "test", "internal", "debug", "me", "self"]:
                    mutations.append(base_template.replace(placeholder, val))

        # Version mutations
        version_re = re.compile(r"/v(\d+)/")
        for url in template.observed_urls[:1]:
            match = version_re.search(url)
            if match:
                current_v = int(match.group(1))
                for v in range(1, min(current_v + 3, 10)):
                    if v != current_v:
                        mutations.append(url.replace(f"/v{current_v}/", f"/v{v}/"))

        # AFLFast energy cap: productive templates get more budget
        energy = self.get_energy(template)
        return mutations[:energy]

    @property
    def templates(self) -> dict[str, PathTemplate]:
        return dict(self._templates)


# ---------------------------------------------------------------------------
# Hindsight Feedback (from RL: Hindsight Experience Replay)
# ---------------------------------------------------------------------------


@dataclass
class HindsightInsight:
    """An insight derived from a "failed" request."""

    url: str
    method: str
    status_code: int
    insight_type: str  # auth_boundary, method_hint, server_processing, redirect_boundary
    detail: str


class HindsightFeedback:
    """Extract security-relevant information from non-2xx responses.

    Every response is information:
    - 403 → path exists, needs auth (auth boundary)
    - 405 → path exists, wrong method (method hint)
    - 500 → input reached server logic (server processing)
    - 302 → redirect to login (auth boundary)
    - 401 → explicit auth required
    """

    _MAX_INSIGHTS = 5_000

    def __init__(self) -> None:
        self._insights: deque[HindsightInsight] = deque(maxlen=self._MAX_INSIGHTS)

    @property
    def insights(self) -> list[HindsightInsight]:
        return list(self._insights)

    def analyze(
        self, url: str, method: str, status_code: int, headers: dict[str, str]
    ) -> HindsightInsight | None:
        """Analyze a response for hindsight insights."""
        insight = None

        if status_code == 403:
            insight = HindsightInsight(
                url=url, method=method, status_code=403,
                insight_type="auth_boundary",
                detail="Path exists but requires authorization",
            )

        elif status_code == 401:
            insight = HindsightInsight(
                url=url, method=method, status_code=401,
                insight_type="auth_boundary",
                detail="Explicit authentication required",
            )

        elif status_code == 405:
            allow = headers.get("allow", headers.get("Allow", ""))
            insight = HindsightInsight(
                url=url, method=method, status_code=405,
                insight_type="method_hint",
                detail=f"Method not allowed. Accepted: {allow}" if allow else "Method not allowed",
            )

        elif status_code == 500:
            insight = HindsightInsight(
                url=url, method=method, status_code=500,
                insight_type="server_processing",
                detail="Input reached server-side processing (internal error)",
            )

        elif status_code in (301, 302, 303, 307, 308):
            location = headers.get("location", headers.get("Location", ""))
            if location and any(kw in location.lower() for kw in ("login", "signin", "auth", "sso")):
                insight = HindsightInsight(
                    url=url, method=method, status_code=status_code,
                    insight_type="redirect_boundary",
                    detail=f"Redirects to auth: {location}",
                )

        if insight:
            self._insights.append(insight)
            logger.debug("Hindsight [%s] %s %s: %s", insight.insight_type, method, url, insight.detail)

        return insight

    def get_auth_boundaries(self) -> list[HindsightInsight]:
        """Get all insights that indicate auth boundaries."""
        return [i for i in self._insights if i.insight_type in ("auth_boundary", "redirect_boundary")]

    def get_method_hints(self) -> list[HindsightInsight]:
        """Get all 405 responses with Allow header info."""
        return [i for i in self._insights if i.insight_type == "method_hint"]

    def get_stats(self) -> dict[str, Any]:
        types = defaultdict(int)
        for i in self._insights:
            types[i.insight_type] += 1
        return {"total_insights": len(self._insights), "by_type": dict(types)}
