"""Hierarchical state management and transition tracking for web app state machines.

Layer 0: SecurityContext   — coarse state for exploration dedup (5-15 per app)
Layer 1: FunctionalState   — flow tracking (50-200 per app)
Layer 2: FullState          — everything stored, never used for dedup

State transitions are detected by monitoring:
- Set-Cookie changes (new session/token)
- Authorization header changes
- Redirect patterns (POST→302→dashboard = login success)
- Response content markers ("logged in as", "welcome")
- Endpoint accessibility changes (403→200)
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from pydantic import BaseModel, Field

from prowl.models.request import CrawlRequest, CrawlResponse


# ---------------------------------------------------------------------------
# Hierarchical State Models
# ---------------------------------------------------------------------------


class SecurityContext(BaseModel):
    """Layer 0: Coarsest state for exploration dedup. ~5-15 per app."""

    auth_level: str = "anonymous"  # anonymous, authenticated, admin, ...
    accessible_endpoints_hash: str = ""  # hash of endpoint template set
    role_markers: frozenset[str] = frozenset()

    @property
    def identity(self) -> str:
        """Unique identity for dedup decisions."""
        raw = f"{self.auth_level}|{self.accessible_endpoints_hash}|{sorted(self.role_markers)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    model_config = {"frozen": True}


class FunctionalState(BaseModel):
    """Layer 1: Medium state for flow tracking. ~50-200 per app."""

    security_context: SecurityContext
    active_flow: str | None = None  # "checkout_step_2", None
    available_actions_hash: str = ""  # hash of current page actions

    @property
    def identity(self) -> str:
        raw = f"{self.security_context.identity}|{self.active_flow}|{self.available_actions_hash}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    model_config = {"frozen": True}


class FullState(BaseModel):
    """Layer 2: Full state stored in TransactionStore. Never used for dedup."""

    functional_state: FunctionalState
    cookies: dict[str, str] = Field(default_factory=dict)
    auth_tokens: dict[str, str] = Field(default_factory=dict)
    csrf_tokens: dict[str, str] = Field(default_factory=dict)
    response_structure_hash: str = ""
    transaction_ids: list[str] = Field(default_factory=list)


class StateTransition(BaseModel):
    """A recorded state change triggered by an HTTP request."""

    from_state: str  # SecurityContext.identity
    to_state: str
    trigger_url: str
    trigger_method: str
    trigger_status: int
    set_cookies: dict[str, str] = Field(default_factory=dict)
    new_endpoints_discovered: int = 0


class FlowSequence(BaseModel):
    """A multi-step sequence (login flow, checkout flow, etc.)."""

    name: str
    steps: list[StateTransition] = Field(default_factory=list)
    total_new_endpoints: int = 0
    requires_credentials: bool = False
    has_side_effects: bool = False


# ---------------------------------------------------------------------------
# Structural hashing (value-blind, structure-only comparison)
# ---------------------------------------------------------------------------

_TAG_RE = re.compile(r"<(\w+)([^>]*)>", re.IGNORECASE)
_JSON_KEY_RE = re.compile(r'"(\w+)"\s*:')


def structural_hash(body: bytes, content_type: str) -> str:
    """Hash the STRUCTURE of a response, ignoring values.

    - JSON: key structure only, values replaced by type
    - HTML: tag skeleton only, text removed
    - Other: content length bucket (1KB granularity)
    """
    if not body:
        return "empty"

    ct = content_type.lower()

    if "json" in ct:
        return _json_structural_hash(body)
    elif "html" in ct:
        return _html_structural_hash(body)
    else:
        # Binary/other: length bucket
        bucket = len(body) // 1024
        return hashlib.sha256(f"bin:{bucket}".encode()).hexdigest()[:12]


def _json_structural_hash(body: bytes) -> str:
    """Extract JSON key structure, replace values with types."""
    try:
        data = json.loads(body)
        skeleton = _json_skeleton(data)
        return hashlib.sha256(json.dumps(skeleton, sort_keys=True).encode()).hexdigest()[:12]
    except (json.JSONDecodeError, UnicodeDecodeError):
        return hashlib.sha256(body[:1024]).hexdigest()[:12]


def _json_skeleton(obj: Any, depth: int = 0) -> Any:
    """Recursively replace values with type names."""
    if depth > 10:
        return "..."
    if isinstance(obj, dict):
        return {k: _json_skeleton(v, depth + 1) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        if obj:
            return [_json_skeleton(obj[0], depth + 1)]
        return []
    elif isinstance(obj, str):
        return "str"
    elif isinstance(obj, bool):
        return "bool"
    elif isinstance(obj, (int, float)):
        return "num"
    elif obj is None:
        return "null"
    return "unknown"


def _html_structural_hash(body: bytes) -> str:
    """Extract HTML tag skeleton, ignoring text content."""
    text = body.decode("utf-8", errors="replace")
    tags = _TAG_RE.findall(text)
    skeleton = ">".join(t[0].lower() for t in tags[:200])
    return hashlib.sha256(skeleton.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# State Merge Logic
# ---------------------------------------------------------------------------


def should_merge(state_a: FullState, state_b: FullState) -> bool:
    """Determine if two states are equivalent for exploration purposes.

    MERGE (ignore difference):
    - CSRF token values changed
    - Timestamps/request IDs changed
    - Same URL, same response structure

    SPLIT (keep separate):
    - Different SecurityContext (auth level, accessible endpoints)
    - Different response status bucket (200 vs 403 = IDOR signal)
    - Different response structure (same URL but different DOM)
    """
    # Layer 0 must match
    if state_a.functional_state.security_context.identity != state_b.functional_state.security_context.identity:
        return False

    # Response structure must match
    if state_a.response_structure_hash != state_b.response_structure_hash:
        return False

    # If both match, merge
    return True


# ---------------------------------------------------------------------------
# State Transition Graph
# ---------------------------------------------------------------------------

# Auth state markers detected in response bodies
_AUTH_MARKERS = [
    (re.compile(r"logged\s+in\s+as", re.I), "authenticated"),
    (re.compile(r"welcome\s+back", re.I), "authenticated"),
    (re.compile(r"my\s+account", re.I), "authenticated"),
    (re.compile(r"sign\s+out|log\s*out", re.I), "authenticated"),
    (re.compile(r"admin\s*(panel|dashboard|console)", re.I), "admin"),
    (re.compile(r"role[\"'\s:=]+[\"']?admin", re.I), "admin"),
    (re.compile(r"sign\s+in|log\s*in", re.I), "anonymous"),
    (re.compile(r"create\s+account|register", re.I), "anonymous"),
]

# Form type identification patterns
_FORM_PATTERNS = {
    "login": {"username", "email", "password", "login", "signin"},
    "register": {"username", "email", "password", "confirm", "register", "signup"},
    "password_reset": {"email", "token", "new_password", "reset"},
    "search": {"q", "query", "search", "keyword"},
    "checkout": {"card", "payment", "cvv", "expiry", "billing"},
}


class StateTransitionGraph:
    """Directed graph tracking web application state transitions.

    Nodes = SecurityContext identities
    Edges = StateTransition (which request caused the transition)
    """

    def __init__(self) -> None:
        self._transitions: list[StateTransition] = []
        self._states: dict[str, SecurityContext] = {}  # identity → SecurityContext
        self._state_endpoints: dict[str, set[str]] = {}  # identity → set of endpoint URLs
        self._current_context: SecurityContext = SecurityContext()
        self._flows: list[FlowSequence] = []

    @property
    def current_context(self) -> SecurityContext:
        return self._current_context

    @property
    def transitions(self) -> list[StateTransition]:
        return list(self._transitions)

    @property
    def flows(self) -> list[FlowSequence]:
        return list(self._flows)

    @property
    def state_count(self) -> int:
        return len(self._states)

    def record_state(self, context: SecurityContext) -> None:
        """Register a known state."""
        self._states[context.identity] = context

    def record_endpoint_for_state(self, state_identity: str, endpoint_url: str) -> None:
        """Record that an endpoint is accessible from a given state."""
        if state_identity not in self._state_endpoints:
            self._state_endpoints[state_identity] = set()
        self._state_endpoints[state_identity].add(endpoint_url)

    def record_transition(
        self,
        before: SecurityContext,
        request: CrawlRequest,
        response: CrawlResponse,
        after: SecurityContext,
    ) -> StateTransition | None:
        """Record a state transition if the state actually changed."""
        if before.identity == after.identity:
            return None

        self.record_state(before)
        self.record_state(after)

        # Count new endpoints
        before_eps = self._state_endpoints.get(before.identity, set())
        after_eps = self._state_endpoints.get(after.identity, set())
        new_count = len(after_eps - before_eps)

        # Extract set-cookies
        set_cookies = {}
        for header_name, header_value in response.headers.items():
            if header_name.lower() == "set-cookie":
                parts = header_value.split("=", 1)
                if len(parts) == 2:
                    cookie_name = parts[0].strip()
                    cookie_val = parts[1].split(";")[0].strip()
                    set_cookies[cookie_name] = cookie_val

        transition = StateTransition(
            from_state=before.identity,
            to_state=after.identity,
            trigger_url=request.url,
            trigger_method=request.method.upper(),
            trigger_status=response.status_code,
            set_cookies=set_cookies,
            new_endpoints_discovered=new_count,
        )
        self._transitions.append(transition)
        return transition

    def record_flow(self, flow: FlowSequence) -> None:
        """Register a discovered multi-step flow."""
        self._flows.append(flow)

    def get_reachable_states(self, from_identity: str) -> list[str]:
        """Get all state identities reachable from a given state."""
        reachable = set()
        stack = [from_identity]
        while stack:
            current = stack.pop()
            for t in self._transitions:
                if t.from_state == current and t.to_state not in reachable:
                    reachable.add(t.to_state)
                    stack.append(t.to_state)
        return list(reachable)

    def get_transition_path(
        self, from_identity: str, to_identity: str
    ) -> list[StateTransition]:
        """Find the shortest transition path between two states (BFS)."""
        if from_identity == to_identity:
            return []

        from collections import deque

        visited: set[str] = {from_identity}
        queue: deque[tuple[str, list[StateTransition]]] = deque([(from_identity, [])])

        while queue:
            current, path = queue.popleft()
            for t in self._transitions:
                if t.from_state == current and t.to_state not in visited:
                    new_path = path + [t]
                    if t.to_state == to_identity:
                        return new_path
                    visited.add(t.to_state)
                    queue.append((t.to_state, new_path))

        return []

    def get_state_specific_endpoints(self, state_identity: str) -> set[str]:
        """Get endpoints accessible ONLY from a specific state (not from anonymous)."""
        target_eps = self._state_endpoints.get(state_identity, set())
        anon_eps = self._state_endpoints.get(
            SecurityContext().identity, set()
        )
        return target_eps - anon_eps

    def detect_auth_level(self, response: CrawlResponse) -> str:
        """Detect auth level from response content markers."""
        body_text = response.body.decode("utf-8", errors="replace")[:10000]
        detected = "anonymous"

        for pattern, level in _AUTH_MARKERS:
            if pattern.search(body_text):
                # "admin" takes priority over "authenticated"
                if level == "admin":
                    return "admin"
                if level == "authenticated":
                    detected = "authenticated"

        return detected

    @staticmethod
    def classify_form(field_names: set[str]) -> str | None:
        """Classify a form by its field names (login, register, checkout, etc.)."""
        field_lower = {f.lower().replace("-", "_") for f in field_names}
        best_match = None
        best_score = 0

        for form_type, keywords in _FORM_PATTERNS.items():
            overlap = len(field_lower & keywords)
            if overlap > best_score:
                best_score = overlap
                best_match = form_type

        return best_match if best_score >= 2 else None

    def get_stats(self) -> dict[str, Any]:
        return {
            "states": self.state_count,
            "transitions": len(self._transitions),
            "flows": len(self._flows),
            "current_auth_level": self._current_context.auth_level,
        }
