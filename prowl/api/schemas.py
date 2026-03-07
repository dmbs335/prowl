"""Pydantic schemas for the LLM orchestration API v1."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


# ── Generic ──────────────────────────────────────────────────────────────────


class PaginatedResponse(BaseModel):
    """Cursor-based pagination wrapper."""

    items: list[Any] = Field(description="Page of results")
    total: int = Field(description="Total matching items")
    offset: int = Field(description="Current offset")
    limit: int = Field(description="Page size")
    has_more: bool = Field(description="Whether more items exist beyond this page")


class ErrorResponse(BaseModel):
    error: str
    detail: str = ""


class OperationResponse(BaseModel):
    status: str = Field(description="Operation result: ok, paused, resumed, stopped, resolved, error")
    message: str = ""


# ── Crawl Lifecycle ──────────────────────────────────────────────────────────


class CrawlStartRequest(BaseModel):
    """Full crawl configuration for programmatic launch."""

    target_url: str = Field(description="Target URL to crawl")
    scope_patterns: list[str] = Field(default_factory=list, description="Regex patterns to include in scope")
    exclude_patterns: list[str] = Field(default_factory=list, description="Regex patterns to exclude from scope")
    max_depth: int = Field(10, ge=1, le=100, description="Maximum crawl depth")
    max_requests: int = Field(10000, ge=1, le=1_000_000, description="Maximum total requests")
    concurrency: int = Field(10, ge=1, le=200, description="Concurrent request workers")
    request_delay: float = Field(0.0, ge=0.0, le=60.0, description="Base delay between requests (seconds)")
    request_timeout: float = Field(30.0, ge=1.0, le=300.0, description="HTTP request timeout (seconds)")
    user_agent: str = Field("Prowl/0.1", description="User-Agent header value")
    follow_redirects: bool = Field(True, description="Follow HTTP redirects")
    backend: Literal["http", "browser", "hybrid"] = Field("hybrid", description="Request backend type")
    headless: bool = Field(True, description="Headless browser mode")
    modules: list[str] = Field(
        default_factory=list,
        description="Modules to run (empty=all). Options: s1_spider, s2_bruteforce, s3_params, "
        "s4_js, s5_api, s6_passive, s7_auth, s8_states, s9_infra, s10_tech, s11_input, "
        "s12_auth, s13_report",
    )
    output_dir: str = Field("./prowl-output", description="Output directory path")
    output_formats: list[str] = Field(default_factory=lambda: ["json"], description="Output formats: json, markdown, html, burp")
    llm_model: str = Field("", description="LLM model name (e.g. gpt-4o-mini)")
    llm_api_key: str = Field("", description="LLM API key")
    coverage_guided: bool = Field(True, description="Enable coverage-guided exploration")
    seed_scheduling: bool = Field(True, description="Enable Thompson Sampling seed scheduling")
    saturation_threshold: float = Field(0.02, description="Coverage saturation threshold")
    wordlist_dirs: str = Field("", description="Path to directory wordlist file")
    wordlist_params: str = Field("", description="Path to parameter wordlist file")
    auth_roles: list[dict[str, Any]] = Field(default_factory=list, description="Auth role configurations")
    noise_filter: bool = Field(True, description="Enable builtin noise URL pattern filtering")
    noise_patterns: list[str] = Field(default_factory=list, description="Additional noise regex patterns to exclude")
    auto_merge_rules: dict[str, int] = Field(default_factory=dict, description="Auto-merge rules: template_pattern -> max_per_template")
    focus_patterns: list[str] = Field(default_factory=list, description="URL substring patterns to boost priority")
    focus_boost: int = Field(10, description="Priority boost for focus pattern matches")
    dashboard: bool = Field(False, description="Enable web dashboard (already running if using API)")
    dashboard_port: int = Field(8484, description="Dashboard port")

    model_config = {"json_schema_extra": {"examples": [
        {
            "target_url": "https://example.com",
            "max_depth": 5,
            "concurrency": 15,
            "modules": ["s6_passive", "s1_spider", "s4_js"],
        }
    ]}}


class CrawlStatusResponse(BaseModel):
    """Full crawl status snapshot."""

    state: str = Field(description="Engine state: idle, running, paused, stopping, stopped")
    target: str = Field(description="Target URL")
    elapsed: float = Field(description="Elapsed time in seconds")
    requests_completed: int
    requests_failed: int
    requests_queued: int
    requests_dropped: int
    queue_size: int
    endpoints_found: int
    unique_urls: int
    transactions_stored: int
    phase_name: str = Field(description="Current phase name")
    current_phase: int = Field(description="Current phase index")
    coverage: dict[str, Any] = Field(description="Coverage bitmap statistics")
    hindsight: dict[str, Any] = Field(description="Hindsight feedback statistics")
    rate_limiter: dict[str, Any] = Field(description="Adaptive rate limiter state")


class PhaseStatusResponse(BaseModel):
    name: str
    state: str = Field(description="Phase state: pending, running, complete, error, skipped")
    modules: list[str]
    depends_on: list[str]
    parallel: bool
    exploration: dict[str, Any] | None = Field(
        None,
        description="Exploration stats: new_coverage, discovery_rate, requests, elapsed",
    )


class ModuleStatusResponse(BaseModel):
    name: str
    state: str = Field(description="Module state: pending, running, complete, error, needs_attention")
    requests_made: int = 0
    endpoints_found: int = 0
    errors: int = 0
    duration_seconds: float = 0.0


# ── Discovery Queries ────────────────────────────────────────────────────────


class ParameterResponse(BaseModel):
    name: str
    location: str = Field(description="Parameter location: query, body, header, cookie, path, graphql_arg")
    sample_values: list[str] = Field(default_factory=list)
    param_type: str = "string"
    required: bool = False
    source_module: str = ""


class EndpointResponse(BaseModel):
    url: str
    method: str
    parameters: list[ParameterResponse] = Field(default_factory=list)
    status_code: int | None = None
    content_type: str = ""
    source_module: str = ""
    depth: int = 0
    tags: list[str] = Field(default_factory=list)
    page_type: str = Field("", description="Page classification: login, error, api_json, admin, static, custom_404")
    requires_auth: bool = False
    input_vector_count: int = 0
    param_count: int = 0
    path_template: str = ""
    fingerprint: str = ""


class InputVectorResponse(BaseModel):
    endpoint_url: str
    name: str
    location: str = Field(description="Input location: query, body, header, cookie, path")
    input_type: str = Field("string", description="Data type: string, integer, file, json, xml")
    is_reflected: bool = Field(False, description="Value appears in response (XSS candidate)")
    sample_values: list[str] = Field(default_factory=list)
    risk_indicators: list[str] = Field(
        default_factory=list,
        description="Risk tags: ssrf_candidate, lfi_candidate, sqli_candidate, cmdi_candidate, ssti_candidate, redirect_candidate",
    )
    source_module: str = ""
    fingerprint: str = ""


class TransactionSummary(BaseModel):
    """HTTP transaction without full bodies (for listing)."""

    id: str
    timestamp: float
    request_method: str
    request_url: str
    response_status: int
    response_content_type: str = ""
    source_module: str = ""
    depth: int = 0
    page_type: str = ""


class TransactionDetail(BaseModel):
    """Full HTTP transaction with headers and body sizes."""

    id: str
    timestamp: float
    request_method: str
    request_url: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body_size: int = 0
    request_content_type: str = ""
    response_status: int
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_size: int = 0
    response_content_type: str = ""
    response_url_final: str = ""
    source_module: str = ""
    depth: int = 0
    page_type: str = ""
    content_hash: str = ""


class TechFingerprintResponse(BaseModel):
    name: str
    version: str = ""
    category: str = Field("", description="Category: framework, server, cms, frontend, waf")
    confidence: float = Field(0.0, description="Detection confidence 0.0-1.0")
    evidence: list[str] = Field(default_factory=list)
    implied_paths: list[str] = Field(default_factory=list, description="Paths implied by this technology")


class SecretResponse(BaseModel):
    kind: str = Field(description="Secret type: api_key, token, password, etc.")
    value: str = Field(description="The secret value")
    source_url: str
    entropy: float = 0.0
    risk_indicators: list[str] = Field(default_factory=list)


class AuthBoundaryResponse(BaseModel):
    url: str
    method: str = "GET"
    unauth_status: int = 0
    auth_status: int = 0
    boundary_type: str = Field("", description="Type: redirect_to_login, 403_forbidden, content_difference")
    access_matrix: dict[str, int] = Field(default_factory=dict, description="Role -> status code mapping")


# ── Mid-Crawl Control ────────────────────────────────────────────────────────


class InjectURLsRequest(BaseModel):
    """Inject URLs into the crawl queue."""

    urls: list[str] = Field(description="URLs to inject")
    source_module: str = Field("api_injection", description="Source label for injected URLs")
    priority: int = Field(15, description="Queue priority (higher = processed sooner)")
    depth: int = Field(0, description="Crawl depth for injected URLs")
    auth_role: str | None = Field(None, description="Auth role to use for these requests")


class InjectURLsResponse(BaseModel):
    accepted: int = Field(description="URLs accepted into queue")
    rejected_out_of_scope: int = Field(description="URLs rejected (out of scope)")
    rejected_duplicate: int = Field(description="URLs rejected (already seen)")
    rejected_depth: int = Field(description="URLs rejected (exceeds max depth)")


class ScopeUpdateRequest(BaseModel):
    """Add include/exclude patterns to the crawl scope."""

    add_include_patterns: list[str] = Field(default_factory=list, description="Regex patterns to add to include list")
    add_exclude_patterns: list[str] = Field(default_factory=list, description="Regex patterns to add to exclude list")


class ScopeResponse(BaseModel):
    target_host: str
    include_patterns: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=list)


class SessionInjectRequest(BaseModel):
    """Inject authentication session data."""

    role: str = Field("default", description="Auth role name")
    cookies: dict[str, str] = Field(default_factory=dict, description="Cookies to inject")
    headers: dict[str, str] = Field(default_factory=dict, description="Headers to inject (e.g. Authorization)")
    token: str = Field("", description="Bearer token to inject as Authorization header")


class ConfigUpdateRequest(BaseModel):
    """Hot-update mutable configuration fields mid-crawl."""

    max_depth: int | None = Field(None, description="Update max crawl depth")
    max_requests: int | None = Field(None, description="Update max total requests")
    request_delay: float | None = Field(None, description="Update base request delay")
    saturation_threshold: float | None = Field(None, description="Update saturation detection threshold")
    user_agent: str | None = Field(None, description="Update User-Agent header")


class QueueStatsResponse(BaseModel):
    queue_size: int = Field(description="Current queue size")
    total_queued: int = Field(description="Total URLs queued since start")
    total_dropped: int = Field(description="Total URLs dropped (dedup)")


# ── Interventions ─────────────────────────────────────────────────────────────


class InterventionResponse(BaseModel):
    id: str
    kind: str = Field(description="Intervention type: login, captcha, two_fa, manual")
    message: str
    module: str
    state: str = Field(description="State: pending, in_progress, resolved, expired")
    data: dict[str, Any] = Field(default_factory=dict)


class ResolveInterventionRequest(BaseModel):
    """Provide auth data to resolve an intervention."""

    cookies: dict[str, str] = Field(default_factory=dict, description="Session cookies")
    headers: dict[str, str] = Field(default_factory=dict, description="Auth headers")
    token: str = Field("", description="Bearer token")
    credentials: dict[str, str] = Field(default_factory=dict, description="Login credentials (username, password)")
    extra_data: dict[str, Any] = Field(default_factory=dict, description="Additional resolution data")


# ── Reports ───────────────────────────────────────────────────────────────────


class RiskSummaryResponse(BaseModel):
    total_endpoints: int = 0
    total_input_vectors: int = 0
    high_risk_vectors: int = Field(0, description="Input vectors with risk indicators (ssrf, sqli, cmdi, etc.)")
    auth_boundaries_found: int = 0
    unprotected_admin_paths: int = 0
    exposed_debug_endpoints: int = 0
    secrets_found: int = 0
    score: float = Field(0.0, description="Composite risk score 0-100")


class AttackSurfaceSummaryResponse(BaseModel):
    """High-level attack surface summary for LLM triage."""

    target: str
    scan_duration: float
    risk_summary: RiskSummaryResponse
    endpoint_count: int
    input_vector_count: int
    tech_count: int
    secret_count: int
    auth_boundary_count: int
    api_schema_count: int


class HighRiskFindingsResponse(BaseModel):
    """Consolidated high-risk findings for LLM prioritization."""

    high_risk_input_vectors: list[InputVectorResponse] = Field(default_factory=list)
    unprotected_admin_endpoints: list[EndpointResponse] = Field(default_factory=list)
    exposed_debug_endpoints: list[EndpointResponse] = Field(default_factory=list)
    secrets: list[SecretResponse] = Field(default_factory=list)


class ExplorationStatsResponse(BaseModel):
    """Coverage and exploration strategy statistics."""

    coverage: dict[str, Any] = Field(description="Coverage bitmap stats")
    hindsight: dict[str, Any] = Field(description="Hindsight feedback stats")
    rate_limiter: dict[str, Any] = Field(description="Adaptive rate limiter state")
    phase_exploration: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Per-phase exploration: new_coverage, discovery_rate, requests, elapsed",
    )
    module_stats: dict[str, dict[str, Any]] = Field(default_factory=dict, description="Per-module statistics")


# ── Orchestration: Request Merging ────────────────────────────────────────────


class MergeRequestsRequest(BaseModel):
    """Merge queued requests by template grouping strategy."""

    strategy: Literal["combine_params", "sample_template", "batch_endpoints"] = Field(
        description="Merge strategy. combine_params: merge query params for same template. "
        "sample_template: keep N representatives per template. "
        "batch_endpoints: collapse to one request per template."
    )
    url_pattern: str = Field("", description="Optional URL substring filter (only merge matching requests)")
    sample_size: int = Field(3, description="For sample_template: how many representatives to keep per template")


class MergeCandidateResponse(BaseModel):
    """A group of requests that can be merged."""

    template: str = Field(description="Normalized URL template (e.g. /api/users/{id})")
    request_count: int = Field(description="Number of requests in this group")
    sample_urls: list[str] = Field(description="Example URLs from this group (up to 5)")
    methods: list[str] = Field(description="HTTP methods seen in this group")


class MergePreviewResponse(BaseModel):
    """Dry-run result showing what would be merged."""

    candidates: list[MergeCandidateResponse] = Field(description="Merge candidate groups")
    total_before: int = Field(description="Total queue size before merge")
    total_after: int = Field(description="Estimated queue size after merge")
    reduction_pct: float = Field(description="Estimated reduction percentage")


class MergeResultResponse(BaseModel):
    """Result of an executed merge operation."""

    merged_groups: int = Field(description="Number of template groups merged")
    requests_before: int = Field(description="Queue size before merge")
    requests_after: int = Field(description="Queue size after merge")
    reduction_pct: float = Field(description="Actual reduction percentage")


# ── Orchestration: Credential Management ─────────────────────────────────────


class AutoLoginRequest(BaseModel):
    """Perform automated login to obtain session cookies."""

    login_url: str = Field(description="URL of the login page/form")
    username: str = Field(description="Login username or email")
    password: str = Field(description="Login password")
    role: str = Field("default", description="Auth role name to register session under")
    extra_fields: dict[str, str] = Field(
        default_factory=dict,
        description="Additional form fields to submit (e.g. CSRF token, remember_me)",
    )


class LoginResultResponse(BaseModel):
    """Result of an auto-login attempt."""

    success: bool = Field(description="Whether login succeeded")
    role: str = Field(description="Auth role name")
    cookies_obtained: int = Field(0, description="Number of cookies obtained from login")
    message: str = Field("", description="Human-readable result message")


class RoleStatusResponse(BaseModel):
    """Status of a registered auth role and its sessions."""

    name: str = Field(description="Role name")
    is_active: bool = Field(description="Whether the role has active sessions")
    has_credentials: bool = Field(description="Whether stored credentials exist for re-auth")
    session_count: int = Field(description="Total sessions for this role")
    valid_sessions: int = Field(description="Currently valid sessions")
    cookies_count: int = Field(description="Number of cookies stored")
    last_used: float = Field(0.0, description="Epoch timestamp of last use")
    total_requests: int = Field(0, description="Total requests made with this role")


class ReauthRequest(BaseModel):
    """Re-authenticate an existing role using stored credentials."""

    role: str = Field(description="Role name to re-authenticate")


# ── Orchestration: LLM Decision Support ──────────────────────────────────────


class TemplateProductivity(BaseModel):
    """Thompson Sampling stats for a URL template."""

    template: str = Field(description="Normalized URL template")
    alpha: int = Field(description="Coverage hits (successes)")
    beta: int = Field(description="No-coverage hits (failures)")
    hit_rate: float = Field(description="alpha / (alpha + beta)")


class DecisionContextSnapshot(BaseModel):
    """All-in-one context snapshot for LLM orchestrator decision-making.

    Call this endpoint once per decision cycle to get everything needed.
    """

    # Engine state
    crawl_state: str = Field(description="Engine state: idle, running, paused, stopping, stopped")
    elapsed: float = Field(description="Elapsed time in seconds")
    target: str = Field(description="Target URL")
    phase_name: str = Field(description="Current pipeline phase name")
    current_phase: int = Field(description="Current phase index")

    # Progress
    requests_completed: int
    requests_failed: int
    queue_size: int
    endpoints_found: int

    # Coverage intelligence
    coverage_unique: int = Field(description="Unique coverage tuples discovered")
    coverage_discovery_rate: float = Field(description="Fraction of recent requests producing new coverage")
    coverage_saturated: bool = Field(description="Whether coverage is saturated (below threshold)")

    # Queue pressure
    queue_total_queued: int = Field(description="Total URLs ever queued")
    queue_total_dropped: int = Field(description="Total URLs dropped by dedup")

    # Auth status
    active_roles: list[str] = Field(description="Names of active auth roles")
    pending_interventions: int = Field(description="Number of pending interventions")

    # Exploration intelligence
    top_productive_templates: list[TemplateProductivity] = Field(
        description="Top 20 templates ranked by Thompson Sampling alpha"
    )
    under_explored_areas: list[TemplateProductivity] = Field(
        description="Top 20 templates with high beta / low alpha (under-explored)"
    )
    method_hints: list[dict[str, Any]] = Field(
        default_factory=list,
        description="405 responses with Allow headers suggesting untested methods",
    )

    # Module performance
    module_discovery_rates: dict[str, float] = Field(
        description="Per-module: endpoints_found / requests_made ratio"
    )

    # Rate limiter
    rate_limiter_delay: float = Field(description="Current adaptive delay in seconds")
    rate_limiter_backoffs: int = Field(description="Total 429 backoffs since start")


class StrategyAdjustRequest(BaseModel):
    """Adjust crawl strategy mid-run: module weights and focus areas."""

    module_weights: dict[str, float] = Field(
        default_factory=dict,
        description="Module name -> priority weight multiplier (e.g. {'s1_spider': 1.5})",
    )
    focus_patterns: list[str] = Field(
        default_factory=list,
        description="URL substring patterns to boost priority for",
    )
    focus_boost: int = Field(10, description="Priority boost added to requests matching focus patterns")
    depth_override: int | None = Field(None, description="Override max crawl depth")


class EndpointClusterItem(BaseModel):
    """A cluster of endpoints sharing the same URL template."""

    template: str = Field(description="Normalized URL template")
    count: int = Field(description="Number of endpoints in this cluster")
    methods: list[str] = Field(description="HTTP methods seen")
    param_names: list[str] = Field(description="Union of parameter names across cluster")
    coverage_alpha: int = Field(0, description="Thompson Sampling alpha (coverage hits)")
    coverage_beta: int = Field(0, description="Thompson Sampling beta (no-coverage hits)")
    sample_urls: list[str] = Field(description="Up to 5 sample URLs")
    has_auth_boundary: bool = Field(False, description="Whether any endpoint has auth boundary")


class EndpointClusterResponse(BaseModel):
    """Endpoints grouped by URL template for efficient analysis."""

    clusters: list[EndpointClusterItem] = Field(description="Endpoint clusters sorted by count descending")
    total_endpoints: int = Field(description="Total endpoints across all clusters")
    total_templates: int = Field(description="Number of unique templates")


class CoverageGapItem(BaseModel):
    """A specific coverage gap with suggested remediation."""

    gap_type: str = Field(
        description="Gap type: untested_method, auth_boundary, unspidered, low_coverage"
    )
    url: str = Field(description="URL or template affected")
    detail: str = Field(description="Human-readable explanation of the gap")
    suggested_action: str = Field(description="Suggested action to close the gap")


class CoverageGapsResponse(BaseModel):
    """Coverage gap analysis for targeted exploration."""

    gaps: list[CoverageGapItem] = Field(description="Coverage gaps sorted by impact")
    total_gaps: int = Field(description="Total number of gaps found")


class ReprioritizeRule(BaseModel):
    """A single reprioritization rule."""

    url_pattern: str = Field(description="URL substring to match")
    new_priority: int = Field(description="New priority value (higher = processed sooner)")


class ReprioritizeRequest(BaseModel):
    """Reprioritize queued requests by URL pattern matching."""

    rules: list[ReprioritizeRule] = Field(description="Reprioritization rules to apply")


class QueueRemoveRequest(BaseModel):
    """Remove queued requests matching URL patterns."""

    url_patterns: list[str] = Field(description="URL substrings to match for removal")


class QueueItemResponse(BaseModel):
    """A single queued request."""

    url: str = Field(description="Request URL")
    method: str = Field(description="HTTP method")
    priority: int = Field(description="Queue priority (higher = sooner)")
    depth: int = Field(0, description="Crawl depth")
    source_module: str = Field("", description="Module that generated this request")
    auth_role: str | None = Field(None, description="Auth role for this request")


class QueueItemsResponse(BaseModel):
    """Paginated queue items."""

    items: list[QueueItemResponse] = Field(description="Queue items")
    total: int = Field(description="Total items in queue")
    offset: int = Field(description="Current offset")
    limit: int = Field(description="Page size")


class QueueDetailedStatsResponse(BaseModel):
    """Detailed queue statistics for C&C dashboard."""

    queue_size: int = Field(description="Current queue size")
    total_queued: int = Field(description="Total URLs queued since start")
    total_dropped: int = Field(description="Total URLs dropped (dedup)")
    total_auto_merged: int = Field(0, description="Total items dropped by auto-merge rules")
    active_requests: int = Field(description="In-flight requests currently being processed")
    is_paused: bool = Field(description="Whether queue processing is paused")
    by_source: dict[str, int] = Field(default_factory=dict, description="Queue size by source module")
    by_priority: dict[str, int] = Field(default_factory=dict, description="Queue size by priority band")


class AutoMergeRuleRequest(BaseModel):
    """Add an auto-merge rule: drop URLs when per-template count exceeds max."""

    pattern: str = Field(description="URL template pattern (exact match or trailing * for prefix)")
    max_per_template: int = Field(3, description="Maximum queued items per matching template")


class AutoMergeRulesResponse(BaseModel):
    """Active auto-merge rules."""

    rules: dict[str, int] = Field(description="Pattern -> max count mapping")
    total_auto_merged: int = Field(0, description="Total items dropped by auto-merge this session")


class HypothesisTestRequest(BaseModel):
    """Inject targeted test requests based on a hypothesis about the application."""

    hypothesis: str = Field(description="Text description of the hypothesis (for logging)")
    test_urls: list[str] = Field(default_factory=list, description="Specific URLs to test")
    methods: list[str] = Field(
        default_factory=lambda: ["GET"],
        description="HTTP methods to use for each test URL",
    )
    priority: int = Field(20, description="Priority for injected requests (higher = sooner)")
    auth_role: str | None = Field(None, description="Auth role to use for test requests")


# ── Playbook ──────────────────────────────────────────────────────────────────


class PlaybookFinding(BaseModel):
    """A single quality finding from a playbook play."""

    play: str = Field(description="Play identifier: P1_completeness, P2_auth, P3_semantics, etc.")
    severity: Literal["info", "warn", "fail"] = Field(description="Finding severity")
    title: str = Field(description="One-line summary")
    detail: str = Field(description="Detailed explanation")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Supporting data (URLs, counts, etc.)")
    auto_action: str = Field("", description="Corrective action taken automatically (if any)")


class NextCrawlHint(BaseModel):
    """Suggested configuration change for the next crawl or remaining phases."""

    action: str = Field(description="Hint type: fix_auth, add_seeds, enable_module, increase_depth, focus_area")
    description: str = Field(description="Human-readable recommendation")
    config_patch: dict[str, Any] = Field(default_factory=dict, description="Suggested CrawlConfig field overrides")


class PlaybookResult(BaseModel):
    """Accumulated playbook results across all phase checkpoints."""

    target: str = Field(description="Crawl target URL")
    timestamp: float = Field(description="Result generation epoch timestamp")
    plays_run: int = Field(description="Total play executions (may exceed 8 if plays re-trigger)")
    findings: list[PlaybookFinding] = Field(default_factory=list, description="All findings across all plays")
    hints: list[NextCrawlHint] = Field(default_factory=list, description="Configuration hints derived from findings")
    summary: dict[str, int] = Field(default_factory=dict, description="Severity counts: {info: N, warn: N, fail: N}")
    phases_checked: list[str] = Field(default_factory=list, description="Phases after which playbook ran")


# ── WebSocket ─────────────────────────────────────────────────────────────────


class WSEvent(BaseModel):
    """Structured WebSocket event envelope."""

    event_type: str = Field(description="Event type (e.g. endpoint.found, phase.started)")
    timestamp: float
    data: dict[str, Any] = Field(default_factory=dict)
