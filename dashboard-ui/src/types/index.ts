/** Types matching Python Pydantic models */

export type ModuleState =
  | "pending"
  | "running"
  | "complete"
  | "error"
  | "needs_attention";

export interface ModuleStats {
  requests_made: number;
  endpoints_found: number;
  errors: number;
  // Module-specific extended stats (params_found, forms_identified, etc.)
  [key: string]: number | string | Record<string, unknown> | undefined;
}

export interface ModuleInfo {
  state: ModuleState;
  stats: ModuleStats;
}

export interface Endpoint {
  url: string;
  method: string;
  status_code: number | null;
  content_type: string;
  source_module: string;
  param_count: number;
  tags: string[];
}

export interface TechFingerprint {
  name: string;
  version: string;
  category: string;
  confidence: number;
  evidence: string[];
}

export interface InputVector {
  endpoint_url: string;
  name: string;
  location: string;
  input_type: string;
  is_reflected: boolean;
  sample_values: string[];
  risk_indicators: string[];
  source_module: string;
}

export interface AuthBoundary {
  url: string;
  method: string;
  unauth_status: number;
  auth_status: number | null;
  boundary_type: string;
  access_matrix: Record<string, number>;
}

export interface RiskSummary {
  total_endpoints: number;
  total_input_vectors: number;
  high_risk_vectors: number;
  auth_boundaries_found: number;
  unprotected_admin_paths: number;
  exposed_debug_endpoints: number;
  secrets_found: number;
  score: number;
}

export interface Intervention {
  id: string;
  kind: "login" | "captcha" | "2fa" | "manual";
  message: string;
  module: string;
  state: "pending" | "in_progress" | "resolved" | "expired";
  data: Record<string, unknown>;
}

export interface CoverageStats {
  total_bits: number;
  set_bits: number;
  coverage_pct: number;
}

export interface RateLimiterStats {
  current_delay: number;
  total_backoffs: number;
  consecutive_ok: number;
}

export interface CrawlStats {
  total_endpoints: number;
  total_params: number;
  total_secrets: number;
  total_js_files: number;
  requests_completed: number;
  requests_failed: number;
  elapsed: number;
  // Extended stats from engine
  requests_queued?: number;
  requests_dropped?: number;
  queue_size?: number;
  endpoints_found?: number;
  unique_urls?: number;
  transactions_stored?: number;
  state?: string;
  coverage?: CoverageStats;
  hindsight?: Record<string, unknown>;
  rate_limiter?: RateLimiterStats;
}

export interface LogEntry {
  level: string;
  module: string;
  message: string;
  ts: number;
}

export interface SitemapNode {
  name: string;
  children: SitemapNode[];
  endpoints: Endpoint[];
  count: number;
}

// ── Orchestration types ──────────────────────────────────────────────────────

export interface QueueItem {
  url: string;
  method: string;
  priority: number;
  depth: number;
  source_module: string;
  auth_role: string | null;
}

export interface QueueDetailedStats {
  queue_size: number;
  total_queued: number;
  total_dropped: number;
  total_auto_merged: number;
  active_requests: number;
  is_paused: boolean;
  by_source: Record<string, number>;
  by_priority: Record<string, number>;
}

export interface AutoMergeRules {
  rules: Record<string, number>;
  total_auto_merged: number;
}

export interface MergeCandidate {
  template: string;
  request_count: number;
  sample_urls: string[];
  methods: string[];
}

export interface RoleStatus {
  name: string;
  is_active: boolean;
  has_credentials: boolean;
  session_count: number;
  valid_sessions: number;
  cookies_count: number;
  last_used: number;
  total_requests: number;
}

export interface TemplateProductivity {
  template: string;
  alpha: number;
  beta: number;
  hit_rate: number;
}

export interface DecisionContext {
  crawl_state: string;
  elapsed: number;
  target: string;
  phase_name: string;
  current_phase: number;
  requests_completed: number;
  requests_failed: number;
  queue_size: number;
  endpoints_found: number;
  coverage_unique: number;
  coverage_discovery_rate: number;
  coverage_saturated: boolean;
  queue_total_queued: number;
  queue_total_dropped: number;
  active_roles: string[];
  pending_interventions: number;
  top_productive_templates: TemplateProductivity[];
  under_explored_areas: TemplateProductivity[];
  method_hints: Array<{ url: string; method: string; detail: string }>;
  module_discovery_rates: Record<string, number>;
  rate_limiter_delay: number;
  rate_limiter_backoffs: number;
}

export interface EndpointCluster {
  template: string;
  count: number;
  methods: string[];
  param_names: string[];
  coverage_alpha: number;
  coverage_beta: number;
  sample_urls: string[];
  has_auth_boundary: boolean;
}

export interface CoverageGap {
  gap_type: string;
  url: string;
  detail: string;
  suggested_action: string;
}

// ── Playbook types ───────────────────────────────────────────────────────────

export interface PlaybookFinding {
  play: string;
  severity: "info" | "warn" | "fail";
  title: string;
  detail: string;
  evidence: Record<string, unknown>;
  auto_action: string;
}

export interface NextCrawlHint {
  action: string;
  description: string;
  config_patch: Record<string, unknown>;
}

export interface PlaybookResult {
  target: string;
  timestamp: number;
  plays_run: number;
  findings: PlaybookFinding[];
  hints: NextCrawlHint[];
  summary: Record<string, number>;
  phases_checked: string[];
}

/** WebSocket message types */
export type WSMessage =
  | {
      type: "module_state";
      module: string;
      state: ModuleState;
      stats: ModuleStats;
    }
  | { type: "endpoint_found"; endpoint: Endpoint }
  | { type: "tech_detected"; tech: TechFingerprint }
  | { type: "input_vector_found"; input_vector: InputVector }
  | { type: "auth_boundary_found"; boundary: AuthBoundary }
  | {
      type: "intervention_requested";
      id: string;
      kind: string;
      message: string;
    }
  | { type: "intervention_resolved"; id: string }
  | { type: "queue_merged"; merged_groups: number; reduction_pct: number }
  | { type: "auth_login_result"; role: string; success: boolean; message: string }
  | { type: "strategy_adjusted"; detail: string }
  | { type: "stats_update"; stats: CrawlStats }
  | { type: "log"; level: string; module: string; message: string; ts: number }
  | { type: "phase_changed"; phase: number; name: string }
  | {
      type: "initial_state";
      target: string;
      modules: Record<string, ModuleInfo>;
      stats: CrawlStats;
      endpoints: Endpoint[];
      endpoint_count: number;
      logs: LogEntry[];
      phase_name: string;
      current_phase: number;
      tech_stack?: TechFingerprint[];
      input_vectors?: InputVector[];
      auth_boundaries?: AuthBoundary[];
    };
