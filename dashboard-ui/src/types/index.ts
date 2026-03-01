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

export interface Intervention {
  id: string;
  kind: "login" | "captcha" | "2fa" | "manual";
  message: string;
  module: string;
  state: "pending" | "in_progress" | "resolved" | "expired";
  data: Record<string, unknown>;
}

export interface CrawlStats {
  total_endpoints: number;
  total_params: number;
  total_secrets: number;
  total_js_files: number;
  requests_completed: number;
  requests_failed: number;
  elapsed: number;
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

/** WebSocket message types */
export type WSMessage =
  | {
      type: "module_state";
      module: string;
      state: ModuleState;
      stats: ModuleStats;
    }
  | { type: "endpoint_found"; endpoint: Endpoint }
  | {
      type: "intervention_requested";
      id: string;
      kind: string;
      message: string;
    }
  | { type: "intervention_resolved"; id: string }
  | { type: "stats_update"; stats: CrawlStats }
  | { type: "log"; level: string; module: string; message: string; ts: number }
  | { type: "phase_changed"; phase: number; name: string }
  | {
      type: "initial_state";
      modules: Record<string, ModuleInfo>;
      stats: CrawlStats;
      endpoint_count: number;
      logs: LogEntry[];
    };
