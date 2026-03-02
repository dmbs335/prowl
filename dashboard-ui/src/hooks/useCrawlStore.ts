import { create } from "zustand";
import type {
  AuthBoundary,
  AutoMergeRules,
  CoverageGap,
  CrawlStats,
  DecisionContext,
  Endpoint,
  EndpointCluster,
  InputVector,
  Intervention,
  LogEntry,
  MergeCandidate,
  ModuleInfo,
  ModuleState,
  ModuleStats,
  PlaybookResult,
  QueueDetailedStats,
  QueueItem,
  RiskSummary,
  RoleStatus,
  TechFingerprint,
} from "../types";
import {
  saveSession,
  listSessions,
  loadSession,
  deleteSession,
  type SessionMeta,
} from "../lib/sessionDB";

interface CrawlStore {
  // Target
  target: string;

  // Pipeline state
  modules: Record<string, ModuleInfo>;
  currentPhase: number;
  phaseName: string;

  // Endpoints
  endpoints: Endpoint[];

  // Interventions
  interventions: Intervention[];

  // WebSocket connection
  connected: boolean;
  _liveMode: boolean;

  // Attack surface data
  techStack: TechFingerprint[];
  inputVectors: InputVector[];
  authBoundaries: AuthBoundary[];
  riskSummary: RiskSummary | null;

  // Orchestration state
  decisionContext: DecisionContext | null;
  endpointClusters: EndpointCluster[];
  coverageGaps: CoverageGap[];
  authRoles: RoleStatus[];
  mergePreview: MergeCandidate[] | null;
  playbookResult: PlaybookResult | null;
  queueItems: QueueItem[];
  queueStats: QueueDetailedStats | null;
  autoMergeRules: AutoMergeRules | null;

  // UI state
  activeView: "pipeline" | "sitemap" | "endpoints" | "graph" | "attack-surface" | "command-center";
  selectedNode: string | null;

  // Stats & logs
  stats: CrawlStats;
  logs: LogEntry[];

  // Timer
  startTime: number;

  // Actions
  setTarget: (target: string) => void;
  setConnected: (connected: boolean) => void;
  setModuleState: (
    module: string,
    state: ModuleState,
    stats?: ModuleStats
  ) => void;
  addEndpoint: (endpoint: Endpoint) => void;
  addTech: (tech: TechFingerprint) => void;
  addInputVector: (iv: InputVector) => void;
  addAuthBoundary: (ab: AuthBoundary) => void;
  addIntervention: (intervention: Intervention) => void;
  resolveIntervention: (id: string) => void;
  updateStats: (stats: Partial<CrawlStats>) => void;
  addLog: (entry: LogEntry) => void;
  setActiveView: (view: "pipeline" | "sitemap" | "endpoints" | "graph" | "attack-surface" | "command-center") => void;

  // Orchestration actions
  fetchDecisionContext: () => Promise<void>;
  fetchEndpointClusters: () => Promise<void>;
  fetchCoverageGaps: () => Promise<void>;
  fetchAuthRoles: () => Promise<void>;
  fetchPlaybookResults: () => Promise<void>;
  fetchMergePreview: (strategy: string, urlPattern?: string) => Promise<void>;
  fetchQueueItems: (offset?: number, limit?: number) => Promise<void>;
  fetchQueueStats: () => Promise<void>;
  pauseQueue: () => Promise<string>;
  resumeQueue: () => Promise<string>;
  clearQueue: () => Promise<string>;
  performLogin: (loginUrl: string, username: string, password: string, role?: string) => Promise<boolean>;
  mergeQueue: (strategy: string, urlPattern?: string, sampleSize?: number) => Promise<void>;
  reprioritizeQueue: (rules: Array<{ url_pattern: string; new_priority: number }>) => Promise<void>;
  removeFromQueue: (urlPatterns: string[]) => Promise<string>;
  fetchAutoMergeRules: () => Promise<void>;
  addAutoMergeRule: (pattern: string, maxPerTemplate: number) => Promise<string>;
  removeAutoMergeRule: (pattern: string) => Promise<string>;
  adjustStrategy: (moduleWeights: Record<string, number>, focusPatterns: string[], focusBoost?: number) => Promise<void>;
  testHypothesis: (hypothesis: string, testUrls: string[], methods: string[], priority?: number, authRole?: string) => Promise<string>;
  setSelectedNode: (nodeId: string | null) => void;
  setPhase: (phase: number, name: string) => void;
  initState: (
    target: string,
    modules: Record<string, ModuleInfo>,
    stats: CrawlStats,
    endpoints: Endpoint[],
    logs: LogEntry[],
    phaseName: string,
    currentPhase: number,
    techStack?: TechFingerprint[],
    inputVectors?: InputVector[],
    authBoundaries?: AuthBoundary[],
  ) => void;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  loadReport: (data: any, name?: string, skipSave?: boolean) => void;

  // Session management
  sessions: SessionMeta[];
  currentSessionId: string | null;
  refreshSessions: () => Promise<void>;
  loadSessionById: (id: string) => Promise<void>;
  deleteSessionById: (id: string) => Promise<void>;
}

export const useCrawlStore = create<CrawlStore>((set) => ({
  target: "",
  modules: {
    s6_passive: { state: "pending", stats: {} as ModuleStats },
    s1_spider: { state: "pending", stats: {} as ModuleStats },
    s2_bruteforce: { state: "pending", stats: {} as ModuleStats },
    s4_js: { state: "pending", stats: {} as ModuleStats },
    s5_api: { state: "pending", stats: {} as ModuleStats },
    s7_auth: { state: "pending", stats: {} as ModuleStats },
    s3_params: { state: "pending", stats: {} as ModuleStats },
    s8_states: { state: "pending", stats: {} as ModuleStats },
    s9_infra: { state: "pending", stats: {} as ModuleStats },
    s10_tech: { state: "pending", stats: {} as ModuleStats },
    s11_input: { state: "pending", stats: {} as ModuleStats },
    s12_auth: { state: "pending", stats: {} as ModuleStats },
    s13_report: { state: "pending", stats: {} as ModuleStats },
  },
  currentPhase: 0,
  phaseName: "",
  endpoints: [],
  techStack: [],
  inputVectors: [],
  authBoundaries: [],
  riskSummary: null,
  decisionContext: null,
  endpointClusters: [],
  coverageGaps: [],
  authRoles: [],
  mergePreview: null,
  playbookResult: null,
  queueItems: [],
  queueStats: null,
  autoMergeRules: null,
  interventions: [],
  connected: false,
  _liveMode: false,
  activeView: "pipeline",
  selectedNode: null,
  startTime: Date.now(),
  stats: {
    total_endpoints: 0,
    total_params: 0,
    total_secrets: 0,
    total_js_files: 0,
    requests_completed: 0,
    requests_failed: 0,
    elapsed: 0,
  },
  logs: [],
  sessions: [],
  currentSessionId: null,

  setTarget: (target) => set({ target }),
  setConnected: (connected) => set({ connected }),

  setModuleState: (module, state, stats) =>
    set((s) => ({
      modules: {
        ...s.modules,
        [module]: { state, stats: stats || s.modules[module]?.stats || ({} as ModuleStats) },
      },
    })),

  addEndpoint: (endpoint) =>
    set((s) => ({ endpoints: [...s.endpoints, endpoint] })),

  addTech: (tech) =>
    set((s) => {
      const idx = s.techStack.findIndex((t) => t.name.toLowerCase() === tech.name.toLowerCase());
      if (idx >= 0) {
        const updated = [...s.techStack];
        updated[idx] = {
          ...updated[idx],
          confidence: Math.max(updated[idx].confidence, tech.confidence),
          evidence: [...new Set([...updated[idx].evidence, ...tech.evidence])],
        };
        return { techStack: updated };
      }
      return { techStack: [...s.techStack, tech] };
    }),

  addInputVector: (iv) =>
    set((s) => ({ inputVectors: [...s.inputVectors, iv] })),

  addAuthBoundary: (ab) =>
    set((s) => ({ authBoundaries: [...s.authBoundaries, ab] })),

  addIntervention: (intervention) =>
    set((s) => ({ interventions: [...s.interventions, intervention] })),

  resolveIntervention: (id) =>
    set((s) => ({
      interventions: s.interventions.map((i) =>
        i.id === id ? { ...i, state: "resolved" as const } : i
      ),
    })),

  updateStats: (stats) =>
    set((s) => ({ stats: { ...s.stats, ...stats } })),

  addLog: (entry) =>
    set((s) => ({ logs: [...s.logs.slice(-199), entry] })),

  setActiveView: (view) => set({ activeView: view }),
  setSelectedNode: (nodeId) => set({ selectedNode: nodeId }),

  setPhase: (phase, name) =>
    set({ currentPhase: phase, phaseName: name }),

  initState: (target, modules, stats, endpoints, logs, phaseName, currentPhase, techStack, inputVectors, authBoundaries) =>
    set({
      target, modules, stats, endpoints, logs, phaseName, currentPhase,
      startTime: Date.now(), _liveMode: true,
      techStack: techStack || [], inputVectors: inputVectors || [], authBoundaries: authBoundaries || [],
    }),

  loadReport: (data, name, skipSave) => {
    // Map report endpoints → store Endpoint type
    const endpoints: Endpoint[] = (data.endpoints || []).map(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (ep: any) => ({
        url: ep.url,
        method: ep.method,
        status_code: ep.status_code ?? null,
        content_type: ep.content_type || "",
        source_module: ep.source_module || "",
        param_count: Array.isArray(ep.parameters) ? ep.parameters.length : 0,
        tags: ep.tags || [],
      })
    );

    // Map module_reports → modules Record
    const modules: Record<string, ModuleInfo> = {};
    const moduleNames = [
      "s6_passive", "s1_spider", "s2_bruteforce", "s4_js", "s5_api",
      "s7_auth", "s3_params", "s8_states", "s9_infra", "s10_tech",
      "s11_input", "s12_auth", "s13_report",
    ];
    for (const n of moduleNames) {
      modules[n] = { state: "pending", stats: { requests_made: 0, endpoints_found: 0, errors: 0 } };
    }
    for (const mr of data.module_reports || []) {
      const key = mr.module_name;
      if (key in modules) {
        // Preserve all stats fields (including module-specific ones like params_found, forms_identified)
        const allStats: ModuleStats = {
          requests_made: mr.requests_made || 0,
          endpoints_found: mr.endpoints_found || 0,
          errors: mr.errors || 0,
        };
        for (const [k, v] of Object.entries(mr)) {
          if (!["module_name", "module", "requests_made", "endpoints_found", "errors", "duration_seconds"].includes(k)) {
            allStats[k] = v as number | string | Record<string, unknown>;
          }
        }
        modules[key] = { state: "complete", stats: allStats };
      }
    }

    // Compute stats
    let totalRequests = 0;
    let totalErrors = 0;
    for (const mr of data.module_reports || []) {
      totalRequests += mr.requests_made || 0;
      totalErrors += mr.errors || 0;
    }

    const stats: CrawlStats = {
      total_endpoints: endpoints.length,
      total_params: endpoints.reduce((sum, ep) => sum + ep.param_count, 0),
      total_secrets: (data.secrets || []).length,
      total_js_files: 0,
      requests_completed: totalRequests,
      requests_failed: totalErrors,
      elapsed: data.scan_duration || 0,
      state: "completed",
    };

    // Parse attack surface data
    const techStack: TechFingerprint[] = (data.tech_stack || []).map((t: any) => ({
      name: t.name, version: t.version || "", category: t.category || "",
      confidence: t.confidence || 0, evidence: t.evidence || [],
    }));
    const inputVectors: InputVector[] = (data.input_vectors || []).map((iv: any) => ({
      endpoint_url: iv.endpoint_url, name: iv.name,
      location: iv.location || "query", input_type: iv.input_type || "string",
      is_reflected: iv.is_reflected || false, sample_values: iv.sample_values || [],
      risk_indicators: iv.risk_indicators || [], source_module: iv.source_module || "",
    }));
    const authBoundaries: AuthBoundary[] = (data.auth_boundaries || []).map((ab: any) => ({
      url: ab.url, method: ab.method || "GET",
      unauth_status: ab.unauth_status || 0, auth_status: ab.auth_status ?? null,
      boundary_type: ab.boundary_type || "", access_matrix: ab.access_matrix || {},
    }));
    const riskSummary: RiskSummary | null = data.risk_summary ? {
      total_endpoints: data.risk_summary.total_endpoints || 0,
      total_input_vectors: data.risk_summary.total_input_vectors || 0,
      high_risk_vectors: data.risk_summary.high_risk_vectors || 0,
      auth_boundaries_found: data.risk_summary.auth_boundaries_found || 0,
      unprotected_admin_paths: data.risk_summary.unprotected_admin_paths || 0,
      exposed_debug_endpoints: data.risk_summary.exposed_debug_endpoints || 0,
      secrets_found: data.risk_summary.secrets_found || 0,
      score: data.risk_summary.score || 0,
    } : null;

    set({
      target: data.target || "",
      modules,
      stats,
      endpoints,
      techStack,
      inputVectors,
      authBoundaries,
      riskSummary,
      logs: [],
      phaseName: "completed",
      currentPhase: 99,
      connected: false,
      activeView: "endpoints",
      startTime: Date.now(),
    });

    // Auto-save to IndexedDB (skip when loading an existing session)
    if (!skipSave) {
      const sessionName = name || data.target || "Unnamed";
      saveSession(sessionName, data).then((id) => {
        set({ currentSessionId: id });
        listSessions().then((sessions) => set({ sessions }));
      });
    }
  },

  // ── Orchestration actions ──────────────────────────────────────────────────

  fetchDecisionContext: async () => {
    try {
      const r = await fetch("/api/v1/orchestration/context/snapshot");
      if (r.ok) set({ decisionContext: await r.json() });
    } catch { /* ignore */ }
  },

  fetchEndpointClusters: async () => {
    try {
      const r = await fetch("/api/v1/orchestration/endpoints/clusters");
      if (r.ok) {
        const data = await r.json();
        set({ endpointClusters: data.clusters || [] });
      }
    } catch { /* ignore */ }
  },

  fetchCoverageGaps: async () => {
    try {
      const r = await fetch("/api/v1/orchestration/coverage/gaps");
      if (r.ok) {
        const data = await r.json();
        set({ coverageGaps: data.gaps || [] });
      }
    } catch { /* ignore */ }
  },

  fetchAuthRoles: async () => {
    try {
      const r = await fetch("/api/v1/orchestration/auth/roles");
      if (r.ok) set({ authRoles: await r.json() });
    } catch { /* ignore */ }
  },

  fetchPlaybookResults: async () => {
    try {
      const r = await fetch("/api/v1/orchestration/playbook/results");
      if (r.ok) set({ playbookResult: await r.json() });
    } catch { /* ignore */ }
  },

  fetchMergePreview: async (strategy, urlPattern) => {
    try {
      const params = new URLSearchParams({ strategy });
      if (urlPattern) params.set("url_pattern", urlPattern);
      const r = await fetch(`/api/v1/orchestration/queue/merge-preview?${params}`);
      if (r.ok) {
        const data = await r.json();
        set({ mergePreview: data.candidates || [] });
      }
    } catch { /* ignore */ }
  },

  fetchQueueItems: async (offset = 0, limit = 50) => {
    try {
      const r = await fetch(`/api/v1/orchestration/queue/items?offset=${offset}&limit=${limit}`);
      if (r.ok) {
        const data = await r.json();
        set({ queueItems: data.items || [] });
      }
    } catch { /* ignore */ }
  },

  fetchQueueStats: async () => {
    try {
      const r = await fetch("/api/v1/orchestration/queue/stats");
      if (r.ok) set({ queueStats: await r.json() });
    } catch { /* ignore */ }
  },

  pauseQueue: async () => {
    try {
      const r = await fetch("/api/v1/orchestration/queue/pause", { method: "POST" });
      if (r.ok) { const d = await r.json(); return d.message || ""; }
    } catch { /* ignore */ }
    return "";
  },

  resumeQueue: async () => {
    try {
      const r = await fetch("/api/v1/orchestration/queue/resume", { method: "POST" });
      if (r.ok) { const d = await r.json(); return d.message || ""; }
    } catch { /* ignore */ }
    return "";
  },

  clearQueue: async () => {
    try {
      const r = await fetch("/api/v1/orchestration/queue/clear", { method: "POST" });
      if (r.ok) { const d = await r.json(); return d.message || ""; }
    } catch { /* ignore */ }
    return "";
  },

  performLogin: async (loginUrl, username, password, role) => {
    try {
      const r = await fetch("/api/v1/orchestration/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ login_url: loginUrl, username, password, role: role || "default" }),
      });
      if (r.ok) {
        const data = await r.json();
        useCrawlStore.getState().fetchAuthRoles();
        return data.success;
      }
    } catch { /* ignore */ }
    return false;
  },

  mergeQueue: async (strategy, urlPattern, sampleSize) => {
    try {
      await fetch("/api/v1/orchestration/queue/merge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ strategy, url_pattern: urlPattern || "", sample_size: sampleSize || 3 }),
      });
    } catch { /* ignore */ }
  },

  reprioritizeQueue: async (rules) => {
    try {
      await fetch("/api/v1/orchestration/queue/reprioritize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules }),
      });
    } catch { /* ignore */ }
  },

  removeFromQueue: async (urlPatterns) => {
    try {
      const r = await fetch("/api/v1/orchestration/queue/remove", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url_patterns: urlPatterns }),
      });
      if (r.ok) {
        const data = await r.json();
        return data.message || "";
      }
    } catch { /* ignore */ }
    return "";
  },

  fetchAutoMergeRules: async () => {
    try {
      const r = await fetch("/api/v1/orchestration/queue/auto-merge-rules");
      if (r.ok) set({ autoMergeRules: await r.json() });
    } catch { /* ignore */ }
  },

  addAutoMergeRule: async (pattern, maxPerTemplate) => {
    try {
      const r = await fetch("/api/v1/orchestration/queue/auto-merge-rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pattern, max_per_template: maxPerTemplate }),
      });
      if (r.ok) {
        const data = await r.json();
        useCrawlStore.getState().fetchAutoMergeRules();
        return data.message || "";
      }
    } catch { /* ignore */ }
    return "";
  },

  removeAutoMergeRule: async (pattern) => {
    try {
      const r = await fetch(`/api/v1/orchestration/queue/auto-merge-rules?pattern=${encodeURIComponent(pattern)}`, {
        method: "DELETE",
      });
      if (r.ok) {
        const data = await r.json();
        useCrawlStore.getState().fetchAutoMergeRules();
        return data.message || "";
      }
    } catch { /* ignore */ }
    return "";
  },

  adjustStrategy: async (moduleWeights, focusPatterns, focusBoost) => {
    try {
      await fetch("/api/v1/orchestration/strategy/adjust", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ module_weights: moduleWeights, focus_patterns: focusPatterns, focus_boost: focusBoost || 10 }),
      });
    } catch { /* ignore */ }
  },

  testHypothesis: async (hypothesis, testUrls, methods, priority, authRole) => {
    try {
      const r = await fetch("/api/v1/orchestration/hypothesis/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hypothesis, test_urls: testUrls, methods, priority: priority || 20, auth_role: authRole || null }),
      });
      if (r.ok) {
        const data = await r.json();
        return data.message || "";
      }
    } catch { /* ignore */ }
    return "";
  },

  // ── Session management ────────────────────────────────────────────────────

  refreshSessions: async () => {
    const sessions = await listSessions();
    set({ sessions });
  },

  loadSessionById: async (id) => {
    const data = await loadSession(id);
    if (!data) return;
    // Don't overwrite live crawl data from WebSocket
    if (useCrawlStore.getState()._liveMode) return;
    useCrawlStore.getState().loadReport(data, undefined, true);
    set({ currentSessionId: id });
  },

  deleteSessionById: async (id) => {
    await deleteSession(id);
    const sessions = await listSessions();
    const state = useCrawlStore.getState();
    if (state.currentSessionId === id) {
      // Deleted active session — load the next one or clear
      if (sessions.length > 0) {
        set({ sessions });
        await useCrawlStore.getState().loadSessionById(sessions[0].id);
      } else {
        set({ sessions, currentSessionId: null, target: "", endpoints: [], phaseName: "", techStack: [], inputVectors: [], authBoundaries: [], riskSummary: null });
      }
    } else {
      set({ sessions });
    }
  },
}));
