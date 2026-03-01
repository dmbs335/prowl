import { create } from "zustand";
import type {
  CrawlStats,
  Endpoint,
  Intervention,
  LogEntry,
  ModuleInfo,
  ModuleState,
  ModuleStats,
} from "../types";

interface CrawlStore {
  // Pipeline state
  modules: Record<string, ModuleInfo>;
  currentPhase: number;
  phaseName: string;

  // Endpoints
  endpoints: Endpoint[];

  // Interventions
  interventions: Intervention[];

  // UI state
  activeView: "pipeline" | "sitemap";
  selectedNode: string | null;

  // Stats & logs
  stats: CrawlStats;
  logs: LogEntry[];

  // Actions
  setModuleState: (
    module: string,
    state: ModuleState,
    stats?: ModuleStats
  ) => void;
  addEndpoint: (endpoint: Endpoint) => void;
  addIntervention: (intervention: Intervention) => void;
  resolveIntervention: (id: string) => void;
  updateStats: (stats: Partial<CrawlStats>) => void;
  addLog: (entry: LogEntry) => void;
  setActiveView: (view: "pipeline" | "sitemap") => void;
  setSelectedNode: (nodeId: string | null) => void;
  setPhase: (phase: number, name: string) => void;
  initState: (
    modules: Record<string, ModuleInfo>,
    stats: CrawlStats,
    logs: LogEntry[]
  ) => void;
}

export const useCrawlStore = create<CrawlStore>((set) => ({
  modules: {
    s6_passive: { state: "pending", stats: {} as ModuleStats },
    s1_spider: { state: "pending", stats: {} as ModuleStats },
    s2_bruteforce: { state: "pending", stats: {} as ModuleStats },
    s4_js: { state: "pending", stats: {} as ModuleStats },
    s5_api: { state: "pending", stats: {} as ModuleStats },
    s7_auth: { state: "pending", stats: {} as ModuleStats },
    s3_params: { state: "pending", stats: {} as ModuleStats },
  },
  currentPhase: 0,
  phaseName: "",
  endpoints: [],
  interventions: [],
  activeView: "pipeline",
  selectedNode: null,
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

  setModuleState: (module, state, stats) =>
    set((s) => ({
      modules: {
        ...s.modules,
        [module]: { state, stats: stats || s.modules[module]?.stats || ({} as ModuleStats) },
      },
    })),

  addEndpoint: (endpoint) =>
    set((s) => ({ endpoints: [...s.endpoints, endpoint] })),

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

  initState: (modules, stats, logs) =>
    set({ modules, stats, logs }),
}));
