import {
  ReactFlow,
  type Node,
  type Edge,
  Background,
  BackgroundVariant,
  Controls,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useCrawlStore } from "../hooks/useCrawlStore";
import type { ModuleState } from "../types";

const STATE_COLORS: Record<ModuleState, string> = {
  pending: "#4a5568",
  running: "#3b82f6",
  complete: "#10b981",
  error: "#ef4444",
  needs_attention: "#f59e0b",
};

const MODULE_LABELS: Record<string, string> = {
  s6_passive: "Passive Recon",
  s1_spider: "Active Spider",
  s2_bruteforce: "Dir Bruteforce",
  s4_js: "JS Analysis",
  s5_api: "API Discovery",
  s7_auth: "Auth Crawl",
  s3_params: "Param Discovery",
  s8_states: "State Transitions",
  s9_infra: "Infra Mapping",
  s10_tech: "Tech Fingerprint",
  s11_input: "Input Classify",
  s12_auth: "Auth Boundary",
  s13_report: "Report",
};

// Layout: phases flow left to right
// Phase 1: Passive  |  Phase 2: Active Crawl  |  Phase 3: Deep  |  Phase 4: Analysis  |  Phase 5: Report
const MODULE_POSITIONS: Record<string, { x: number; y: number }> = {
  s6_passive:       { x: 50,  y: 160 },
  s1_spider:        { x: 280, y: 80 },
  s2_bruteforce:    { x: 280, y: 240 },
  s4_js:            { x: 510, y: 40 },
  s5_api:           { x: 510, y: 160 },
  s7_auth:          { x: 510, y: 280 },
  s3_params:        { x: 740, y: 80 },
  s8_states:        { x: 740, y: 240 },
  s9_infra:         { x: 970, y: 40 },
  s10_tech:         { x: 970, y: 160 },
  s11_input:        { x: 970, y: 280 },
  s12_auth:         { x: 1200, y: 120 },
  s13_report:       { x: 1200, y: 280 },
};

const EDGES_DEF: { source: string; target: string }[] = [
  { source: "s6_passive", target: "s1_spider" },
  { source: "s6_passive", target: "s2_bruteforce" },
  { source: "s1_spider", target: "s4_js" },
  { source: "s1_spider", target: "s5_api" },
  { source: "s1_spider", target: "s7_auth" },
  { source: "s2_bruteforce", target: "s3_params" },
  { source: "s4_js", target: "s3_params" },
  { source: "s5_api", target: "s3_params" },
  { source: "s7_auth", target: "s8_states" },
  { source: "s3_params", target: "s9_infra" },
  { source: "s3_params", target: "s10_tech" },
  { source: "s8_states", target: "s11_input" },
  { source: "s10_tech", target: "s12_auth" },
  { source: "s11_input", target: "s12_auth" },
  { source: "s9_infra", target: "s13_report" },
  { source: "s12_auth", target: "s13_report" },
];

export function PipelineView() {
  const { modules, setSelectedNode } = useCrawlStore();

  const nodes: Node[] = Object.entries(MODULE_POSITIONS).map(([id, pos]) => {
    const mod = modules[id];
    const state = mod?.state || "pending";
    const stats = mod?.stats;
    const found = stats?.endpoints_found ?? 0;
    const reqs = stats?.requests_made ?? 0;
    const errs = stats?.errors ?? 0;
    const color = STATE_COLORS[state];
    const isPulsing = state === "running" || state === "needs_attention";

    return {
      id,
      position: pos,
      data: {
        label: (
          <div
            className={isPulsing ? "pulse" : ""}
            style={{ textAlign: "center", padding: "4px 0" }}
          >
            <div style={{ fontWeight: 600, fontSize: 12 }}>
              {MODULE_LABELS[id] || id}
            </div>
            {state !== "pending" && (
              <div style={{ fontSize: 10, opacity: 0.85, marginTop: 3, display: "flex", gap: 6, justifyContent: "center" }}>
                {id === "s3_params" ? (
                  <>
                    {(stats?.params_found as number) > 0 && <span>{stats?.params_found as number} param</span>}
                    {(stats?.endpoints_profiled as number) > 0 && <span>{stats?.endpoints_profiled as number} ep</span>}
                  </>
                ) : id === "s8_states" ? (
                  <>
                    {(stats?.forms_identified as number) > 0 && <span>{stats?.forms_identified as number} form</span>}
                  </>
                ) : id === "s9_infra" ? (
                  <>{found > 0 && <span>{found} comp</span>}</>
                ) : id === "s10_tech" ? (
                  <>{found > 0 && <span>{found} tech</span>}</>
                ) : id === "s11_input" ? (
                  <>{found > 0 && <span>{found} vec</span>}</>
                ) : id === "s12_auth" ? (
                  <>{found > 0 && <span>{found} auth</span>}</>
                ) : (
                  <>{found > 0 && <span>{found} ep</span>}</>
                )}
                {reqs > 0 && <span>{reqs} req</span>}
                {errs > 0 && <span style={{ color: "#fca5a5" }}>{errs} err</span>}
              </div>
            )}
          </div>
        ),
      },
      style: {
        background: state === "pending" ? "#1a1d27" : color,
        color: state === "pending" ? "#6b7084" : "#fff",
        border: `2px solid ${color}`,
        borderRadius: 8,
        padding: "8px 14px",
        minWidth: 120,
        boxShadow:
          state === "needs_attention"
            ? `0 0 16px ${color}80`
            : state === "running"
              ? `0 0 12px ${color}60`
              : "none",
      },
    };
  });

  const edges: Edge[] = EDGES_DEF.map((e, i) => {
    const sourceState = modules[e.source]?.state;
    const isActive = sourceState === "running" || sourceState === "complete";
    return {
      id: `e${i}`,
      source: e.source,
      target: e.target,
      type: "smoothstep",
      animated: isActive,
      style: { stroke: isActive ? "#3b82f680" : "#4a5568" },
    };
  });

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodeClick={(_event, node) => setSelectedNode(node.id)}
      fitView
      proOptions={{ hideAttribution: true }}
    >
      <Background variant={BackgroundVariant.Dots} color="#2e3144" gap={20} />
      <Controls
        style={{ background: "var(--bg-tertiary)", borderColor: "var(--border)" }}
      />
    </ReactFlow>
  );
}
