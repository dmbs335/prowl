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
  s6_passive: "§6 Passive",
  s1_spider: "§1 Spider",
  s2_bruteforce: "§2 Bruteforce",
  s4_js: "§4 JS Analysis",
  s5_api: "§5 API Discovery",
  s7_auth: "§7 Auth Crawl",
  s3_params: "§3 Params",
};

export function PipelineView() {
  const { modules, setSelectedNode } = useCrawlStore();

  const nodes: Node[] = [
    { id: "s6_passive", position: { x: 50, y: 150 }, data: { label: "" } },
    { id: "s1_spider", position: { x: 280, y: 80 }, data: { label: "" } },
    { id: "s2_bruteforce", position: { x: 280, y: 220 }, data: { label: "" } },
    { id: "s4_js", position: { x: 510, y: 80 }, data: { label: "" } },
    { id: "s5_api", position: { x: 740, y: 80 }, data: { label: "" } },
    { id: "s7_auth", position: { x: 510, y: 220 }, data: { label: "" } },
    { id: "s3_params", position: { x: 740, y: 220 }, data: { label: "" } },
  ].map((n) => {
    const mod = modules[n.id];
    const state = mod?.state || "pending";
    const stats = mod?.stats;
    const found = stats?.endpoints_found ?? 0;
    const color = STATE_COLORS[state];
    const isPulsing = state === "running" || state === "needs_attention";

    return {
      ...n,
      data: {
        label: (
          <div
            className={isPulsing ? "pulse" : ""}
            style={{ textAlign: "center", padding: "4px 0" }}
          >
            <div style={{ fontWeight: 600, fontSize: 13 }}>
              {MODULE_LABELS[n.id] || n.id}
            </div>
            {found > 0 && (
              <div style={{ fontSize: 11, opacity: 0.8, marginTop: 2 }}>
                {found} found
              </div>
            )}
          </div>
        ),
      },
      style: {
        background: color,
        color: "#fff",
        border: `2px solid ${color}`,
        borderRadius: 8,
        padding: "8px 16px",
        minWidth: 130,
        boxShadow:
          state === "needs_attention"
            ? `0 0 16px ${color}80`
            : state === "running"
              ? `0 0 12px ${color}60`
              : "none",
      },
    };
  });

  const edges: Edge[] = [
    { id: "e1", source: "s6_passive", target: "s1_spider", animated: true },
    { id: "e2", source: "s6_passive", target: "s2_bruteforce", animated: true },
    { id: "e3", source: "s1_spider", target: "s4_js" },
    { id: "e4", source: "s1_spider", target: "s7_auth" },
    { id: "e5", source: "s4_js", target: "s5_api" },
    { id: "e6", source: "s1_spider", target: "s3_params" },
    { id: "e7", source: "s2_bruteforce", target: "s3_params" },
    { id: "e8", source: "s5_api", target: "s3_params" },
  ].map((e) => ({
    ...e,
    style: { stroke: "#4a5568" },
    type: "smoothstep",
  }));

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
