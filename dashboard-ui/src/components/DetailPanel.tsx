import { useCrawlStore } from "../hooks/useCrawlStore";
import type { ModuleState } from "../types";

const STATE_LABELS: Record<ModuleState, string> = {
  pending: "Pending",
  running: "Running",
  complete: "Complete",
  error: "Error",
  needs_attention: "Needs Attention",
};

const STATE_COLORS: Record<ModuleState, string> = {
  pending: "var(--text-muted)",
  running: "var(--accent-blue)",
  complete: "var(--accent-green)",
  error: "var(--accent-red)",
  needs_attention: "var(--accent-yellow)",
};

export function DetailPanel() {
  const { selectedNode, modules, endpoints } = useCrawlStore();

  if (!selectedNode) {
    return (
      <div
        style={{
          padding: 16,
          color: "var(--text-muted)",
          fontSize: 13,
        }}
      >
        Click a node to see details
      </div>
    );
  }

  // Module detail
  const mod = modules[selectedNode];
  if (mod) {
    const relatedEndpoints = endpoints
      .filter((e) => e.source_module === selectedNode)
      .slice(-20);

    return (
      <div style={{ padding: 12, overflowY: "auto", height: "100%" }}>
        <h3 style={{ fontSize: 15, marginBottom: 12 }}>{selectedNode}</h3>

        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
            Status
          </div>
          <div style={{ color: STATE_COLORS[mod.state], fontWeight: 600 }}>
            {STATE_LABELS[mod.state]}
          </div>
        </div>

        {mod.stats && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
              Statistics
            </div>
            <div style={{ fontSize: 13 }}>
              {mod.stats.endpoints_found != null && (
                <div>Endpoints: {mod.stats.endpoints_found}</div>
              )}
              {mod.stats.requests_made != null && (
                <div>Requests: {mod.stats.requests_made}</div>
              )}
              {mod.stats.errors != null && mod.stats.errors > 0 && (
                <div style={{ color: "var(--accent-red)" }}>
                  Errors: {mod.stats.errors}
                </div>
              )}
            </div>
          </div>
        )}

        {relatedEndpoints.length > 0 && (
          <div>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
              Recent Endpoints
            </div>
            {relatedEndpoints.map((ep, i) => (
              <div
                key={i}
                style={{
                  fontSize: 12,
                  fontFamily: "monospace",
                  padding: "3px 0",
                  borderBottom: "1px solid var(--border)",
                  color: "var(--text-secondary)",
                  wordBreak: "break-all",
                }}
              >
                <span style={{ fontWeight: 600, marginRight: 6 }}>{ep.method}</span>
                {new URL(ep.url).pathname}
                {ep.param_count > 0 && (
                  <span style={{ color: "var(--accent-green)", marginLeft: 4 }}>
                    ({ep.param_count}p)
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  // URL detail
  const ep = endpoints.find((e) => e.url === selectedNode);
  if (ep) {
    return (
      <div style={{ padding: 12, overflowY: "auto", height: "100%" }}>
        <h3 style={{ fontSize: 14, marginBottom: 12, wordBreak: "break-all" }}>
          {ep.url}
        </h3>
        <div style={{ fontSize: 13 }}>
          <div>Method: <strong>{ep.method}</strong></div>
          <div>Status: {ep.status_code || "N/A"}</div>
          <div>Content-Type: {ep.content_type || "N/A"}</div>
          <div>Source: {ep.source_module}</div>
          <div>Params: {ep.param_count}</div>
          {ep.tags.length > 0 && (
            <div style={{ marginTop: 8, display: "flex", gap: 4, flexWrap: "wrap" }}>
              {ep.tags.map((tag, i) => (
                <span
                  key={i}
                  style={{
                    fontSize: 11,
                    padding: "2px 8px",
                    borderRadius: 10,
                    background: "var(--bg-tertiary)",
                    color: "var(--text-secondary)",
                  }}
                >
                  {tag}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div style={{ padding: 16, color: "var(--text-muted)", fontSize: 13 }}>
      No details for: {selectedNode}
    </div>
  );
}
