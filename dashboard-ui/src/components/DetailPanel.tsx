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

const SOURCE_COLORS: Record<string, string> = {
  s1_spider: "var(--accent-blue)",
  s2_bruteforce: "var(--accent-orange)",
  s3_params: "var(--accent-green)",
  s4_js: "var(--accent-purple)",
  s5_api: "#ec4899",
  s6_passive: "var(--text-muted)",
  s7_auth: "var(--accent-yellow)",
};

function StatRow({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", padding: "3px 0", fontSize: 13 }}>
      <span style={{ color: "var(--text-muted)" }}>{label}</span>
      <span style={{ color: color || "var(--text-primary)", fontWeight: 500, fontFamily: "monospace" }}>{value}</span>
    </div>
  );
}

export function DetailPanel() {
  const { selectedNode, modules, endpoints, stats, techStack, riskSummary } = useCrawlStore();

  // No selection: show overview
  if (!selectedNode) {
    const completedModules = Object.values(modules).filter((m) => m.state === "complete").length;
    const totalModules = Object.keys(modules).length;
    const runningModules = Object.values(modules).filter((m) => m.state === "running");

    return (
      <div style={{ padding: 12, fontSize: 13 }}>
        <h3 style={{ fontSize: 14, marginBottom: 12, color: "var(--text-primary)" }}>Overview</h3>

        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.5px" }}>
            Progress
          </div>
          <div style={{ width: "100%", height: 6, background: "var(--bg-tertiary)", borderRadius: 3, overflow: "hidden", marginBottom: 4 }}>
            <div
              style={{
                width: `${(completedModules / totalModules) * 100}%`,
                height: "100%",
                background: "var(--accent-green)",
                borderRadius: 3,
                transition: "width 0.5s ease",
              }}
            />
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
            {completedModules}/{totalModules} modules
          </div>
        </div>

        {runningModules.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Active
            </div>
            {Object.entries(modules)
              .filter(([, m]) => m.state === "running")
              .map(([id]) => (
                <div key={id} className="pulse" style={{ color: "var(--accent-blue)", fontSize: 12, padding: "2px 0" }}>
                  {MODULE_LABELS[id] || id}
                </div>
              ))}
          </div>
        )}

        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.5px" }}>
            Discovery
          </div>
          <StatRow label="Endpoints" value={stats.total_endpoints} color="var(--accent-blue)" />
          <StatRow label="Parameters" value={stats.total_params} color="var(--accent-green)" />
          <StatRow label="Secrets" value={stats.total_secrets} color={stats.total_secrets > 0 ? "var(--accent-red)" : undefined} />
          <StatRow label="Unique URLs" value={stats.unique_urls ?? "-"} />
          <StatRow label="Transactions" value={stats.transactions_stored ?? "-"} />
        </div>

        {/* Risk / Attack Surface */}
        {(riskSummary || techStack.length > 0) && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Attack Surface
            </div>
            {riskSummary && (
              <>
                <div style={{ display: "flex", alignItems: "baseline", gap: 4, marginBottom: 4 }}>
                  <span style={{
                    fontSize: 20, fontWeight: 700, fontFamily: "monospace",
                    color: riskSummary.score >= 75 ? "var(--accent-red)" :
                           riskSummary.score >= 50 ? "var(--accent-orange)" :
                           riskSummary.score >= 25 ? "var(--accent-yellow)" : "var(--accent-green)",
                  }}>
                    {riskSummary.score.toFixed(0)}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>/100 risk</span>
                </div>
                <StatRow label="Input Vectors" value={riskSummary.total_input_vectors} />
                <StatRow label="High Risk" value={riskSummary.high_risk_vectors} color={riskSummary.high_risk_vectors > 0 ? "var(--accent-red)" : undefined} />
                <StatRow label="Auth Boundaries" value={riskSummary.auth_boundaries_found} />
              </>
            )}
            {techStack.length > 0 && (
              <StatRow label="Technologies" value={techStack.length} color="var(--accent-purple)" />
            )}
          </div>
        )}

        {/* Sources breakdown */}
        <div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.5px" }}>
            Endpoints by Source
          </div>
          {Object.entries(
            endpoints.reduce<Record<string, number>>((acc, ep) => {
              acc[ep.source_module] = (acc[ep.source_module] || 0) + 1;
              return acc;
            }, {})
          )
            .sort(([, a], [, b]) => b - a)
            .map(([source, count]) => (
              <div
                key={source}
                style={{ display: "flex", justifyContent: "space-between", padding: "2px 0", fontSize: 12 }}
              >
                <span style={{ color: SOURCE_COLORS[source] || "var(--text-secondary)" }}>
                  {MODULE_LABELS[source] || source}
                </span>
                <span style={{ fontFamily: "monospace", color: "var(--text-secondary)" }}>{count}</span>
              </div>
            ))}
        </div>

        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 16, textAlign: "center" }}>
          Click a node for details
        </div>
      </div>
    );
  }

  // Module detail
  const mod = modules[selectedNode];
  if (mod) {
    const relatedEndpoints = endpoints
      .filter((e) => e.source_module === selectedNode)
      .slice(-30);

    return (
      <div style={{ padding: 12, overflowY: "auto", height: "100%" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <h3 style={{ fontSize: 14 }}>{MODULE_LABELS[selectedNode] || selectedNode}</h3>
          <span
            style={{
              fontSize: 11,
              fontWeight: 600,
              color: STATE_COLORS[mod.state],
              background: `${STATE_COLORS[mod.state]}20`,
              padding: "2px 8px",
              borderRadius: 8,
            }}
          >
            {STATE_LABELS[mod.state]}
          </span>
        </div>

        {mod.stats && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Statistics
            </div>
            {/* Module-specific primary metrics */}
            {selectedNode === "s3_params" && (
              <>
                {mod.stats.params_found != null && (
                  <StatRow label="Params Found" value={mod.stats.params_found as number} color="var(--accent-green)" />
                )}
                {mod.stats.known_params_collected != null && (
                  <StatRow label="Known Params" value={mod.stats.known_params_collected as number} />
                )}
                {mod.stats.endpoints_profiled != null && (
                  <StatRow label="Endpoints Profiled" value={mod.stats.endpoints_profiled as number} color="var(--accent-blue)" />
                )}
              </>
            )}
            {selectedNode === "s8_states" && (
              <>
                {mod.stats.forms_identified != null && (
                  <StatRow label="Forms Found" value={mod.stats.forms_identified as number} color="var(--accent-purple)" />
                )}
                {mod.stats.state_specific_endpoints != null && typeof mod.stats.state_specific_endpoints === "object" && (
                  Object.entries(mod.stats.state_specific_endpoints as Record<string, number>).map(([level, count]) => (
                    <StatRow key={level} label={`${level} endpoints`} value={count} color="var(--accent-blue)" />
                  ))
                )}
              </>
            )}
            {selectedNode === "s9_infra" && (
              <>
                {mod.stats.endpoints_found != null && (
                  <StatRow label="Components" value={mod.stats.endpoints_found} color="var(--accent-orange)" />
                )}
                {mod.stats.server_variants != null && (mod.stats.server_variants as number) > 0 && (
                  <StatRow label="Server Variants" value={mod.stats.server_variants as number} color="var(--accent-yellow)" />
                )}
                {mod.stats.via_chains != null && (mod.stats.via_chains as number) > 0 && (
                  <StatRow label="Proxy Chains" value={mod.stats.via_chains as number} />
                )}
                {(mod.stats.cache_hits != null || mod.stats.cache_misses != null) &&
                  ((mod.stats.cache_hits as number) + (mod.stats.cache_misses as number)) > 0 && (
                  <StatRow
                    label="Cache Hit Rate"
                    value={`${mod.stats.cache_hits}/${(mod.stats.cache_hits as number) + (mod.stats.cache_misses as number)}`}
                    color="var(--accent-blue)"
                  />
                )}
                {mod.stats.by_category != null && typeof mod.stats.by_category === "object" && (
                  Object.entries(mod.stats.by_category as Record<string, number>).map(([cat, count]) => (
                    <StatRow key={cat} label={cat} value={count} />
                  ))
                )}
              </>
            )}
            {selectedNode === "s10_tech" && (
              <>
                {mod.stats.endpoints_found != null && (
                  <StatRow label="Technologies" value={mod.stats.endpoints_found} color="var(--accent-purple)" />
                )}
                {mod.stats.high_confidence != null && (
                  <StatRow label="High Confidence" value={mod.stats.high_confidence as number} color="var(--accent-green)" />
                )}
                {mod.stats.by_category != null && typeof mod.stats.by_category === "object" && (
                  Object.entries(mod.stats.by_category as Record<string, number>).map(([cat, count]) => (
                    <StatRow key={cat} label={cat} value={count} />
                  ))
                )}
              </>
            )}
            {selectedNode === "s11_input" && mod.stats.endpoints_found != null && (
              <StatRow label="Vectors Classified" value={mod.stats.endpoints_found} color="var(--accent-yellow)" />
            )}
            {selectedNode === "s12_auth" && mod.stats.endpoints_found != null && (
              <StatRow label="Boundaries" value={mod.stats.endpoints_found} color="var(--accent-orange)" />
            )}
            {/* Generic endpoints_found for standard discovery modules */}
            {!["s3_params", "s8_states", "s9_infra", "s10_tech", "s11_input", "s12_auth"].includes(selectedNode) &&
              mod.stats.endpoints_found != null && (
              <StatRow label="Endpoints" value={mod.stats.endpoints_found} color="var(--accent-blue)" />
            )}
            {mod.stats.requests_made != null && (
              <StatRow label="Requests" value={mod.stats.requests_made} />
            )}
            {mod.stats.errors != null && mod.stats.errors > 0 && (
              <StatRow label="Errors" value={mod.stats.errors} color="var(--accent-red)" />
            )}
          </div>
        )}

        {relatedEndpoints.length > 0 && (
          <div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Found Endpoints ({relatedEndpoints.length})
            </div>
            {relatedEndpoints.map((ep, i) => (
              <div
                key={i}
                style={{
                  fontSize: 11,
                  fontFamily: "monospace",
                  padding: "4px 0",
                  borderBottom: "1px solid var(--border)",
                  color: "var(--text-secondary)",
                  wordBreak: "break-all",
                  display: "flex",
                  alignItems: "baseline",
                  gap: 4,
                }}
              >
                <span style={{ fontWeight: 700, color: "var(--accent-blue)", flexShrink: 0 }}>{ep.method}</span>
                <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>
                  {(() => { try { return new URL(ep.url).pathname; } catch { return ep.url; } })()}
                </span>
                {ep.status_code && (
                  <span style={{ color: "var(--text-muted)", flexShrink: 0 }}>{ep.status_code}</span>
                )}
                {ep.param_count > 0 && (
                  <span style={{ color: "var(--accent-green)", flexShrink: 0 }}>{ep.param_count}p</span>
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
    let pathname = ep.url;
    let search = "";
    try {
      const u = new URL(ep.url);
      pathname = u.pathname;
      search = u.search;
    } catch { /* ignore */ }

    return (
      <div style={{ padding: 12, overflowY: "auto", height: "100%" }}>
        <h3
          style={{
            fontSize: 13,
            marginBottom: 12,
            wordBreak: "break-all",
            fontFamily: "monospace",
            lineHeight: 1.4,
          }}
        >
          <span style={{ color: "var(--accent-blue)", fontWeight: 700, marginRight: 6 }}>{ep.method}</span>
          <span>{pathname}</span>
          {search && <span style={{ color: "var(--text-muted)" }}>{search}</span>}
        </h3>

        <div style={{ fontSize: 13 }}>
          <StatRow label="Status" value={ep.status_code || "N/A"} color={
            ep.status_code && ep.status_code < 300 ? "var(--accent-green)" :
            ep.status_code && ep.status_code < 400 ? "var(--accent-blue)" :
            ep.status_code && ep.status_code < 500 ? "var(--accent-orange)" :
            ep.status_code ? "var(--accent-red)" : undefined
          } />
          <StatRow label="Content-Type" value={ep.content_type || "N/A"} />
          <StatRow label="Source" value={MODULE_LABELS[ep.source_module] || ep.source_module} color={SOURCE_COLORS[ep.source_module]} />
          <StatRow label="Parameters" value={ep.param_count} color={ep.param_count > 0 ? "var(--accent-green)" : undefined} />
        </div>

        {ep.tags.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Tags
            </div>
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
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
          </div>
        )}
      </div>
    );
  }

  return (
    <div style={{ padding: 16, color: "var(--text-muted)", fontSize: 13 }}>
      No details for: {selectedNode}
    </div>
  );
}
