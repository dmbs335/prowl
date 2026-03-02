import { useEffect, useState } from "react";
import { useCrawlStore } from "../hooks/useCrawlStore";
import type { RoleStatus, EndpointCluster, CoverageGap, DecisionContext, PlaybookFinding, PlaybookResult, NextCrawlHint, QueueItem, QueueDetailedStats, MergeCandidate } from "../types";

// ── Sub-tab types ────────────────────────────────────────────
type SubTab = "results" | "queue" | "auth" | "intelligence" | "hypothesis" | "playbook";

// ── Style helpers ────────────────────────────────────────────
const cardStyle: React.CSSProperties = {
  background: "var(--bg-secondary)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  padding: 14,
  marginBottom: 12,
};

const labelStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 600,
  color: "var(--text-muted)",
  marginBottom: 4,
  textTransform: "uppercase",
  letterSpacing: "0.5px",
};

const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "6px 10px",
  border: "1px solid var(--border)",
  borderRadius: 4,
  background: "var(--bg-tertiary)",
  color: "var(--text-primary)",
  fontSize: 13,
  outline: "none",
  boxSizing: "border-box",
};

const btnStyle: React.CSSProperties = {
  padding: "6px 16px",
  border: "none",
  borderRadius: 4,
  cursor: "pointer",
  fontSize: 13,
  fontWeight: 600,
};

const btnPrimary: React.CSSProperties = {
  ...btnStyle,
  background: "var(--accent-blue)",
  color: "#fff",
};

const btnDanger: React.CSSProperties = {
  ...btnStyle,
  background: "var(--accent-red)",
  color: "#fff",
};

const btnSecondary: React.CSSProperties = {
  ...btnStyle,
  background: "var(--bg-tertiary)",
  color: "var(--text-secondary)",
  border: "1px solid var(--border)",
};

function Badge({ text, color }: { text: string; color?: string }) {
  return (
    <span
      style={{
        fontSize: 10,
        padding: "1px 6px",
        borderRadius: 8,
        background: `${color || "var(--text-muted)"}20`,
        color: color || "var(--text-muted)",
        whiteSpace: "nowrap",
      }}
    >
      {text}
    </span>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        fontSize: 14,
        fontWeight: 700,
        color: "var(--text-primary)",
        marginBottom: 10,
        marginTop: 16,
      }}
    >
      {children}
    </div>
  );
}

// ── Results Operations Tab ───────────────────────────────────
function ResultsOpsTab() {
  const { stats, endpointClusters, fetchEndpointClusters, adjustStrategy } = useCrawlStore();
  const [focusPattern, setFocusPattern] = useState("");
  const [focusBoost, setFocusBoost] = useState(10);
  const [excludePattern, setExcludePattern] = useState("");
  const [excludeResult, setExcludeResult] = useState("");

  useEffect(() => {
    fetchEndpointClusters();
  }, [fetchEndpointClusters]);

  const overSampled = endpointClusters.filter((c) => c.count > 20);

  return (
    <div>
      {/* Result stats */}
      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        {[
          { label: "Endpoints", value: stats.total_endpoints },
          { label: "Templates", value: endpointClusters.length },
          { label: "Over-sampled", value: overSampled.length, color: overSampled.length > 0 ? "var(--accent-orange)" : undefined },
          { label: "Requests", value: stats.requests_completed },
        ].map((s) => (
          <div key={s.label} style={{ ...cardStyle, flex: 1, textAlign: "center", marginBottom: 0 }}>
            <div style={labelStyle}>{s.label}</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: s.color || "var(--accent-blue)" }}>
              {typeof s.value === "number" ? s.value.toLocaleString() : s.value}
            </div>
          </div>
        ))}
      </div>

      {/* Endpoint Clusters table */}
      <SectionTitle>Endpoint Clusters ({endpointClusters.length})</SectionTitle>
      <div style={cardStyle}>
        {endpointClusters.length === 0 ? (
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>No endpoint clusters yet. Crawl in progress...</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)", color: "var(--text-muted)" }}>
                  <th style={{ textAlign: "left", padding: "4px 8px" }}>Template</th>
                  <th style={{ textAlign: "right", padding: "4px 8px" }}>Count</th>
                  <th style={{ textAlign: "left", padding: "4px 8px" }}>Methods</th>
                  <th style={{ textAlign: "left", padding: "4px 8px" }}>Params</th>
                  <th style={{ textAlign: "right", padding: "4px 8px" }}>Coverage</th>
                  <th style={{ textAlign: "right", padding: "4px 8px" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {endpointClusters.map((c: EndpointCluster, i: number) => (
                  <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "4px 8px", fontFamily: "monospace", color: "var(--accent-blue)" }}>
                      {c.template}
                      {c.has_auth_boundary && <> <Badge text="AUTH" color="#ef4444" /></>}
                    </td>
                    <td style={{ padding: "4px 8px", textAlign: "right", color: c.count > 20 ? "var(--accent-orange)" : undefined }}>
                      {c.count}
                    </td>
                    <td style={{ padding: "4px 8px" }}>
                      {c.methods.map((m) => <Badge key={m} text={m} color="#3b82f6" />)}
                    </td>
                    <td style={{ padding: "4px 8px", fontSize: 11, color: "var(--text-muted)" }}>
                      {c.param_names.length > 0 ? c.param_names.slice(0, 4).join(", ") : "-"}
                    </td>
                    <td style={{ padding: "4px 8px", textAlign: "right", fontSize: 11 }}>
                      {c.coverage_alpha.toFixed(0)}/{c.coverage_beta.toFixed(0)}
                    </td>
                    <td style={{ padding: "4px 8px", textAlign: "right" }}>
                      <button
                        style={{ ...btnSecondary, padding: "2px 8px", fontSize: 10 }}
                        onClick={() => adjustStrategy({}, [c.template], 10)}
                      >
                        Boost
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div style={{ marginTop: 10, textAlign: "right" }}>
          <button style={{ ...btnSecondary, fontSize: 11 }} onClick={fetchEndpointClusters}>
            Refresh
          </button>
        </div>
      </div>

      {/* Focus Boost section */}
      <SectionTitle>Focus Boost</SectionTitle>
      <div style={cardStyle}>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
          <div style={{ flex: 1 }}>
            <div style={labelStyle}>URL Pattern</div>
            <input
              style={inputStyle}
              placeholder="/admin/.*"
              value={focusPattern}
              onChange={(e) => setFocusPattern(e.target.value)}
            />
          </div>
          <div style={{ width: 100 }}>
            <div style={labelStyle}>Boost</div>
            <input
              type="number"
              min={1}
              max={100}
              style={inputStyle}
              value={focusBoost}
              onChange={(e) => setFocusBoost(Number(e.target.value))}
            />
          </div>
          <button
            style={btnPrimary}
            onClick={() => {
              if (focusPattern) adjustStrategy({}, [focusPattern], focusBoost);
            }}
          >
            Apply
          </button>
        </div>
      </div>

      {/* Exclude from Scope section */}
      <SectionTitle>Exclude from Scope</SectionTitle>
      <div style={cardStyle}>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
          <div style={{ flex: 1 }}>
            <div style={labelStyle}>Exclude Pattern (regex)</div>
            <input
              style={inputStyle}
              placeholder="/static/.*|/assets/.*"
              value={excludePattern}
              onChange={(e) => setExcludePattern(e.target.value)}
            />
          </div>
          <button
            style={btnDanger}
            onClick={async () => {
              if (!excludePattern) return;
              try {
                const r = await fetch("/api/v1/crawl/scope", {
                  method: "PUT",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ add_exclude_patterns: [excludePattern] }),
                });
                if (r.ok) setExcludeResult(`Excluded: ${excludePattern}`);
                else setExcludeResult("Failed to update scope");
              } catch {
                setExcludeResult("Network error");
              }
            }}
          >
            Exclude
          </button>
        </div>
        {excludeResult && (
          <div style={{ marginTop: 8, fontSize: 12, color: "var(--accent-green)" }}>{excludeResult}</div>
        )}
      </div>
    </div>
  );
}

// ── Auth Tab ─────────────────────────────────────────────────
function AuthTab() {
  const { authRoles, fetchAuthRoles, performLogin } = useCrawlStore();
  const [loginUrl, setLoginUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("");
  const [loginResult, setLoginResult] = useState<{ success: boolean; message: string } | null>(null);

  useEffect(() => {
    fetchAuthRoles();
  }, [fetchAuthRoles]);

  async function handleLogin() {
    if (!loginUrl || !username || !password) return;
    setLoginResult(null);
    const ok = await performLogin(loginUrl, username, password, role || undefined);
    setLoginResult({ success: ok, message: ok ? "Login successful" : "Login failed" });
    fetchAuthRoles();
  }

  async function handleReauth(roleName: string) {
    try {
      await fetch(`/api/v1/orchestration/auth/reauth`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role: roleName }),
      });
      fetchAuthRoles();
    } catch { /* ignore */ }
  }

  async function handleRemoveRole(roleName: string) {
    try {
      await fetch(`/api/v1/orchestration/auth/roles/${encodeURIComponent(roleName)}`, {
        method: "DELETE",
      });
      fetchAuthRoles();
    } catch { /* ignore */ }
  }

  return (
    <div>
      {/* Role table */}
      <SectionTitle>Active Roles</SectionTitle>
      <div style={cardStyle}>
        {authRoles.length === 0 ? (
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>No roles configured. Use the login form below.</div>
        ) : (
          <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border)", color: "var(--text-muted)" }}>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>Role</th>
                <th style={{ textAlign: "center", padding: "4px 8px" }}>Active</th>
                <th style={{ textAlign: "right", padding: "4px 8px" }}>Sessions</th>
                <th style={{ textAlign: "right", padding: "4px 8px" }}>Cookies</th>
                <th style={{ textAlign: "right", padding: "4px 8px" }}>Requests</th>
                <th style={{ textAlign: "right", padding: "4px 8px" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {authRoles.map((r: RoleStatus) => (
                <tr key={r.name} style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "4px 8px", fontWeight: 600 }}>{r.name}</td>
                  <td style={{ padding: "4px 8px", textAlign: "center" }}>
                    <span style={{
                      display: "inline-block",
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      background: r.is_active ? "var(--accent-green)" : "var(--accent-red)",
                    }} />
                  </td>
                  <td style={{ padding: "4px 8px", textAlign: "right" }}>{r.valid_sessions}/{r.session_count}</td>
                  <td style={{ padding: "4px 8px", textAlign: "right" }}>{r.cookies_count}</td>
                  <td style={{ padding: "4px 8px", textAlign: "right" }}>{r.total_requests.toLocaleString()}</td>
                  <td style={{ padding: "4px 8px", textAlign: "right", display: "flex", gap: 4, justifyContent: "flex-end" }}>
                    <button style={{ ...btnSecondary, padding: "2px 8px", fontSize: 11 }} onClick={() => handleReauth(r.name)}>
                      Re-auth
                    </button>
                    <button style={{ ...btnDanger, padding: "2px 8px", fontSize: 11 }} onClick={() => handleRemoveRole(r.name)}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Login form */}
      <SectionTitle>Auto Login</SectionTitle>
      <div style={cardStyle}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <div style={{ gridColumn: "1 / -1" }}>
            <div style={labelStyle}>Login URL</div>
            <input style={inputStyle} placeholder="https://example.com/login" value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)} />
          </div>
          <div>
            <div style={labelStyle}>Username</div>
            <input style={inputStyle} placeholder="admin" value={username} onChange={(e) => setUsername(e.target.value)} />
          </div>
          <div>
            <div style={labelStyle}>Password</div>
            <input style={inputStyle} type="password" placeholder="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          <div>
            <div style={labelStyle}>Role Name (optional)</div>
            <input style={inputStyle} placeholder="admin" value={role} onChange={(e) => setRole(e.target.value)} />
          </div>
          <div style={{ display: "flex", alignItems: "flex-end" }}>
            <button style={btnPrimary} onClick={handleLogin}>Login</button>
          </div>
        </div>
        {loginResult && (
          <div style={{ marginTop: 10, fontSize: 12, color: loginResult.success ? "var(--accent-green)" : "var(--accent-red)" }}>
            {loginResult.message}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Intelligence Tab ─────────────────────────────────────────
function IntelligenceTab() {
  const {
    decisionContext, endpointClusters, coverageGaps,
    fetchDecisionContext, fetchEndpointClusters, fetchCoverageGaps, adjustStrategy,
  } = useCrawlStore();
  const [expandedCluster, setExpandedCluster] = useState<string | null>(null);

  useEffect(() => {
    fetchDecisionContext();
    fetchEndpointClusters();
    fetchCoverageGaps();
  }, [fetchDecisionContext, fetchEndpointClusters, fetchCoverageGaps]);

  // Auto-refresh decision context every 5s
  useEffect(() => {
    const interval = setInterval(fetchDecisionContext, 5000);
    return () => clearInterval(interval);
  }, [fetchDecisionContext]);

  const ctx: DecisionContext | null = decisionContext;

  return (
    <div>
      {/* Decision Context */}
      <SectionTitle>Decision Context</SectionTitle>
      <div style={cardStyle}>
        {!ctx ? (
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Loading...</div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(130px, 1fr))", gap: 10 }}>
            {[
              { label: "State", value: ctx.crawl_state },
              { label: "Phase", value: `${ctx.current_phase}: ${ctx.phase_name}` },
              { label: "Elapsed", value: `${Math.floor(ctx.elapsed / 60)}m ${Math.floor(ctx.elapsed % 60)}s` },
              { label: "Endpoints", value: ctx.endpoints_found },
              { label: "Coverage", value: `${ctx.coverage_unique} unique` },
              { label: "Discovery Rate", value: ctx.coverage_discovery_rate.toFixed(3) },
              { label: "Saturated", value: ctx.coverage_saturated ? "Yes" : "No", color: ctx.coverage_saturated ? "var(--accent-orange)" : "var(--accent-green)" },
              { label: "Queue Size", value: ctx.queue_size },
              { label: "Requests Done", value: ctx.requests_completed },
              { label: "Requests Failed", value: ctx.requests_failed },
              { label: "Rate Limiter", value: `${ctx.rate_limiter_delay.toFixed(2)}s` },
              { label: "Backoffs", value: ctx.rate_limiter_backoffs },
              { label: "Active Roles", value: ctx.active_roles.join(", ") || "none" },
              { label: "Pending Interventions", value: ctx.pending_interventions },
            ].map((item) => (
              <div key={item.label}>
                <div style={labelStyle}>{item.label}</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: (item as { color?: string }).color || "var(--text-primary)" }}>
                  {item.value}
                </div>
              </div>
            ))}
          </div>
        )}
        <div style={{ marginTop: 10, textAlign: "right" }}>
          <button style={{ ...btnSecondary, fontSize: 11 }} onClick={() => { fetchDecisionContext(); fetchEndpointClusters(); fetchCoverageGaps(); }}>
            Refresh All
          </button>
        </div>
      </div>

      {/* Top Productive Templates */}
      {ctx && ctx.top_productive_templates.length > 0 && (
        <>
          <SectionTitle>Top Productive Templates</SectionTitle>
          <div style={cardStyle}>
            {ctx.top_productive_templates.map((t, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "4px 0", borderBottom: i < ctx.top_productive_templates.length - 1 ? "1px solid var(--border)" : "none" }}>
                <span style={{ fontFamily: "monospace", fontSize: 12, color: "var(--accent-blue)" }}>{t.template}</span>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    hit: {t.hit_rate.toFixed(2)} ({t.alpha.toFixed(0)}/{t.beta.toFixed(0)})
                  </span>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Under-explored Areas */}
      {ctx && ctx.under_explored_areas.length > 0 && (
        <>
          <SectionTitle>Under-explored Areas</SectionTitle>
          <div style={cardStyle}>
            {ctx.under_explored_areas.map((t, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "4px 0", borderBottom: i < ctx.under_explored_areas.length - 1 ? "1px solid var(--border)" : "none" }}>
                <span style={{ fontFamily: "monospace", fontSize: 12, color: "var(--accent-orange)" }}>{t.template}</span>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    ({t.alpha.toFixed(0)}/{t.beta.toFixed(0)})
                  </span>
                  <button
                    style={{ ...btnSecondary, padding: "2px 8px", fontSize: 10 }}
                    onClick={() => adjustStrategy({}, [t.template], 10)}
                  >
                    Boost
                  </button>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Coverage Gaps */}
      {coverageGaps.length > 0 && (
        <>
          <SectionTitle>Coverage Gaps ({coverageGaps.length})</SectionTitle>
          <div style={cardStyle}>
            {coverageGaps.map((g: CoverageGap, i: number) => {
              const gapColors: Record<string, string> = {
                untested_method: "#3b82f6",
                auth_boundary: "#ef4444",
                unspidered: "#f97316",
                low_coverage: "#f59e0b",
              };
              return (
                <div key={i} style={{ padding: "6px 0", borderBottom: i < coverageGaps.length - 1 ? "1px solid var(--border)" : "none" }}>
                  <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 2 }}>
                    <Badge text={g.gap_type} color={gapColors[g.gap_type]} />
                    <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text-primary)" }}>{g.url}</span>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 2 }}>{g.detail}</div>
                  <div style={{ fontSize: 11, color: "var(--accent-green)" }}>{g.suggested_action}</div>
                </div>
              );
            })}
          </div>
        </>
      )}

      {/* Endpoint Clusters */}
      {endpointClusters.length > 0 && (
        <>
          <SectionTitle>Endpoint Clusters ({endpointClusters.length})</SectionTitle>
          <div style={cardStyle}>
            {endpointClusters.map((c: EndpointCluster, i: number) => (
              <div key={i} style={{ borderBottom: i < endpointClusters.length - 1 ? "1px solid var(--border)" : "none" }}>
                <div
                  style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", cursor: "pointer" }}
                  onClick={() => setExpandedCluster(expandedCluster === c.template ? null : c.template)}
                >
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <span style={{ fontFamily: "monospace", fontSize: 12, color: "var(--accent-blue)" }}>{c.template}</span>
                    {c.has_auth_boundary && <Badge text="AUTH" color="#ef4444" />}
                  </div>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{c.count} endpoints</span>
                    {c.methods.map((m) => <Badge key={m} text={m} color="#3b82f6" />)}
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{expandedCluster === c.template ? "\u25B2" : "\u25BC"}</span>
                  </div>
                </div>
                {expandedCluster === c.template && (
                  <div style={{ padding: "4px 0 8px 12px" }}>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                      Coverage: {c.coverage_alpha.toFixed(0)}/{c.coverage_beta.toFixed(0)} |
                      Params: {c.param_names.join(", ") || "none"}
                    </div>
                    {c.sample_urls.map((u, j) => (
                      <div key={j} style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text-secondary)", padding: "1px 0" }}>{u}</div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// ── Hypothesis Tab ───────────────────────────────────────────
function HypothesisTab() {
  const { testHypothesis, authRoles, fetchAuthRoles } = useCrawlStore();
  const [hypothesis, setHypothesis] = useState("");
  const [urls, setUrls] = useState("");
  const [methods, setMethods] = useState<Record<string, boolean>>({ GET: true, POST: false, PUT: false, DELETE: false, PATCH: false });
  const [priority, setPriority] = useState(20);
  const [authRole, setAuthRole] = useState("");
  const [result, setResult] = useState("");
  const [history, setHistory] = useState<Array<{ hypothesis: string; result: string; ts: number }>>([]);

  useEffect(() => {
    fetchAuthRoles();
  }, [fetchAuthRoles]);

  async function handleTest() {
    if (!hypothesis) return;
    const testUrls = urls.split("\n").map((u) => u.trim()).filter(Boolean);
    const selectedMethods = Object.entries(methods).filter(([, v]) => v).map(([k]) => k);
    const msg = await testHypothesis(hypothesis, testUrls, selectedMethods, priority, authRole || undefined);
    setResult(msg);
    setHistory((h) => [{ hypothesis, result: msg, ts: Date.now() }, ...h.slice(0, 9)]);
  }

  return (
    <div>
      <SectionTitle>Test Hypothesis</SectionTitle>
      <div style={cardStyle}>
        <div style={{ marginBottom: 10 }}>
          <div style={labelStyle}>Hypothesis</div>
          <textarea
            style={{ ...inputStyle, minHeight: 60, resize: "vertical", fontFamily: "inherit" }}
            placeholder="e.g., Hidden admin API behind /internal/ prefix"
            value={hypothesis}
            onChange={(e) => setHypothesis(e.target.value)}
          />
        </div>
        <div style={{ marginBottom: 10 }}>
          <div style={labelStyle}>Target URLs (one per line, optional)</div>
          <textarea
            style={{ ...inputStyle, minHeight: 50, resize: "vertical", fontFamily: "monospace", fontSize: 12 }}
            placeholder={"/internal/admin\n/internal/config\n/internal/debug"}
            value={urls}
            onChange={(e) => setUrls(e.target.value)}
          />
        </div>
        <div style={{ display: "flex", gap: 16, alignItems: "flex-end", flexWrap: "wrap", marginBottom: 10 }}>
          <div>
            <div style={labelStyle}>Methods</div>
            <div style={{ display: "flex", gap: 6 }}>
              {Object.keys(methods).map((m) => (
                <label key={m} style={{ display: "flex", alignItems: "center", gap: 3, fontSize: 12, color: "var(--text-secondary)", cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={methods[m]}
                    onChange={(e) => setMethods((prev) => ({ ...prev, [m]: e.target.checked }))}
                  />
                  {m}
                </label>
              ))}
            </div>
          </div>
          <div style={{ width: 80 }}>
            <div style={labelStyle}>Priority</div>
            <input
              type="number"
              min={1}
              max={100}
              style={inputStyle}
              value={priority}
              onChange={(e) => setPriority(Number(e.target.value))}
            />
          </div>
          <div style={{ minWidth: 120 }}>
            <div style={labelStyle}>Auth Role</div>
            <select
              style={{ ...inputStyle, cursor: "pointer" }}
              value={authRole}
              onChange={(e) => setAuthRole(e.target.value)}
            >
              <option value="">No auth</option>
              {authRoles.map((r) => (
                <option key={r.name} value={r.name}>{r.name}</option>
              ))}
            </select>
          </div>
        </div>
        <button style={btnPrimary} onClick={handleTest}>Test</button>

        {result && (
          <div style={{ marginTop: 10, fontSize: 12, color: "var(--accent-green)", background: "var(--bg-tertiary)", padding: 8, borderRadius: 4 }}>
            {result}
          </div>
        )}
      </div>

      {/* History */}
      {history.length > 0 && (
        <>
          <SectionTitle>Recent Tests</SectionTitle>
          <div style={cardStyle}>
            {history.map((h, i) => (
              <div key={i} style={{ padding: "6px 0", borderBottom: i < history.length - 1 ? "1px solid var(--border)" : "none" }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-primary)" }}>{h.hypothesis}</div>
                <div style={{ fontSize: 11, color: "var(--accent-green)" }}>{h.result}</div>
                <div style={{ fontSize: 10, color: "var(--text-muted)" }}>{new Date(h.ts).toLocaleTimeString()}</div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// ── Queue Tab ────────────────────────────────────────────────
function QueueTab() {
  const {
    queueStats, queueItems, mergePreview, autoMergeRules, stats,
    fetchQueueStats, fetchQueueItems, fetchMergePreview, fetchAutoMergeRules,
    pauseQueue, resumeQueue, clearQueue, mergeQueue, reprioritizeQueue, removeFromQueue,
    addAutoMergeRule, removeAutoMergeRule,
  } = useCrawlStore();
  const [removePattern, setRemovePattern] = useState("");
  const [removeResult, setRemoveResult] = useState("");
  const [reprioPattern, setReprioPattern] = useState("");
  const [reprioPriority, setReprioPriority] = useState(20);
  const [mergeStrategy, setMergeStrategy] = useState<string>("batch_endpoints");
  const [mergeFilter, setMergeFilter] = useState("");
  const [actionMsg, setActionMsg] = useState("");
  const [amPattern, setAmPattern] = useState("");
  const [amMax, setAmMax] = useState(3);

  useEffect(() => {
    fetchQueueStats();
    fetchQueueItems();
    fetchAutoMergeRules();
  }, [fetchQueueStats, fetchQueueItems, fetchAutoMergeRules]);

  // Auto-refresh every 3s
  useEffect(() => {
    const interval = setInterval(() => { fetchQueueStats(); fetchQueueItems(); }, 3000);
    return () => clearInterval(interval);
  }, [fetchQueueStats, fetchQueueItems]);

  const qs: QueueDetailedStats | null = queueStats;

  return (
    <div>
      {/* Queue Stats */}
      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        {[
          { label: "Queue Size", value: qs?.queue_size ?? stats.queue_size ?? 0, color: "var(--accent-blue)" },
          { label: "Total Queued", value: qs?.total_queued ?? stats.requests_queued ?? 0 },
          { label: "Dropped", value: qs?.total_dropped ?? stats.requests_dropped ?? 0 },
          { label: "Auto-Merged", value: qs?.total_auto_merged ?? 0, color: "#8b5cf6" },
          { label: "In-Flight", value: qs?.active_requests ?? 0, color: "var(--accent-orange)" },
        ].map((s) => (
          <div key={s.label} style={{ ...cardStyle, flex: 1, textAlign: "center", marginBottom: 0 }}>
            <div style={labelStyle}>{s.label}</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: s.color || "var(--text-primary)" }}>
              {typeof s.value === "number" ? s.value.toLocaleString() : s.value}
            </div>
          </div>
        ))}
      </div>

      {/* Pause / Resume / Clear controls */}
      <SectionTitle>Queue Control</SectionTitle>
      <div style={cardStyle}>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{
              display: "inline-block", width: 10, height: 10, borderRadius: "50%",
              background: qs?.is_paused ? "var(--accent-orange)" : "var(--accent-green)",
            }} />
            <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
              {qs?.is_paused ? "PAUSED" : "RUNNING"}
            </span>
          </div>
          <button
            style={{ ...btnSecondary, ...(qs?.is_paused ? {} : { background: "var(--accent-orange)", color: "#fff", border: "none" }) }}
            onClick={async () => {
              const msg = qs?.is_paused ? await resumeQueue() : await pauseQueue();
              setActionMsg(msg);
              fetchQueueStats();
            }}
          >
            {qs?.is_paused ? "Resume" : "Pause"}
          </button>
          <button
            style={btnDanger}
            onClick={async () => {
              if (!confirm("Clear all queued requests?")) return;
              const msg = await clearQueue();
              setActionMsg(msg);
              fetchQueueStats();
              fetchQueueItems();
            }}
          >
            Clear Queue
          </button>
          <button style={{ ...btnSecondary, fontSize: 11 }} onClick={() => { fetchQueueStats(); fetchQueueItems(); }}>
            Refresh
          </button>
        </div>
        {actionMsg && <div style={{ marginTop: 8, fontSize: 12, color: "var(--accent-green)" }}>{actionMsg}</div>}
      </div>

      {/* Source & Priority breakdown */}
      {qs && (Object.keys(qs.by_source).length > 0 || Object.keys(qs.by_priority).length > 0) && (
        <>
          <SectionTitle>Queue Breakdown</SectionTitle>
          <div style={{ display: "flex", gap: 12 }}>
            {Object.keys(qs.by_source).length > 0 && (
              <div style={{ ...cardStyle, flex: 1 }}>
                <div style={{ ...labelStyle, marginBottom: 8 }}>By Source</div>
                {Object.entries(qs.by_source).sort((a, b) => b[1] - a[1]).map(([src, count]) => (
                  <div key={src} style={{ display: "flex", justifyContent: "space-between", padding: "2px 0", fontSize: 12 }}>
                    <span style={{ color: "var(--text-secondary)", fontFamily: "monospace" }}>{src}</span>
                    <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{count}</span>
                  </div>
                ))}
              </div>
            )}
            {Object.keys(qs.by_priority).length > 0 && (
              <div style={{ ...cardStyle, flex: 1 }}>
                <div style={{ ...labelStyle, marginBottom: 8 }}>By Priority</div>
                {Object.entries(qs.by_priority).sort().map(([band, count]) => (
                  <div key={band} style={{ display: "flex", justifyContent: "space-between", padding: "2px 0", fontSize: 12 }}>
                    <span style={{ color: "var(--text-secondary)" }}>{band}</span>
                    <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {/* Queue Items table */}
      <SectionTitle>Queue Items ({qs?.queue_size ?? queueItems.length})</SectionTitle>
      <div style={cardStyle}>
        {queueItems.length === 0 ? (
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Queue is empty.</div>
        ) : (
          <div style={{ overflowX: "auto", maxHeight: 300, overflowY: "auto" }}>
            <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)", color: "var(--text-muted)", position: "sticky", top: 0, background: "var(--bg-secondary)" }}>
                  <th style={{ textAlign: "left", padding: "4px 8px" }}>URL</th>
                  <th style={{ textAlign: "center", padding: "4px 8px", width: 50 }}>Method</th>
                  <th style={{ textAlign: "right", padding: "4px 8px", width: 50 }}>Prio</th>
                  <th style={{ textAlign: "right", padding: "4px 8px", width: 40 }}>Depth</th>
                  <th style={{ textAlign: "left", padding: "4px 8px" }}>Source</th>
                </tr>
              </thead>
              <tbody>
                {queueItems.map((item: QueueItem, i: number) => (
                  <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "3px 8px", fontFamily: "monospace", fontSize: 11, color: "var(--accent-blue)", maxWidth: 400, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {item.url}
                    </td>
                    <td style={{ padding: "3px 8px", textAlign: "center" }}>
                      <Badge text={item.method} color="#3b82f6" />
                    </td>
                    <td style={{ padding: "3px 8px", textAlign: "right", fontWeight: 600, color: item.priority >= 20 ? "var(--accent-orange)" : "var(--text-secondary)" }}>
                      {item.priority}
                    </td>
                    <td style={{ padding: "3px 8px", textAlign: "right", color: "var(--text-muted)" }}>{item.depth}</td>
                    <td style={{ padding: "3px 8px", fontSize: 11, color: "var(--text-muted)" }}>{item.source_module}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Merge Requests */}
      <SectionTitle>Merge Requests</SectionTitle>
      <div style={cardStyle}>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap", marginBottom: 10 }}>
          <div style={{ minWidth: 160 }}>
            <div style={labelStyle}>Strategy</div>
            <select
              style={{ ...inputStyle, cursor: "pointer" }}
              value={mergeStrategy}
              onChange={(e) => setMergeStrategy(e.target.value)}
            >
              <option value="batch_endpoints">Batch (1 per template)</option>
              <option value="sample_template">Sample (N per template)</option>
              <option value="combine_params">Combine params</option>
            </select>
          </div>
          <div style={{ flex: 1 }}>
            <div style={labelStyle}>URL Filter (optional)</div>
            <input style={inputStyle} placeholder="/api/users/..." value={mergeFilter} onChange={(e) => setMergeFilter(e.target.value)} />
          </div>
          <button style={btnSecondary} onClick={() => fetchMergePreview(mergeStrategy, mergeFilter || undefined)}>
            Preview
          </button>
          <button
            style={btnPrimary}
            onClick={async () => {
              await mergeQueue(mergeStrategy, mergeFilter || undefined);
              setActionMsg("Merge executed");
              fetchQueueStats();
              fetchQueueItems();
            }}
          >
            Merge
          </button>
        </div>
        {mergePreview && mergePreview.length > 0 && (
          <div style={{ maxHeight: 200, overflowY: "auto" }}>
            <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)", color: "var(--text-muted)" }}>
                  <th style={{ textAlign: "left", padding: "3px 6px" }}>Template</th>
                  <th style={{ textAlign: "right", padding: "3px 6px" }}>Requests</th>
                  <th style={{ textAlign: "left", padding: "3px 6px" }}>Methods</th>
                </tr>
              </thead>
              <tbody>
                {mergePreview.map((c: MergeCandidate, i: number) => (
                  <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "3px 6px", fontFamily: "monospace", color: "var(--accent-blue)" }}>{c.template}</td>
                    <td style={{ padding: "3px 6px", textAlign: "right", fontWeight: 600 }}>{c.request_count}</td>
                    <td style={{ padding: "3px 6px" }}>{c.methods.map((m) => <Badge key={m} text={m} color="#3b82f6" />)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Reprioritize */}
      <SectionTitle>Reprioritize</SectionTitle>
      <div style={cardStyle}>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
          <div style={{ flex: 1 }}>
            <div style={labelStyle}>URL Pattern</div>
            <input style={inputStyle} placeholder="/admin/.*" value={reprioPattern} onChange={(e) => setReprioPattern(e.target.value)} />
          </div>
          <div style={{ width: 100 }}>
            <div style={labelStyle}>New Priority</div>
            <input type="number" min={0} max={100} style={inputStyle} value={reprioPriority} onChange={(e) => setReprioPriority(Number(e.target.value))} />
          </div>
          <button
            style={btnPrimary}
            onClick={async () => {
              if (!reprioPattern) return;
              await reprioritizeQueue([{ url_pattern: reprioPattern, new_priority: reprioPriority }]);
              setActionMsg(`Reprioritized: ${reprioPattern} -> ${reprioPriority}`);
              fetchQueueStats();
              fetchQueueItems();
            }}
          >
            Apply
          </button>
        </div>
      </div>

      {/* Remove from Queue */}
      <SectionTitle>Remove from Queue</SectionTitle>
      <div style={cardStyle}>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
          <div style={{ flex: 1 }}>
            <div style={labelStyle}>URL Pattern(s) — comma separated</div>
            <input style={inputStyle} placeholder="/static/,/assets/,/fonts/" value={removePattern} onChange={(e) => setRemovePattern(e.target.value)} />
          </div>
          <button
            style={btnDanger}
            onClick={async () => {
              if (!removePattern) return;
              const patterns = removePattern.split(",").map((p) => p.trim()).filter(Boolean);
              const msg = await removeFromQueue(patterns);
              setRemoveResult(msg);
              fetchQueueStats();
              fetchQueueItems();
            }}
          >
            Remove
          </button>
        </div>
        {removeResult && <div style={{ marginTop: 8, fontSize: 12, color: "var(--accent-green)" }}>{removeResult}</div>}
      </div>

      {/* Auto-Merge Rules */}
      <SectionTitle>Auto-Merge Rules</SectionTitle>
      <div style={cardStyle}>
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
          Auto-drop URLs when the same template already has N entries queued. Persists for the session.
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-end", marginBottom: 10 }}>
          <div style={{ flex: 1 }}>
            <div style={labelStyle}>Template Pattern</div>
            <input style={inputStyle} placeholder="/api/users/{id} or /blog/* (trailing *)" value={amPattern} onChange={(e) => setAmPattern(e.target.value)} />
          </div>
          <div style={{ width: 100 }}>
            <div style={labelStyle}>Max Count</div>
            <input type="number" min={1} max={100} style={inputStyle} value={amMax} onChange={(e) => setAmMax(Number(e.target.value))} />
          </div>
          <button
            style={btnPrimary}
            onClick={async () => {
              if (!amPattern) return;
              const msg = await addAutoMergeRule(amPattern, amMax);
              setActionMsg(msg);
              setAmPattern("");
            }}
          >
            Add Rule
          </button>
        </div>
        {autoMergeRules && Object.keys(autoMergeRules.rules).length > 0 ? (
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 4 }}>
              Active Rules ({Object.keys(autoMergeRules.rules).length}) | Dropped: {autoMergeRules.total_auto_merged}
            </div>
            {Object.entries(autoMergeRules.rules).map(([pattern, max]) => (
              <div key={pattern} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "4px 0", borderBottom: "1px solid var(--border)" }}>
                <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--accent-blue)" }}>{pattern}</span>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>max {max}</span>
                  <button
                    style={{ ...btnDanger, fontSize: 10, padding: "2px 8px" }}
                    onClick={async () => {
                      await removeAutoMergeRule(pattern);
                    }}
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>No auto-merge rules active.</div>
        )}
      </div>
    </div>
  );
}

// ── Playbook Tab ─────────────────────────────────────────────
function PlaybookTab() {
  const { playbookResult, fetchPlaybookResults } = useCrawlStore();

  useEffect(() => {
    fetchPlaybookResults();
  }, [fetchPlaybookResults]);

  // Auto-refresh every 5s during crawl
  useEffect(() => {
    const interval = setInterval(fetchPlaybookResults, 5000);
    return () => clearInterval(interval);
  }, [fetchPlaybookResults]);

  const pb: PlaybookResult | null = playbookResult;

  if (!pb) {
    return (
      <div style={{ padding: 20, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
        Playbook not active. Start a crawl with --dashboard to see results.
      </div>
    );
  }

  const sevColors: Record<string, string> = { fail: "#ef4444", warn: "#f59e0b", info: "var(--text-muted)" };
  const sevLabels: Record<string, string> = { fail: "FAIL", warn: "WARN", info: "INFO" };

  const failCount = pb.summary.fail || 0;
  const warnCount = pb.summary.warn || 0;
  const infoCount = pb.summary.info || 0;

  return (
    <div>
      {/* Summary bar */}
      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        {[
          { label: "Plays Run", value: pb.plays_run, color: "var(--accent-blue)" },
          { label: "FAIL", value: failCount, color: failCount > 0 ? "#ef4444" : "var(--text-muted)" },
          { label: "WARN", value: warnCount, color: warnCount > 0 ? "#f59e0b" : "var(--text-muted)" },
          { label: "INFO", value: infoCount, color: "var(--text-muted)" },
        ].map((s) => (
          <div key={s.label} style={{ ...cardStyle, flex: 1, textAlign: "center", marginBottom: 0 }}>
            <div style={labelStyle}>{s.label}</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Phases checked */}
      {pb.phases_checked.length > 0 && (
        <div style={{ marginBottom: 12, display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 600 }}>Phases:</span>
          {pb.phases_checked.map((p) => (
            <Badge key={p} text={p} color="var(--accent-blue)" />
          ))}
        </div>
      )}

      {/* Findings - FAIL first, then WARN, then INFO */}
      <SectionTitle>Findings ({pb.findings.length})</SectionTitle>
      <div style={cardStyle}>
        {pb.findings.length === 0 ? (
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>No findings yet. Waiting for phase completions...</div>
        ) : (
          [...pb.findings]
            .sort((a, b) => {
              const order: Record<string, number> = { fail: 0, warn: 1, info: 2 };
              return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
            })
            .map((f: PlaybookFinding, i: number) => (
              <div
                key={i}
                style={{
                  padding: "8px 0",
                  borderBottom: i < pb.findings.length - 1 ? "1px solid var(--border)" : "none",
                  borderLeft: `3px solid ${sevColors[f.severity] || "var(--text-muted)"}`,
                  paddingLeft: 10,
                  marginBottom: 2,
                }}
              >
                <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 3 }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: sevColors[f.severity], textTransform: "uppercase" }}>
                    {sevLabels[f.severity] || f.severity}
                  </span>
                  <Badge text={f.play} color="var(--accent-blue)" />
                  <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>{f.title}</span>
                </div>
                <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 2 }}>{f.detail}</div>
                {f.auto_action && (
                  <div style={{ fontSize: 11, color: "var(--accent-green)" }}>Auto-action: {f.auto_action}</div>
                )}
              </div>
            ))
        )}
      </div>

      {/* Hints */}
      {pb.hints.length > 0 && (
        <>
          <SectionTitle>Next Crawl Hints ({pb.hints.length})</SectionTitle>
          <div style={cardStyle}>
            {pb.hints.map((h: NextCrawlHint, i: number) => (
              <div key={i} style={{ padding: "6px 0", borderBottom: i < pb.hints.length - 1 ? "1px solid var(--border)" : "none" }}>
                <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 2 }}>
                  <Badge text={h.action} color="#8b5cf6" />
                </div>
                <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>{h.description}</div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Refresh */}
      <div style={{ textAlign: "right", marginTop: 8 }}>
        <button style={{ ...btnSecondary, fontSize: 11 }} onClick={fetchPlaybookResults}>
          Refresh
        </button>
      </div>
    </div>
  );
}

// ── Main CommandCenter Component ─────────────────────────────
export function CommandCenter() {
  const [activeTab, setActiveTab] = useState<SubTab>("results");

  const tabs: { key: SubTab; label: string }[] = [
    { key: "results", label: "Results" },
    { key: "queue", label: "Queue" },
    { key: "playbook", label: "Playbook" },
    { key: "auth", label: "Auth" },
    { key: "intelligence", label: "Intelligence" },
    { key: "hypothesis", label: "Hypothesis" },
  ];

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Sub-tab bar */}
      <div
        style={{
          display: "flex",
          background: "var(--bg-secondary)",
          borderBottom: "1px solid var(--border)",
          padding: "0 12px",
          flexShrink: 0,
        }}
      >
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            style={{
              padding: "8px 18px",
              border: "none",
              borderBottom: activeTab === tab.key ? "2px solid var(--accent-blue)" : "2px solid transparent",
              background: "transparent",
              color: activeTab === tab.key ? "var(--accent-blue)" : "var(--text-secondary)",
              cursor: "pointer",
              fontSize: 13,
              fontWeight: activeTab === tab.key ? 600 : 400,
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
        {activeTab === "results" && <ResultsOpsTab />}
        {activeTab === "queue" && <QueueTab />}
        {activeTab === "playbook" && <PlaybookTab />}
        {activeTab === "auth" && <AuthTab />}
        {activeTab === "intelligence" && <IntelligenceTab />}
        {activeTab === "hypothesis" && <HypothesisTab />}
      </div>
    </div>
  );
}
