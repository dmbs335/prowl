import { useState } from "react";
import { useCrawlStore } from "../hooks/useCrawlStore";
import type { TechFingerprint } from "../types";

// ── category colors ────────────────────────────────────────
const CAT_COLORS: Record<string, string> = {
  server: "#ef4444",
  framework: "#3b82f6",
  cms: "#8b5cf6",
  js_library: "#a78bfa",
  css_framework: "#ec4899",
  cdn: "#f97316",
  waf: "#f59e0b",
  api: "#10b981",
  analytics: "#6b7280",
  font: "#6b7280",
};

const BOUNDARY_COLORS: Record<string, string> = {
  forbidden: "#ef4444",
  unauthorized: "#f97316",
  redirect_to_login: "#f59e0b",
  idor_candidate: "#a78bfa",
  role_difference: "#3b82f6",
};

// ── helpers ────────────────────────────────────────────────
function scoreColor(score: number): string {
  if (score >= 75) return "var(--accent-red)";
  if (score >= 50) return "var(--accent-orange)";
  if (score >= 25) return "var(--accent-yellow)";
  return "var(--accent-green)";
}

function SectionHeader({ title, count }: { title: string; count: number }) {
  return (
    <div
      style={{
        fontSize: 14,
        fontWeight: 700,
        color: "var(--text-primary)",
        marginBottom: 8,
        marginTop: 20,
        display: "flex",
        alignItems: "center",
        gap: 8,
      }}
    >
      {title}
      <span
        style={{
          fontSize: 11,
          fontWeight: 500,
          color: "var(--text-muted)",
          background: "var(--bg-tertiary)",
          padding: "2px 8px",
          borderRadius: 10,
        }}
      >
        {count}
      </span>
    </div>
  );
}

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

// ── Risk Summary ───────────────────────────────────────────
function RiskBanner() {
  const rs = useCrawlStore((s) => s.riskSummary);
  const techCount = useCrawlStore((s) => s.techStack.length);
  const ivCount = useCrawlStore((s) => s.inputVectors.length);
  const abCount = useCrawlStore((s) => s.authBoundaries.length);

  const score = rs?.score ?? 0;
  const metrics = [
    { label: "Endpoints", value: rs?.total_endpoints ?? 0, color: "var(--accent-blue)" },
    { label: "Input Vectors", value: rs?.total_input_vectors || ivCount, color: "var(--accent-green)" },
    { label: "High Risk", value: rs?.high_risk_vectors ?? 0, color: "var(--accent-red)" },
    { label: "Auth Boundaries", value: rs?.auth_boundaries_found || abCount, color: "var(--accent-orange)" },
    { label: "Technologies", value: techCount, color: "var(--accent-purple)" },
    { label: "Admin Paths", value: rs?.unprotected_admin_paths ?? 0, color: "var(--accent-yellow)" },
    { label: "Secrets", value: rs?.secrets_found ?? 0, color: rs?.secrets_found ? "var(--accent-red)" : "var(--text-muted)" },
  ];

  return (
    <div
      style={{
        background: "var(--bg-tertiary)",
        borderRadius: 8,
        padding: 16,
        display: "flex",
        alignItems: "center",
        gap: 24,
      }}
    >
      {/* Score */}
      <div style={{ textAlign: "center", minWidth: 80 }}>
        <div
          style={{
            fontSize: 36,
            fontWeight: 800,
            fontFamily: "monospace",
            color: scoreColor(score),
            lineHeight: 1,
          }}
        >
          {score > 0 ? score.toFixed(0) : "--"}
        </div>
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
          Risk Score
        </div>
      </div>

      {/* Divider */}
      <div style={{ width: 1, height: 48, background: "var(--border)" }} />

      {/* Metric cards */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px 20px", flex: 1 }}>
        {metrics.map((m) => (
          <div key={m.label} style={{ minWidth: 90 }}>
            <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "monospace", color: m.color }}>
              {m.value}
            </div>
            <div style={{ fontSize: 10, color: "var(--text-muted)" }}>{m.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Tech Stack ─────────────────────────────────────────────
function TechStackSection() {
  const techStack = useCrawlStore((s) => s.techStack);

  if (techStack.length === 0) {
    return (
      <>
        <SectionHeader title="Tech Stack" count={0} />
        <div style={{ color: "var(--text-muted)", fontSize: 12, padding: "8px 0" }}>
          No technologies detected
        </div>
      </>
    );
  }

  // Group by category
  const grouped: Record<string, TechFingerprint[]> = {};
  for (const t of techStack) {
    const cat = t.category || "other";
    (grouped[cat] ??= []).push(t);
  }

  return (
    <>
      <SectionHeader title="Tech Stack" count={techStack.length} />
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {Object.entries(grouped)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([category, techs]) => (
            <div key={category}>
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 600,
                  color: CAT_COLORS[category] || "var(--text-muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.5px",
                  marginBottom: 4,
                }}
              >
                {category.replace(/_/g, " ")}
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {techs.sort((a, b) => b.confidence - a.confidence).map((t) => (
                  <div
                    key={t.name}
                    title={`${(t.confidence * 100).toFixed(0)}% confidence\n${t.evidence.join("\n")}`}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      padding: "4px 10px",
                      borderRadius: 6,
                      background: "var(--bg-secondary)",
                      border: "1px solid var(--border)",
                      fontSize: 12,
                    }}
                  >
                    <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{t.name}</span>
                    {t.version && (
                      <span style={{ color: "var(--text-muted)", fontSize: 11 }}>{t.version}</span>
                    )}
                    {/* Confidence bar */}
                    <div
                      style={{
                        width: 30,
                        height: 3,
                        background: "var(--bg-tertiary)",
                        borderRadius: 2,
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          width: `${Math.min(t.confidence * 100, 100)}%`,
                          height: "100%",
                          background: CAT_COLORS[category] || "var(--accent-blue)",
                          borderRadius: 2,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
      </div>
    </>
  );
}

// ── Input Vectors ──────────────────────────────────────────
function InputVectorsSection() {
  const inputVectors = useCrawlStore((s) => s.inputVectors);
  const [filter, setFilter] = useState("");
  const [reflectedOnly, setReflectedOnly] = useState(false);
  const [locationFilter, setLocationFilter] = useState("");

  if (inputVectors.length === 0) {
    return (
      <>
        <SectionHeader title="Input Vectors" count={0} />
        <div style={{ color: "var(--text-muted)", fontSize: 12, padding: "8px 0" }}>
          No input vectors classified
        </div>
      </>
    );
  }

  const locations = [...new Set(inputVectors.map((iv) => iv.location))].sort();

  let filtered = inputVectors;
  if (filter) {
    const q = filter.toLowerCase();
    filtered = filtered.filter(
      (iv) => iv.name.toLowerCase().includes(q) || iv.endpoint_url.toLowerCase().includes(q) || iv.risk_indicators.some((r) => r.toLowerCase().includes(q))
    );
  }
  if (reflectedOnly) filtered = filtered.filter((iv) => iv.is_reflected);
  if (locationFilter) filtered = filtered.filter((iv) => iv.location === locationFilter);

  // Sort: high-risk first
  filtered = [...filtered].sort((a, b) => b.risk_indicators.length - a.risk_indicators.length);

  return (
    <>
      <SectionHeader title="Input Vectors" count={inputVectors.length} />

      {/* Toolbar */}
      <div style={{ display: "flex", gap: 8, marginBottom: 8, flexWrap: "wrap", alignItems: "center" }}>
        <input
          type="text"
          placeholder="Filter..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{
            padding: "4px 8px",
            fontSize: 12,
            background: "var(--bg-secondary)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            color: "var(--text-primary)",
            width: 160,
          }}
        />
        <select
          value={locationFilter}
          onChange={(e) => setLocationFilter(e.target.value)}
          style={{
            padding: "4px 8px",
            fontSize: 12,
            background: "var(--bg-secondary)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            color: "var(--text-primary)",
          }}
        >
          <option value="">All locations</option>
          {locations.map((l) => (
            <option key={l} value={l}>{l}</option>
          ))}
        </select>
        <label style={{ fontSize: 12, color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 4, cursor: "pointer" }}>
          <input type="checkbox" checked={reflectedOnly} onChange={(e) => setReflectedOnly(e.target.checked)} />
          Reflected only
        </label>
        <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
          {filtered.length} shown
        </span>
      </div>

      {/* Table */}
      <div style={{ overflowX: "auto" }}>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            fontSize: 12,
            fontFamily: "monospace",
          }}
        >
          <thead>
            <tr style={{ borderBottom: "1px solid var(--border)" }}>
              {["Name", "Location", "Type", "Refl", "Risk Indicators", "Endpoint"].map((h) => (
                <th
                  key={h}
                  style={{
                    padding: "6px 8px",
                    textAlign: "left",
                    color: "var(--text-muted)",
                    fontWeight: 600,
                    fontSize: 11,
                    textTransform: "uppercase",
                    letterSpacing: "0.3px",
                  }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 200).map((iv, i) => (
              <tr
                key={i}
                style={{
                  borderBottom: "1px solid var(--border)",
                  background: iv.risk_indicators.length > 0 ? "rgba(239,68,68,0.03)" : "transparent",
                }}
              >
                <td style={{ padding: "5px 8px", fontWeight: 600, color: "var(--text-primary)" }}>
                  {iv.name}
                </td>
                <td style={{ padding: "5px 8px", color: "var(--text-muted)" }}>{iv.location}</td>
                <td style={{ padding: "5px 8px", color: "var(--text-secondary)" }}>{iv.input_type}</td>
                <td style={{ padding: "5px 8px" }}>
                  {iv.is_reflected && (
                    <span style={{ color: "var(--accent-green)", fontSize: 14 }} title="Reflected in response">&#9679;</span>
                  )}
                </td>
                <td style={{ padding: "5px 8px" }}>
                  <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                    {iv.risk_indicators.map((r, j) => (
                      <Badge key={j} text={r} color="var(--accent-red)" />
                    ))}
                  </div>
                </td>
                <td
                  style={{
                    padding: "5px 8px",
                    color: "var(--text-muted)",
                    maxWidth: 300,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  title={iv.endpoint_url}
                >
                  {(() => { try { return new URL(iv.endpoint_url).pathname; } catch { return iv.endpoint_url; } })()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {filtered.length > 200 && (
        <div style={{ fontSize: 11, color: "var(--text-muted)", padding: 8 }}>
          Showing 200 of {filtered.length} vectors
        </div>
      )}
    </>
  );
}

// ── Auth Boundaries ────────────────────────────────────────
function AuthBoundariesSection() {
  const authBoundaries = useCrawlStore((s) => s.authBoundaries);

  if (authBoundaries.length === 0) {
    return (
      <>
        <SectionHeader title="Auth Boundaries" count={0} />
        <div style={{ color: "var(--text-muted)", fontSize: 12, padding: "8px 0" }}>
          No auth boundaries detected
        </div>
      </>
    );
  }

  return (
    <>
      <SectionHeader title="Auth Boundaries" count={authBoundaries.length} />
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, fontFamily: "monospace" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid var(--border)" }}>
              {["URL", "Method", "Type", "Unauth", "Auth", "Access Matrix"].map((h) => (
                <th
                  key={h}
                  style={{
                    padding: "6px 8px",
                    textAlign: "left",
                    color: "var(--text-muted)",
                    fontWeight: 600,
                    fontSize: 11,
                    textTransform: "uppercase",
                    letterSpacing: "0.3px",
                  }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {authBoundaries.map((ab, i) => (
              <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                <td
                  style={{
                    padding: "5px 8px",
                    color: "var(--text-primary)",
                    maxWidth: 300,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  title={ab.url}
                >
                  {(() => { try { return new URL(ab.url).pathname; } catch { return ab.url; } })()}
                </td>
                <td style={{ padding: "5px 8px", color: "var(--accent-blue)", fontWeight: 600 }}>
                  {ab.method}
                </td>
                <td style={{ padding: "5px 8px" }}>
                  <Badge text={ab.boundary_type} color={BOUNDARY_COLORS[ab.boundary_type]} />
                </td>
                <td style={{ padding: "5px 8px", color: "var(--accent-red)" }}>
                  {ab.unauth_status || "-"}
                </td>
                <td style={{ padding: "5px 8px", color: "var(--accent-green)" }}>
                  {ab.auth_status || "-"}
                </td>
                <td style={{ padding: "5px 8px", color: "var(--text-muted)", fontSize: 11 }}>
                  {Object.entries(ab.access_matrix).map(([role, status]) => (
                    <span key={role} style={{ marginRight: 8 }}>
                      {role}:{status}
                    </span>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ── Main Component ─────────────────────────────────────────
export function AttackSurfaceView() {
  return (
    <div style={{ height: "100%", overflow: "auto", padding: 16, maxWidth: 1200 }}>
      <RiskBanner />
      <TechStackSection />
      <InputVectorsSection />
      <AuthBoundariesSection />
      <div style={{ height: 32 }} />
    </div>
  );
}
