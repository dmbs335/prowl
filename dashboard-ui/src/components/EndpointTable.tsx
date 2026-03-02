import { useMemo, useState } from "react";
import { useCrawlStore } from "../hooks/useCrawlStore";

const METHOD_COLORS: Record<string, string> = {
  GET: "var(--accent-blue)",
  POST: "var(--accent-green)",
  PUT: "var(--accent-orange)",
  DELETE: "var(--accent-red)",
  PATCH: "var(--accent-purple)",
  HEAD: "var(--text-muted)",
  OPTIONS: "var(--text-muted)",
};

const STATUS_COLORS: Record<string, string> = {
  "2": "var(--accent-green)",
  "3": "var(--accent-blue)",
  "4": "var(--accent-orange)",
  "5": "var(--accent-red)",
};

const SOURCE_LABELS: Record<string, string> = {
  s1_spider: "Spider",
  s2_bruteforce: "Brute",
  s3_params: "Params",
  s4_js: "JS",
  s5_api: "API",
  s6_passive: "Passive",
  s7_auth: "Auth",
};

export function EndpointTable() {
  const endpoints = useCrawlStore((s) => s.endpoints);
  const setSelectedNode = useCrawlStore((s) => s.setSelectedNode);
  const [filter, setFilter] = useState("");
  const [sortBy, setSortBy] = useState<"url" | "method" | "status" | "params">("url");
  const [methodFilter, setMethodFilter] = useState<string>("");

  const filtered = useMemo(() => {
    let result = endpoints;
    if (filter) {
      const lower = filter.toLowerCase();
      result = result.filter(
        (ep) =>
          ep.url.toLowerCase().includes(lower) ||
          ep.tags.some((t) => t.toLowerCase().includes(lower))
      );
    }
    if (methodFilter) {
      result = result.filter((ep) => ep.method === methodFilter);
    }
    result = [...result].sort((a, b) => {
      switch (sortBy) {
        case "method":
          return a.method.localeCompare(b.method);
        case "status":
          return (a.status_code ?? 0) - (b.status_code ?? 0);
        case "params":
          return b.param_count - a.param_count;
        default:
          return a.url.localeCompare(b.url);
      }
    });
    return result;
  }, [endpoints, filter, sortBy, methodFilter]);

  const methods = useMemo(() => {
    const set = new Set(endpoints.map((e) => e.method));
    return Array.from(set).sort();
  }, [endpoints]);

  const thStyle: React.CSSProperties = {
    padding: "6px 10px",
    textAlign: "left",
    fontSize: 11,
    color: "var(--text-muted)",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.5px",
    cursor: "pointer",
    borderBottom: "1px solid var(--border)",
    position: "sticky",
    top: 0,
    background: "var(--bg-secondary)",
    zIndex: 1,
  };

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
      {/* Toolbar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "8px 12px",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-secondary)",
          flexShrink: 0,
        }}
      >
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter endpoints..."
          style={{
            flex: 1,
            padding: "4px 10px",
            background: "var(--bg-tertiary)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            color: "var(--text-primary)",
            fontSize: 13,
            fontFamily: "monospace",
            outline: "none",
          }}
        />
        <select
          value={methodFilter}
          onChange={(e) => setMethodFilter(e.target.value)}
          style={{
            padding: "4px 8px",
            background: "var(--bg-tertiary)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            color: "var(--text-secondary)",
            fontSize: 12,
          }}
        >
          <option value="">All Methods</option>
          {methods.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
          {filtered.length}/{endpoints.length}
        </span>
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflow: "auto" }}>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            fontSize: 12,
            fontFamily: "monospace",
          }}
        >
          <thead>
            <tr>
              <th style={{ ...thStyle, width: 60 }} onClick={() => setSortBy("method")}>
                Method {sortBy === "method" ? "^" : ""}
              </th>
              <th style={{ ...thStyle, width: 50 }} onClick={() => setSortBy("status")}>
                Code {sortBy === "status" ? "^" : ""}
              </th>
              <th style={thStyle} onClick={() => setSortBy("url")}>
                URL {sortBy === "url" ? "^" : ""}
              </th>
              <th style={{ ...thStyle, width: 50 }} onClick={() => setSortBy("params")}>
                Params {sortBy === "params" ? "^" : ""}
              </th>
              <th style={{ ...thStyle, width: 60 }}>Source</th>
              <th style={thStyle}>Tags</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((ep, i) => {
              const statusColor =
                STATUS_COLORS[String(ep.status_code)?.[0]] || "var(--text-muted)";
              return (
                <tr
                  key={i}
                  onClick={() => setSelectedNode(ep.url)}
                  style={{ cursor: "pointer" }}
                  onMouseEnter={(e) =>
                    (e.currentTarget.style.background = "var(--bg-tertiary)")
                  }
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.background = "transparent")
                  }
                >
                  <td
                    style={{
                      padding: "4px 10px",
                      color: METHOD_COLORS[ep.method] || "var(--text-secondary)",
                      fontWeight: 600,
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    {ep.method}
                  </td>
                  <td
                    style={{
                      padding: "4px 10px",
                      color: statusColor,
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    {ep.status_code || "-"}
                  </td>
                  <td
                    style={{
                      padding: "4px 10px",
                      color: "var(--text-primary)",
                      borderBottom: "1px solid var(--border)",
                      wordBreak: "break-all",
                      maxWidth: 0,
                    }}
                  >
                    {(() => {
                      try {
                        const u = new URL(ep.url);
                        return u.pathname + u.search;
                      } catch {
                        return ep.url;
                      }
                    })()}
                  </td>
                  <td
                    style={{
                      padding: "4px 10px",
                      textAlign: "center",
                      color:
                        ep.param_count > 0
                          ? "var(--accent-green)"
                          : "var(--text-muted)",
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    {ep.param_count || "-"}
                  </td>
                  <td
                    style={{
                      padding: "4px 10px",
                      fontSize: 11,
                      color: "var(--text-muted)",
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    {SOURCE_LABELS[ep.source_module] || ep.source_module}
                  </td>
                  <td
                    style={{
                      padding: "4px 10px",
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    {ep.tags.map((tag, j) => (
                      <span
                        key={j}
                        style={{
                          fontSize: 10,
                          padding: "1px 6px",
                          borderRadius: 8,
                          background: "var(--bg-tertiary)",
                          color: "var(--text-secondary)",
                          marginRight: 3,
                          display: "inline-block",
                        }}
                      >
                        {tag}
                      </span>
                    ))}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {filtered.length === 0 && (
          <div
            style={{
              padding: 24,
              textAlign: "center",
              color: "var(--text-muted)",
            }}
          >
            {endpoints.length === 0
              ? "Waiting for endpoints..."
              : "No endpoints match filter"}
          </div>
        )}
      </div>
    </div>
  );
}
