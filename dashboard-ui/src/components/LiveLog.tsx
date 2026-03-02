import { useEffect, useRef } from "react";
import { useCrawlStore } from "../hooks/useCrawlStore";

const LEVEL_COLORS: Record<string, string> = {
  info: "var(--text-secondary)",
  warning: "var(--accent-yellow)",
  error: "var(--accent-red)",
  debug: "var(--text-muted)",
};

const MODULE_COLORS: Record<string, string> = {
  s1_spider: "#3b82f6",
  s2_bruteforce: "#f97316",
  s3_params: "#10b981",
  s4_js: "#8b5cf6",
  s5_api: "#ec4899",
  s6_passive: "#6b7280",
  s7_auth: "#f59e0b",
  pipeline: "#3b82f6",
  secret: "#ef4444",
};

function formatTs(ts: number): string {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

export function LiveLog() {
  const logs = useCrawlStore((s) => s.logs);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs.length]);

  return (
    <div
      ref={containerRef}
      style={{
        height: 140,
        overflowY: "auto",
        padding: "4px 12px",
        background: "var(--bg-primary)",
        borderTop: "1px solid var(--border)",
        fontFamily: "monospace",
        fontSize: 12,
        flexShrink: 0,
      }}
    >
      {logs.slice(-80).map((log, i) => (
        <div
          key={i}
          style={{
            color: LEVEL_COLORS[log.level] || "var(--text-secondary)",
            padding: "1px 0",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
            display: "flex",
            gap: 6,
          }}
        >
          <span style={{ color: "var(--text-muted)", flexShrink: 0, width: 55 }}>
            {formatTs(log.ts)}
          </span>
          <span
            style={{
              color: MODULE_COLORS[log.module] || "var(--text-muted)",
              flexShrink: 0,
              width: 70,
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}
          >
            {log.module}
          </span>
          <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>
            {log.message}
          </span>
        </div>
      ))}
      {logs.length === 0 && (
        <div style={{ color: "var(--text-muted)", padding: 8 }}>
          Waiting for log entries...
        </div>
      )}
    </div>
  );
}
