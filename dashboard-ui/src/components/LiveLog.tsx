import { useEffect, useRef } from "react";
import { useCrawlStore } from "../hooks/useCrawlStore";

const LEVEL_COLORS: Record<string, string> = {
  info: "var(--text-secondary)",
  warning: "var(--accent-yellow)",
  error: "var(--accent-red)",
  debug: "var(--text-muted)",
};

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
        height: 120,
        overflowY: "auto",
        padding: "4px 12px",
        background: "var(--bg-primary)",
        borderTop: "1px solid var(--border)",
        fontFamily: "monospace",
        fontSize: 12,
        flexShrink: 0,
      }}
    >
      {logs.slice(-50).map((log, i) => (
        <div
          key={i}
          style={{
            color: LEVEL_COLORS[log.level] || "var(--text-secondary)",
            padding: "1px 0",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          <span style={{ color: "var(--text-muted)", marginRight: 8 }}>
            [{log.module}]
          </span>
          {log.message}
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
