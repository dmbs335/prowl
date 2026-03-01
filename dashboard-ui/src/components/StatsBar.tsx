import { useCrawlStore } from "../hooks/useCrawlStore";

export function StatsBar() {
  const stats = useCrawlStore((s) => s.stats);

  const items = [
    { label: "Endpoints", value: stats.total_endpoints, color: "var(--accent-blue)" },
    { label: "Params", value: stats.total_params, color: "var(--accent-green)" },
    { label: "Secrets", value: stats.total_secrets, color: "var(--accent-red)" },
    { label: "Requests", value: stats.requests_completed, color: "var(--text-secondary)" },
    { label: "Errors", value: stats.requests_failed, color: "var(--accent-orange)" },
  ];

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 20,
        padding: "6px 16px",
        background: "var(--bg-secondary)",
        borderTop: "1px solid var(--border)",
        fontSize: 12,
        flexShrink: 0,
      }}
    >
      {items.map((item) => (
        <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <span style={{ color: "var(--text-muted)" }}>{item.label}:</span>
          <span style={{ color: item.color, fontWeight: 600, fontFamily: "monospace" }}>
            {item.value}
          </span>
        </div>
      ))}
    </div>
  );
}
