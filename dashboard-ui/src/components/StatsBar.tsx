import { useCrawlStore } from "../hooks/useCrawlStore";

export function StatsBar() {
  const stats = useCrawlStore((s) => s.stats);

  const totalReqs = stats.requests_completed + stats.requests_failed;
  const successRate =
    totalReqs > 0 ? Math.round((stats.requests_completed / totalReqs) * 100) : 0;
  const coveragePct = stats.coverage?.coverage_pct ?? 0;
  const queueSize = stats.queue_size ?? 0;
  const rateDelay = stats.rate_limiter?.current_delay ?? 0;

  const items: { label: string; value: string | number; color: string; title?: string }[] = [
    { label: "Endpoints", value: stats.total_endpoints, color: "var(--accent-blue)" },
    { label: "Params", value: stats.total_params, color: "var(--accent-green)" },
    { label: "Secrets", value: stats.total_secrets, color: stats.total_secrets > 0 ? "var(--accent-red)" : "var(--text-muted)" },
    { label: "Requests", value: `${stats.requests_completed}/${totalReqs}`, color: "var(--text-secondary)", title: `${successRate}% success` },
    { label: "Queue", value: queueSize, color: queueSize > 0 ? "var(--accent-orange)" : "var(--text-muted)" },
    { label: "Coverage", value: `${coveragePct.toFixed(1)}%`, color: "var(--accent-purple)" },
  ];

  if (rateDelay > 0.01) {
    items.push({ label: "Delay", value: `${(rateDelay * 1000).toFixed(0)}ms`, color: "var(--accent-yellow)", title: `Rate limiter: ${stats.rate_limiter?.total_backoffs ?? 0} backoffs` });
  }

  if (stats.requests_failed > 0) {
    items.push({ label: "Errors", value: stats.requests_failed, color: "var(--accent-red)" });
  }

  const techCount = useCrawlStore.getState().techStack.length;
  const riskScore = useCrawlStore.getState().riskSummary?.score ?? 0;
  if (techCount > 0) {
    items.push({ label: "Tech", value: techCount, color: "var(--accent-purple)" });
  }
  if (riskScore > 0) {
    items.push({
      label: "Risk",
      value: riskScore.toFixed(0),
      color: riskScore >= 75 ? "var(--accent-red)" : riskScore >= 50 ? "var(--accent-orange)" : riskScore >= 25 ? "var(--accent-yellow)" : "var(--accent-green)",
    });
  }

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 16,
        padding: "6px 16px",
        background: "var(--bg-secondary)",
        borderTop: "1px solid var(--border)",
        fontSize: 12,
        flexShrink: 0,
        flexWrap: "wrap",
      }}
    >
      {items.map((item) => (
        <div
          key={item.label}
          title={item.title}
          style={{ display: "flex", alignItems: "center", gap: 4 }}
        >
          <span style={{ color: "var(--text-muted)" }}>{item.label}</span>
          <span style={{ color: item.color, fontWeight: 600, fontFamily: "monospace" }}>
            {item.value}
          </span>
        </div>
      ))}

      {/* Mini coverage bar */}
      {coveragePct > 0 && (
        <div
          style={{
            width: 60,
            height: 4,
            background: "var(--bg-tertiary)",
            borderRadius: 2,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: `${Math.min(coveragePct, 100)}%`,
              height: "100%",
              background: "var(--accent-purple)",
              borderRadius: 2,
              transition: "width 0.5s ease",
            }}
          />
        </div>
      )}
    </div>
  );
}
