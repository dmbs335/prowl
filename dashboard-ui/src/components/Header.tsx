import { useCrawlStore } from "../hooks/useCrawlStore";

export function Header() {
  const { activeView, setActiveView, stats } = useCrawlStore();

  const elapsed = Math.floor(stats.elapsed);
  const minutes = Math.floor(elapsed / 60);
  const seconds = elapsed % 60;
  const timeStr = `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;

  async function handlePause() {
    await fetch("/api/crawl/pause", { method: "POST" });
  }

  async function handleStop() {
    if (confirm("Stop the crawl?")) {
      await fetch("/api/crawl/pause", { method: "POST" });
    }
  }

  return (
    <header
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "8px 16px",
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border)",
        height: 48,
        flexShrink: 0,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <span
          style={{ fontWeight: 700, fontSize: 18, color: "var(--accent-blue)" }}
        >
          Prowl
        </span>

        <div
          style={{
            display: "flex",
            background: "var(--bg-tertiary)",
            borderRadius: 6,
            overflow: "hidden",
          }}
        >
          {(["pipeline", "sitemap"] as const).map((view) => (
            <button
              key={view}
              onClick={() => setActiveView(view)}
              style={{
                padding: "4px 14px",
                border: "none",
                background:
                  activeView === view ? "var(--accent-blue)" : "transparent",
                color:
                  activeView === view
                    ? "#fff"
                    : "var(--text-secondary)",
                cursor: "pointer",
                fontSize: 13,
                fontWeight: 500,
                textTransform: "capitalize",
              }}
            >
              {view}
            </button>
          ))}
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <button
          onClick={handlePause}
          style={{
            padding: "4px 12px",
            border: "1px solid var(--border)",
            borderRadius: 4,
            background: "transparent",
            color: "var(--text-secondary)",
            cursor: "pointer",
            fontSize: 13,
          }}
        >
          Pause
        </button>
        <button
          onClick={handleStop}
          style={{
            padding: "4px 12px",
            border: "1px solid var(--accent-red)",
            borderRadius: 4,
            background: "transparent",
            color: "var(--accent-red)",
            cursor: "pointer",
            fontSize: 13,
          }}
        >
          Stop
        </button>
        <span
          style={{
            fontFamily: "monospace",
            fontSize: 14,
            color: "var(--text-muted)",
          }}
        >
          {timeStr}
        </span>
      </div>
    </header>
  );
}
