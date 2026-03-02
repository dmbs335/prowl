import { useEffect, useRef, useState } from "react";
import { useCrawlStore } from "../hooks/useCrawlStore";

const PHASE_LABELS: Record<string, string> = {
  passive: "Passive Recon",
  active_crawl: "Active Crawl",
  deep_crawl: "Deep Crawl",
  fingerprinting: "Fingerprinting",
  classification: "Classification",
  reporting: "Reporting",
};

export function Header() {
  const {
    activeView, setActiveView, stats, target, phaseName, connected, loadReport,
    sessions, currentSessionId, refreshSessions, loadSessionById, deleteSessionById,
  } = useCrawlStore();
  const [elapsed, setElapsed] = useState(0);
  const [showSessions, setShowSessions] = useState(false);
  const startTime = useCrawlStore((s) => s.startTime);
  const fileRef = useRef<HTMLInputElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Load session list on mount
  useEffect(() => { refreshSessions(); }, [refreshSessions]);

  // Close dropdown on outside click
  useEffect(() => {
    if (!showSessions) return;
    function handleClick(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowSessions(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [showSessions]);

  useEffect(() => {
    const interval = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [startTime]);

  const minutes = Math.floor(elapsed / 60);
  const seconds = elapsed % 60;
  const timeStr = `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;

  const engineState = stats.state || "running";
  const isPaused = engineState === "paused";
  const isRunning = engineState === "running" || engineState === undefined;

  function handleImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result as string);
        loadReport(data);
      } catch {
        // ignore parse errors
      }
    };
    reader.readAsText(file);
    // Reset so the same file can be re-imported
    e.target.value = "";
  }

  async function handlePauseResume() {
    if (isPaused) {
      await fetch("/api/crawl/resume", { method: "POST" });
    } else {
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
        height: 52,
        flexShrink: 0,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: connected ? "var(--accent-green)" : "var(--accent-red)",
              boxShadow: connected
                ? "0 0 6px var(--accent-green)"
                : "0 0 6px var(--accent-red)",
            }}
          />
          <span style={{ fontWeight: 700, fontSize: 18, color: "var(--accent-blue)" }}>
            Prowl
          </span>
        </div>

        {target && (
          <span
            style={{
              fontSize: 12,
              color: "var(--text-muted)",
              fontFamily: "monospace",
              background: "var(--bg-tertiary)",
              padding: "3px 10px",
              borderRadius: 4,
              maxWidth: 300,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {target}
          </span>
        )}

        {phaseName && (
          <span
            className={isRunning ? "pulse" : ""}
            style={{
              fontSize: 11,
              fontWeight: 600,
              color: isRunning ? "var(--accent-blue)" : "var(--accent-green)",
              background: isRunning
                ? "rgba(59,130,246,0.15)"
                : "rgba(16,185,129,0.15)",
              padding: "3px 10px",
              borderRadius: 10,
              textTransform: "uppercase",
              letterSpacing: "0.5px",
            }}
          >
            {PHASE_LABELS[phaseName] || phaseName}
          </span>
        )}
      </div>

      <div
        style={{
          display: "flex",
          background: "var(--bg-tertiary)",
          borderRadius: 6,
          overflow: "hidden",
        }}
      >
        {(["pipeline", "graph", "sitemap", "endpoints", "attack-surface", "command-center"] as const).map((view) => {
          const labels: Record<string, string> = {
            pipeline: "Pipeline", graph: "Graph", sitemap: "Sitemap",
            endpoints: "Endpoints", "attack-surface": "Attack Surface",
            "command-center": "Command",
          };
          return (
            <button
              key={view}
              onClick={() => setActiveView(view)}
              style={{
                padding: "4px 14px",
                border: "none",
                background:
                  activeView === view ? "var(--accent-blue)" : "transparent",
                color: activeView === view ? "#fff" : "var(--text-secondary)",
                cursor: "pointer",
                fontSize: 13,
                fontWeight: 500,
              }}
            >
              {labels[view]}
            </button>
          );
        })}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <input
          ref={fileRef}
          type="file"
          accept=".json"
          onChange={handleImport}
          style={{ display: "none" }}
        />
        <button
          onClick={() => fileRef.current?.click()}
          style={{
            padding: "4px 12px",
            border: "1px solid var(--accent-purple, #a78bfa)",
            borderRadius: 4,
            background: "transparent",
            color: "var(--accent-purple, #a78bfa)",
            cursor: "pointer",
            fontSize: 13,
          }}
        >
          Import
        </button>

        {/* Session selector */}
        <div ref={dropdownRef} style={{ position: "relative" }}>
          <button
            onClick={() => setShowSessions((v) => !v)}
            style={{
              padding: "4px 12px",
              border: "1px solid var(--accent-blue, #3b82f6)",
              borderRadius: 4,
              background: showSessions ? "var(--accent-blue)" : "transparent",
              color: showSessions ? "#fff" : "var(--accent-blue, #3b82f6)",
              cursor: "pointer",
              fontSize: 13,
            }}
          >
            Sessions{sessions.length > 0 ? ` (${sessions.length})` : ""}
          </button>
          {showSessions && (
            <div
              style={{
                position: "absolute",
                top: "100%",
                right: 0,
                marginTop: 4,
                background: "var(--bg-secondary)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                minWidth: 280,
                maxHeight: 320,
                overflowY: "auto",
                zIndex: 100,
                boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
              }}
            >
              {sessions.length === 0 ? (
                <div style={{ padding: 12, color: "var(--text-muted)", fontSize: 12 }}>
                  No saved sessions. Import a report.json to create one.
                </div>
              ) : (
                sessions.map((s) => (
                  <div
                    key={s.id}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "8px 12px",
                      borderBottom: "1px solid var(--border)",
                      background: s.id === currentSessionId ? "rgba(59,130,246,0.1)" : "transparent",
                      cursor: "pointer",
                    }}
                    onClick={() => { loadSessionById(s.id); setShowSessions(false); }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{
                        fontSize: 12, fontWeight: 600, color: "var(--text-primary)",
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                      }}>
                        {s.name}
                        {s.id === currentSessionId && (
                          <span style={{ color: "var(--accent-green)", marginLeft: 6, fontSize: 10 }}>ACTIVE</span>
                        )}
                      </div>
                      <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
                        {s.endpointCount} endpoints &middot; {new Date(s.date).toLocaleDateString()}
                      </div>
                    </div>
                    <button
                      onClick={(e) => { e.stopPropagation(); deleteSessionById(s.id); }}
                      style={{
                        background: "none", border: "none", color: "var(--accent-red)",
                        cursor: "pointer", fontSize: 14, padding: "2px 6px",
                      }}
                      title="Delete session"
                    >
                      &times;
                    </button>
                  </div>
                ))
              )}
            </div>
          )}
        </div>

        <button
          onClick={handlePauseResume}
          style={{
            padding: "4px 12px",
            border: `1px solid ${isPaused ? "var(--accent-green)" : "var(--border)"}`,
            borderRadius: 4,
            background: "transparent",
            color: isPaused ? "var(--accent-green)" : "var(--text-secondary)",
            cursor: "pointer",
            fontSize: 13,
          }}
        >
          {isPaused ? "Resume" : "Pause"}
        </button>
        <span
          style={{
            fontFamily: "monospace",
            fontSize: 14,
            color: isRunning ? "var(--accent-blue)" : "var(--text-muted)",
            fontWeight: 600,
          }}
        >
          {timeStr}
        </span>
      </div>
    </header>
  );
}
