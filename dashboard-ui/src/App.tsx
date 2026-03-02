import { useEffect } from "react";
import { ReactFlowProvider } from "@xyflow/react";
import { useWebSocket } from "./hooks/useWebSocket";
import { useCrawlStore } from "./hooks/useCrawlStore";
import { deduplicateSessions } from "./lib/sessionDB";
import { Header } from "./components/Header";
import { PipelineView } from "./components/PipelineView";
import { SitemapView } from "./components/SitemapView";
import { EndpointTable } from "./components/EndpointTable";
import { GraphView } from "./components/GraphView";
import { AttackSurfaceView } from "./components/AttackSurfaceView";
import { CommandCenter } from "./components/CommandCenter";
import { InterventionBanner } from "./components/InterventionBanner";
import { DetailPanel } from "./components/DetailPanel";
import { StatsBar } from "./components/StatsBar";
import { LiveLog } from "./components/LiveLog";

export default function App() {
  useWebSocket();
  const activeView = useCrawlStore((s) => s.activeView);

  // Auto-load: clean up duplicate sessions, then restore last session or fetch bundled report
  useEffect(() => {
    deduplicateSessions().then(() => {
      const store = useCrawlStore.getState();
      store.refreshSessions().then(() => {
        const { sessions } = useCrawlStore.getState();
        if (sessions.length > 0) {
          // Load most recent session
          useCrawlStore.getState().loadSessionById(sessions[0].id);
        } else {
          // First visit — try to load bundled report
          fetch("/data/report.json")
            .then((r) => { if (r.ok) return r.json(); throw new Error("no bundled report"); })
            .then((data) => useCrawlStore.getState().loadReport(data, data.target || "Default"))
            .catch(() => { /* no bundled report available, start empty */ });
        }
      });
    });
  }, []);

  return (
    <ReactFlowProvider>
      <Header />
      <InterventionBanner />

      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* Main area */}
        <div style={{ flex: 1, position: "relative" }}>
          {activeView === "pipeline" ? (
            <PipelineView />
          ) : activeView === "graph" ? (
            <GraphView />
          ) : activeView === "sitemap" ? (
            <SitemapView />
          ) : activeView === "attack-surface" ? (
            <AttackSurfaceView />
          ) : activeView === "command-center" ? (
            <CommandCenter />
          ) : (
            <EndpointTable />
          )}
        </div>

        {/* Detail panel (right sidebar) */}
        <div
          style={{
            width: 280,
            borderLeft: "1px solid var(--border)",
            background: "var(--bg-secondary)",
            overflowY: "auto",
            flexShrink: 0,
          }}
        >
          <DetailPanel />
        </div>
      </div>

      <StatsBar />
      <LiveLog />
    </ReactFlowProvider>
  );
}
