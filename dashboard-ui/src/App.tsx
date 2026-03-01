import { ReactFlowProvider } from "@xyflow/react";
import { useWebSocket } from "./hooks/useWebSocket";
import { useCrawlStore } from "./hooks/useCrawlStore";
import { Header } from "./components/Header";
import { PipelineView } from "./components/PipelineView";
import { SitemapView } from "./components/SitemapView";
import { InterventionBanner } from "./components/InterventionBanner";
import { DetailPanel } from "./components/DetailPanel";
import { StatsBar } from "./components/StatsBar";
import { LiveLog } from "./components/LiveLog";

export default function App() {
  useWebSocket();
  const activeView = useCrawlStore((s) => s.activeView);

  return (
    <ReactFlowProvider>
      <Header />

      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* Main graph area */}
        <div style={{ flex: 1, position: "relative" }}>
          {activeView === "pipeline" ? <PipelineView /> : <SitemapView />}
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

      <InterventionBanner />
      <StatsBar />
      <LiveLog />
    </ReactFlowProvider>
  );
}
