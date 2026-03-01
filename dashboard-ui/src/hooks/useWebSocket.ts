import { useEffect, useRef } from "react";
import { useCrawlStore } from "./useCrawlStore";
import type { WSMessage } from "../types";

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const store = useCrawlStore();

  useEffect(() => {
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${location.host}/ws`;

    function connect() {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => console.log("[Prowl] Dashboard connected");

      ws.onmessage = (event) => {
        try {
          const msg: WSMessage = JSON.parse(event.data);
          handleMessage(msg);
        } catch {
          // ignore parse errors
        }
      };

      ws.onclose = () => {
        console.log("[Prowl] Disconnected, reconnecting in 2s...");
        setTimeout(connect, 2000);
      };

      ws.onerror = () => ws.close();
    }

    function handleMessage(msg: WSMessage) {
      switch (msg.type) {
        case "initial_state":
          store.initState(msg.modules, msg.stats, msg.logs);
          break;
        case "module_state":
          store.setModuleState(msg.module, msg.state, msg.stats);
          break;
        case "endpoint_found":
          store.addEndpoint(msg.endpoint);
          break;
        case "intervention_requested":
          store.addIntervention({
            id: msg.id,
            kind: msg.kind as "login" | "captcha" | "2fa" | "manual",
            message: msg.message,
            module: "",
            state: "pending",
            data: {},
          });
          break;
        case "intervention_resolved":
          store.resolveIntervention(msg.id);
          break;
        case "stats_update":
          store.updateStats(msg.stats);
          break;
        case "log":
          store.addLog({
            level: msg.level,
            module: msg.module,
            message: msg.message,
            ts: msg.ts,
          });
          break;
        case "phase_changed":
          store.setPhase(msg.phase, msg.name);
          break;
      }
    }

    connect();

    return () => {
      wsRef.current?.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}
