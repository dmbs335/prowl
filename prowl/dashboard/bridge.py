"""SignalBus → WebSocket bridge. Subscribes to engine signals and broadcasts to dashboard."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from prowl.core.signals import Signal, SignalBus
from prowl.dashboard.state import DashboardState

logger = logging.getLogger(__name__)


class DashboardBridge:
    """Bridges the engine SignalBus to WebSocket clients."""

    def __init__(self, signals: SignalBus, state: DashboardState) -> None:
        self._signals = signals
        self._state = state
        self._ws_clients: list[Any] = []  # WebSocket connections

        # Subscribe to all relevant signals
        signals.connect(Signal.MODULE_STARTED, self._on_module_started)
        signals.connect(Signal.MODULE_COMPLETED, self._on_module_completed)
        signals.connect(Signal.MODULE_ERROR, self._on_module_error)
        signals.connect(Signal.ENDPOINT_FOUND, self._on_endpoint_found)
        signals.connect(Signal.SECRET_FOUND, self._on_secret_found)
        signals.connect(Signal.PHASE_STARTED, self._on_phase_started)
        signals.connect(Signal.PHASE_COMPLETED, self._on_phase_completed)
        signals.connect(Signal.INTERVENTION_REQUESTED, self._on_intervention_requested)
        signals.connect(Signal.INTERVENTION_RESOLVED, self._on_intervention_resolved)
        signals.connect(Signal.REQUEST_COMPLETED, self._on_request_completed)
        signals.connect(Signal.REQUEST_FAILED, self._on_request_failed)

    def add_client(self, ws: Any) -> None:
        self._ws_clients.append(ws)

    def remove_client(self, ws: Any) -> None:
        if ws in self._ws_clients:
            self._ws_clients.remove(ws)

    async def broadcast(self, message: dict) -> None:
        """Send a message to all connected WebSocket clients."""
        if not self._ws_clients:
            return
        data = json.dumps(message)
        dead: list[Any] = []
        for ws in self._ws_clients:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._ws_clients.remove(ws)

    # --- Signal handlers ---

    async def _on_module_started(self, **kwargs: Any) -> None:
        module = kwargs.get("module", "")
        self._state.update_module_state(module, "running")
        self._state.add_log("info", module, f"Module started", time.time())
        await self.broadcast({
            "type": "module_state",
            "module": module,
            "state": "running",
            "stats": {},
        })

    async def _on_module_completed(self, **kwargs: Any) -> None:
        module = kwargs.get("module", "")
        stats = kwargs.get("stats", {})
        self._state.update_module_state(module, "complete", stats)
        self._state.add_log("info", module, "Module completed", time.time())
        await self.broadcast({
            "type": "module_state",
            "module": module,
            "state": "complete",
            "stats": stats,
        })

    async def _on_module_error(self, **kwargs: Any) -> None:
        module = kwargs.get("module", "")
        error = kwargs.get("error", "")
        self._state.update_module_state(module, "error")
        self._state.add_log("error", module, f"Error: {error}", time.time())
        await self.broadcast({
            "type": "module_state",
            "module": module,
            "state": "error",
            "stats": {},
        })

    async def _on_endpoint_found(self, **kwargs: Any) -> None:
        endpoint = kwargs.get("endpoint")
        if endpoint:
            self._state.add_endpoint(endpoint)
            await self.broadcast({
                "type": "endpoint_found",
                "endpoint": {
                    "url": endpoint.url,
                    "method": endpoint.method,
                    "status_code": endpoint.status_code,
                    "source_module": endpoint.source_module,
                    "param_count": endpoint.param_count,
                    "tags": endpoint.tags,
                },
            })

    async def _on_secret_found(self, **kwargs: Any) -> None:
        self._state.stats["total_secrets"] = self._state.stats.get("total_secrets", 0) + 1
        secret = kwargs.get("secret")
        if secret:
            self._state.add_log(
                "warning", "secret", f"Secret [{secret.kind}] in {secret.source_url}", time.time()
            )
            await self.broadcast({
                "type": "log",
                "level": "warning",
                "module": "secret",
                "message": f"Found {secret.kind} in {secret.source_url}",
                "ts": time.time(),
            })

    async def _on_phase_started(self, **kwargs: Any) -> None:
        phase = kwargs.get("phase", "")
        self._state.phase_name = phase
        self._state.current_phase += 1
        await self.broadcast({
            "type": "phase_changed",
            "phase": self._state.current_phase,
            "name": phase,
        })

    async def _on_phase_completed(self, **kwargs: Any) -> None:
        phase = kwargs.get("phase", "")
        self._state.add_log("info", "pipeline", f"Phase '{phase}' completed", time.time())

    async def _on_intervention_requested(self, **kwargs: Any) -> None:
        kind = kwargs.get("kind", "manual")
        message = kwargs.get("message", "")
        module = kwargs.get("module", "")

        # Update the module state to needs_attention
        self._state.update_module_state(module, "needs_attention")

        await self.broadcast({
            "type": "intervention_requested",
            "id": kwargs.get("id", ""),
            "kind": kind,
            "message": message,
        })

    async def _on_intervention_resolved(self, **kwargs: Any) -> None:
        await self.broadcast({
            "type": "intervention_resolved",
            "id": kwargs.get("intervention_id", ""),
        })

    async def _on_request_completed(self, **kwargs: Any) -> None:
        self._state.stats["requests_completed"] = (
            self._state.stats.get("requests_completed", 0) + 1
        )
        # Throttle stats updates to every 10 requests
        if self._state.stats["requests_completed"] % 10 == 0:
            await self.broadcast({
                "type": "stats_update",
                "stats": self._state.stats,
            })

    async def _on_request_failed(self, **kwargs: Any) -> None:
        self._state.stats["requests_failed"] = (
            self._state.stats.get("requests_failed", 0) + 1
        )
