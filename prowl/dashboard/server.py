"""FastAPI dashboard server with REST API + WebSocket."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import JSONResponse
    from fastapi.staticfiles import StaticFiles

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

if TYPE_CHECKING:
    from prowl.core.engine import CrawlEngine
    from prowl.dashboard.bridge import DashboardBridge
    from prowl.dashboard.state import DashboardState
    from prowl.intervention.manager import InterventionManager


def create_app(
    engine: CrawlEngine,
    state: DashboardState,
    bridge: DashboardBridge,
    intervention_manager: InterventionManager,
) -> Any:
    """Create the FastAPI app with all routes."""
    if not HAS_FASTAPI:
        raise RuntimeError(
            "FastAPI not installed. Install with: pip install prowl[dashboard]"
        )

    app = FastAPI(title="Prowl Dashboard", version="0.1.0")

    # --- REST API ---

    @app.get("/api/status")
    async def get_status() -> dict:
        stats = engine.get_stats()
        stats["elapsed"] = engine.elapsed
        return stats

    @app.get("/api/modules")
    async def get_modules() -> dict:
        return state.module_states

    @app.get("/api/sitemap")
    async def get_sitemap() -> dict:
        return state.build_sitemap_tree()

    @app.get("/api/endpoints")
    async def get_endpoints(
        limit: int = 100, offset: int = 0
    ) -> dict:
        total = len(state.endpoints)
        items = state.endpoints[offset : offset + limit]
        return {"total": total, "items": items}

    @app.get("/api/interventions")
    async def get_interventions() -> list:
        return intervention_manager.get_all()

    @app.post("/api/interventions/{intervention_id}/resolve")
    async def resolve_intervention(
        intervention_id: str, body: dict | None = None
    ) -> dict:
        data = body or {}
        success = await intervention_manager.resolve(intervention_id, data)
        if success:
            engine.resume()
            return {"status": "resolved"}
        return JSONResponse(
            status_code=404,
            content={"error": "Intervention not found or already resolved"},
        )

    @app.post("/api/crawl/pause")
    async def pause_crawl() -> dict:
        engine.pause()
        return {"status": "paused"}

    @app.post("/api/crawl/resume")
    async def resume_crawl() -> dict:
        engine.resume()
        return {"status": "resumed"}

    @app.post("/api/session")
    async def inject_session(body: dict) -> dict:
        cookies = body.get("cookies", {})
        headers = body.get("headers", {})
        role = body.get("role", "default")

        if cookies:
            engine.sessions.update_session_cookies(role, cookies)
        return {"status": "ok", "cookies_injected": len(cookies)}

    @app.get("/api/logs")
    async def get_logs(limit: int = 50) -> list:
        return state.logs[-limit:]

    @app.get("/api/stats")
    async def get_stats() -> dict:
        return state.stats

    # --- WebSocket ---

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket) -> None:
        await ws.accept()
        bridge.add_client(ws)
        logger.info("Dashboard client connected")

        # Send initial state
        try:
            await ws.send_json({
                "type": "initial_state",
                "modules": state.module_states,
                "stats": state.stats,
                "endpoint_count": len(state.endpoints),
                "logs": state.logs[-20:],
            })

            # Keep connection alive
            while True:
                try:
                    data = await ws.receive_text()
                    # Handle client messages if needed
                except WebSocketDisconnect:
                    break
        finally:
            bridge.remove_client(ws)
            logger.info("Dashboard client disconnected")

    # --- Static files (built React app) ---
    static_dir = Path(__file__).parent.parent.parent / "dashboard-ui" / "dist"
    if static_dir.is_dir():
        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

    return app


async def start_dashboard(
    engine: CrawlEngine,
    state: DashboardState,
    bridge: DashboardBridge,
    intervention_manager: InterventionManager,
    port: int = 8484,
) -> None:
    """Start the dashboard server in the background."""
    if not HAS_FASTAPI:
        logger.warning("FastAPI not installed. Dashboard disabled.")
        return

    try:
        import uvicorn

        app = create_app(engine, state, bridge, intervention_manager)
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
        )
        server = uvicorn.Server(config)
        logger.info("Dashboard starting at http://127.0.0.1:%d", port)
        await server.serve()
    except ImportError:
        logger.warning("uvicorn not installed. Dashboard disabled.")
