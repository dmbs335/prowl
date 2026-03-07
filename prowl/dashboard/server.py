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
    from prowl.intervention.approval import ApprovalManager
    from prowl.intervention.manager import InterventionManager


def create_app(
    engine: CrawlEngine,
    state: DashboardState,
    bridge: DashboardBridge,
    intervention_manager: InterventionManager,
    approval_manager: ApprovalManager | None = None,
) -> Any:
    """Create the FastAPI app with all routes."""
    if not HAS_FASTAPI:
        raise RuntimeError(
            "FastAPI not installed. Install with: pip install prowl[dashboard]"
        )

    app = FastAPI(
        title="Prowl",
        version="0.1.0",
        description="Prowl Security Crawler - Dashboard & LLM Orchestration API",
    )

    # --- REST API ---

    @app.get("/api/status")
    async def get_status() -> dict:
        stats = engine.get_stats()
        stats["target"] = engine.config.target_url
        stats["phase_name"] = state.phase_name
        stats["current_phase"] = state.current_phase
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

    @app.get("/api/graph")
    async def get_graph(limit: int = 500) -> dict:
        return state.build_graph(limit)

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
            await engine.sessions.update_session_cookies(role, cookies)
        return {"status": "ok", "cookies_injected": len(cookies)}

    # --- Transaction viewer API ---

    @app.get("/api/transactions")
    async def get_transactions(url: str = "", limit: int = 5) -> dict:
        """Return recent transactions for a given URL."""
        if not url:
            return {"transactions": []}
        try:
            txns = await engine.transaction_store.query(
                url_pattern=url, limit=limit
            )
            result = []
            for t in txns:
                result.append({
                    "id": t.id,
                    "timestamp": t.timestamp,
                    "request_method": t.method,
                    "request_url": t.url,
                    "request_headers": t.request_headers or {},
                    "request_body": (t.request_body or "")[:50000],
                    "response_status": t.status_code or 0,
                    "response_headers": t.response_headers or {},
                    "response_body": (t.response_body or "")[:50000],
                    "response_content_type": t.content_type or "",
                    "source_module": t.source_module or "",
                })
            return {"transactions": result}
        except Exception as e:
            logger.debug("Transaction query error: %s", e)
            return {"transactions": []}

    @app.post("/api/queue/submit")
    async def submit_to_queue(body: dict) -> dict:
        """Submit a URL to the crawl queue from the dashboard."""
        url = body.get("url", "")
        method = body.get("method", "GET")
        priority = body.get("priority", 20)
        if not url:
            return JSONResponse(status_code=400, content={"error": "url required"})
        try:
            from prowl.models.target import CrawlRequest
            req = CrawlRequest(
                url=url, method=method, priority=priority,
                source_module="dashboard",
            )
            await engine.submit(req)
            return {"queued": True}
        except Exception as e:
            logger.debug("Queue submit error: %s", e)
            return {"queued": False, "error": str(e)}

    @app.get("/api/logs")
    async def get_logs(limit: int = 50) -> list:
        return state.logs[-limit:]

    @app.get("/api/stats")
    async def get_stats() -> dict:
        return state.stats

    # --- Approval guardrail API ---

    @app.get("/api/approvals")
    async def get_approvals() -> list:
        if not approval_manager:
            return []
        return approval_manager.get_all()

    @app.post("/api/approvals/{item_id}/approve")
    async def approve_request(item_id: str) -> dict:
        if not approval_manager:
            return JSONResponse(status_code=404, content={"error": "Approval not enabled"})
        req = await approval_manager.approve(item_id)
        if req:
            return {"status": "approved", "url": req.url, "method": req.method.upper()}
        return JSONResponse(
            status_code=404,
            content={"error": "Item not found or already resolved"},
        )

    @app.post("/api/approvals/{item_id}/reject")
    async def reject_request(item_id: str) -> dict:
        if not approval_manager:
            return JSONResponse(status_code=404, content={"error": "Approval not enabled"})
        success = await approval_manager.reject(item_id)
        if success:
            return {"status": "rejected"}
        return JSONResponse(
            status_code=404,
            content={"error": "Item not found or already resolved"},
        )

    @app.post("/api/approvals/approve-all")
    async def approve_all_requests() -> dict:
        if not approval_manager:
            return JSONResponse(status_code=404, content={"error": "Approval not enabled"})
        approved = await approval_manager.approve_all()
        return {"status": "approved_all", "count": len(approved)}

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
                "target": engine.config.target_url,
                "modules": state.module_states,
                "stats": {**state.stats, **engine.get_stats()},
                "endpoints": state.endpoints[-200:],
                "endpoint_count": len(state.endpoints),
                "logs": state.logs[-50:],
                "phase_name": state.phase_name,
                "current_phase": state.current_phase,
                "tech_stack": state.tech_stack,
                "input_vectors": state.input_vectors[-200:],
                "auth_boundaries": state.auth_boundaries,
                "approval_items": approval_manager.get_all() if approval_manager else [],
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

    # --- LLM Orchestration API v1 ---
    try:
        from prowl.api import create_v1_router
        from prowl.api.deps import APIState, set_api_state

        set_api_state(APIState(
            engine=engine,
            state=state,
            bridge=bridge,
            intervention_manager=intervention_manager,
        ))

        v1_router = create_v1_router()
        app.include_router(v1_router, prefix="/api/v1")
        logger.info("LLM orchestration API v1 mounted at /api/v1")
    except ImportError:
        logger.debug("prowl.api not available, orchestration API disabled")

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
    approval_manager: ApprovalManager | None = None,
) -> None:
    """Start the dashboard server in the background."""
    if not HAS_FASTAPI:
        logger.warning("FastAPI not installed. Dashboard disabled.")
        return

    try:
        import uvicorn

        app = create_app(engine, state, bridge, intervention_manager, approval_manager)
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
