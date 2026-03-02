"""Prowl LLM orchestration API v1."""

from __future__ import annotations

from fastapi import APIRouter


def create_v1_router() -> APIRouter:
    """Create the versioned API router with all sub-routers."""
    router = APIRouter(tags=["v1"])

    from prowl.api.router_crawl import router as crawl_router
    from prowl.api.router_discovery import router as discovery_router
    from prowl.api.router_control import router as control_router
    from prowl.api.router_reports import router as reports_router

    from prowl.api.router_orchestration import router as orchestration_router

    router.include_router(crawl_router, tags=["crawl"])
    router.include_router(discovery_router, tags=["discovery"])
    router.include_router(control_router, tags=["control"])
    router.include_router(reports_router, tags=["reports"])
    router.include_router(orchestration_router, tags=["orchestration"])

    return router
