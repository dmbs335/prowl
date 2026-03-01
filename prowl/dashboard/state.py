"""Dashboard state snapshot manager."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from prowl.models.target import Endpoint


class DashboardState:
    """Maintains a snapshot of the crawl state for the dashboard."""

    def __init__(self) -> None:
        self.module_states: dict[str, dict[str, Any]] = {
            "s6_passive": {"state": "pending", "stats": {}},
            "s1_spider": {"state": "pending", "stats": {}},
            "s2_bruteforce": {"state": "pending", "stats": {}},
            "s4_js": {"state": "pending", "stats": {}},
            "s5_api": {"state": "pending", "stats": {}},
            "s7_auth": {"state": "pending", "stats": {}},
            "s3_params": {"state": "pending", "stats": {}},
        }
        self.current_phase: int = 0
        self.phase_name: str = ""
        self.endpoints: list[dict] = []
        self.stats: dict[str, Any] = {
            "total_endpoints": 0,
            "total_params": 0,
            "total_secrets": 0,
            "total_js_files": 0,
            "requests_completed": 0,
            "requests_failed": 0,
            "elapsed": 0.0,
        }
        self.logs: list[dict] = []
        self._max_logs = 200

    def update_module_state(
        self, module: str, state: str, stats: dict | None = None
    ) -> None:
        if module in self.module_states:
            self.module_states[module]["state"] = state
            if stats:
                self.module_states[module]["stats"] = stats

    def add_endpoint(self, endpoint: Endpoint) -> None:
        ep_dict = {
            "url": endpoint.url,
            "method": endpoint.method,
            "status_code": endpoint.status_code,
            "content_type": endpoint.content_type,
            "source_module": endpoint.source_module,
            "param_count": endpoint.param_count,
            "tags": endpoint.tags,
        }
        self.endpoints.append(ep_dict)
        self.stats["total_endpoints"] = len(self.endpoints)
        self.stats["total_params"] += endpoint.param_count

    def add_log(self, level: str, module: str, message: str, ts: float) -> None:
        entry = {"level": level, "module": module, "message": message, "ts": ts}
        self.logs.append(entry)
        if len(self.logs) > self._max_logs:
            self.logs = self.logs[-self._max_logs:]

    def build_sitemap_tree(self) -> dict:
        """Build a hierarchical sitemap tree from discovered endpoints."""
        tree: dict[str, Any] = {"name": "root", "children": {}, "endpoints": []}

        for ep in self.endpoints:
            parsed = urlparse(ep["url"])
            host = parsed.hostname or "unknown"
            path_parts = [p for p in parsed.path.split("/") if p]

            # Navigate to correct node
            node = tree
            # Host level
            if host not in node["children"]:
                node["children"][host] = {
                    "name": host,
                    "children": {},
                    "endpoints": [],
                }
            node = node["children"][host]

            # Path levels
            for part in path_parts:
                if part not in node["children"]:
                    node["children"][part] = {
                        "name": part,
                        "children": {},
                        "endpoints": [],
                    }
                node = node["children"][part]

            node["endpoints"].append(ep)

        return self._tree_to_list(tree)

    def _tree_to_list(self, node: dict) -> dict:
        """Convert tree dict to serializable format."""
        children = [
            self._tree_to_list(child) for child in node["children"].values()
        ]
        return {
            "name": node["name"],
            "children": children,
            "endpoints": node["endpoints"],
            "count": len(node["endpoints"])
            + sum(c.get("count", 0) for c in children),
        }

    def get_snapshot(self) -> dict:
        """Get complete state snapshot."""
        return {
            "modules": self.module_states,
            "current_phase": self.current_phase,
            "phase_name": self.phase_name,
            "stats": self.stats,
            "endpoint_count": len(self.endpoints),
            "log_count": len(self.logs),
        }
