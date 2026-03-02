"""OpenAPI 3.0 specification output."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

import aiofiles

from prowl.models.report import CrawlReport
from prowl.models.target import Endpoint, ParameterLocation, Secret

# Map crawler param_type to OpenAPI types
_TYPE_MAP = {
    "string": "string",
    "integer": "integer",
    "int": "integer",
    "number": "number",
    "float": "number",
    "boolean": "boolean",
    "bool": "boolean",
    "file": "string",
    "json": "object",
    "xml": "string",
}

_LOCATION_MAP = {
    ParameterLocation.QUERY: "query",
    ParameterLocation.HEADER: "header",
    ParameterLocation.COOKIE: "cookie",
    ParameterLocation.PATH: "path",
}


class OpenAPIOutput:
    """Generate an OpenAPI 3.0 spec from crawl results."""

    def __init__(self, output_dir: str) -> None:
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._endpoints: list[Endpoint] = []

    async def write_endpoint(self, endpoint: Endpoint) -> None:
        self._endpoints.append(endpoint)

    async def write_secret(self, secret: Secret) -> None:
        pass

    async def finalize(self, report: CrawlReport | None = None) -> None:
        target = report.target if report else "https://example.com"
        parsed = urlparse(target)
        base = f"{parsed.scheme or 'https'}://{parsed.netloc}"

        spec: dict = {
            "openapi": "3.0.3",
            "info": {
                "title": f"Prowl - {parsed.netloc}",
                "description": "Auto-generated from Prowl crawl results.",
                "version": "1.0.0",
            },
            "servers": [{"url": base}],
            "paths": self._build_paths(),
        }

        # Add security schemes if auth boundaries exist
        if report and report.auth_boundaries:
            spec["components"] = {
                "securitySchemes": {
                    "cookieAuth": {"type": "apiKey", "in": "cookie", "name": "session"},
                }
            }

        path = self._dir / "openapi.json"
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(json.dumps(spec, indent=2, ensure_ascii=False))

    # ------------------------------------------------------------------

    def _build_paths(self) -> dict:
        # Group by (path_template or path, method)
        grouped: dict[str, dict[str, list[Endpoint]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for ep in self._endpoints:
            parsed = urlparse(ep.url)
            # Prefer path_template (/api/users/{id}) over raw path
            path_key = ep.path_template or parsed.path or "/"
            method = ep.method.lower()
            grouped[path_key][method].append(ep)

        paths: dict = {}
        for path_key in sorted(grouped):
            path_item: dict = {}
            for method, eps in grouped[path_key].items():
                # Merge info from all duplicate endpoints
                path_item[method] = self._build_operation(eps, path_key)
            paths[path_key] = path_item

        return paths

    def _build_operation(self, eps: list[Endpoint], path: str) -> dict:
        ep = eps[0]
        method = ep.method.upper()
        op: dict = {
            "summary": f"{method} {path}",
            "responses": self._build_responses(eps),
        }

        # Tags from first path segment
        segments = [s for s in path.split("/") if s and not s.startswith("{")]
        if segments:
            op["tags"] = [segments[0]]

        # Collect all parameters across duplicate endpoints
        all_params = _merge_params(eps)

        # Split into path/query/header/cookie params vs body params
        non_body = [p for p in all_params if p.location != ParameterLocation.BODY]
        body = [p for p in all_params if p.location == ParameterLocation.BODY]

        if non_body:
            op["parameters"] = [self._build_parameter(p) for p in non_body]

        if body and method in ("POST", "PUT", "PATCH"):
            op["requestBody"] = self._build_request_body(body, ep.content_type)

        if ep.requires_auth:
            op["security"] = [{"cookieAuth": []}]

        return op

    def _build_parameter(self, p) -> dict:
        oa_type = _TYPE_MAP.get(p.param_type, "string")
        location = _LOCATION_MAP.get(p.location, "query")
        param: dict = {
            "name": p.name,
            "in": location,
            "required": p.required or location == "path",
            "schema": {"type": oa_type},
        }
        if p.sample_values:
            param["example"] = p.sample_values[0]
        return param

    def _build_request_body(self, params, content_type: str) -> dict:
        ct = content_type.lower() if content_type else ""
        if "json" in ct:
            media = "application/json"
            properties = {}
            for p in params:
                oa_type = _TYPE_MAP.get(p.param_type, "string")
                prop: dict = {"type": oa_type}
                if p.sample_values:
                    prop["example"] = p.sample_values[0]
                properties[p.name] = prop
            schema: dict = {"type": "object", "properties": properties}
            required = [p.name for p in params if p.required]
            if required:
                schema["required"] = required
            return {
                "required": True,
                "content": {media: {"schema": schema}},
            }

        # Default: form-urlencoded
        media = "application/x-www-form-urlencoded"
        properties = {}
        for p in params:
            oa_type = _TYPE_MAP.get(p.param_type, "string")
            prop = {"type": oa_type}
            if p.sample_values:
                prop["example"] = p.sample_values[0]
            properties[p.name] = prop
        schema = {"type": "object", "properties": properties}
        required = [p.name for p in params if p.required]
        if required:
            schema["required"] = required
        return {
            "required": True,
            "content": {media: {"schema": schema}},
        }

    def _build_responses(self, eps: list[Endpoint]) -> dict:
        responses: dict = {}
        seen_codes: set[int] = set()
        for ep in eps:
            code = ep.status_code or 200
            if code in seen_codes:
                continue
            seen_codes.add(code)
            desc = _STATUS_DESC.get(code, "Response")
            resp: dict = {"description": desc}
            if ep.content_type:
                resp["content"] = {ep.content_type: {"schema": {"type": "string"}}}
            responses[str(code)] = resp

        if not responses:
            responses["200"] = {"description": "OK"}
        return responses


def _merge_params(eps: list[Endpoint]) -> list:
    """Deduplicate parameters across multiple Endpoint instances."""
    seen: set[str] = set()
    merged = []
    for ep in eps:
        for p in ep.parameters:
            key = f"{p.name}|{p.location}"
            if key not in seen:
                seen.add(key)
                merged.append(p)
    return merged


_STATUS_DESC = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}
