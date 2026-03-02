"""Postman Collection v2.1 output."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import aiofiles

from prowl.models.report import CrawlReport
from prowl.models.target import Endpoint, ParameterLocation, Secret


class PostmanOutput:
    """Generate a Postman Collection v2.1 JSON file from crawl results."""

    def __init__(self, output_dir: str) -> None:
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._endpoints: list[Endpoint] = []

    async def write_endpoint(self, endpoint: Endpoint) -> None:
        self._endpoints.append(endpoint)

    async def write_secret(self, secret: Secret) -> None:
        pass  # Secrets are not included in Postman collections

    async def finalize(self, report: CrawlReport | None = None) -> None:
        target = report.target if report else "unknown"
        collection = {
            "info": {
                "name": f"Prowl - {target}",
                "_postman_id": "",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": self._build_items(target),
        }

        path = self._dir / "postman-collection.json"
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(json.dumps(collection, indent=2, ensure_ascii=False))

    # ------------------------------------------------------------------

    def _build_items(self, target: str) -> list[dict]:
        """Group endpoints into folders by first path segment."""
        folders: dict[str, list[dict]] = defaultdict(list)

        for ep in self._endpoints:
            item = self._endpoint_to_item(ep)
            parsed = urlparse(ep.url)
            segments = [s for s in parsed.path.split("/") if s]
            folder_name = f"/{segments[0]}" if segments else "/"
            folders[folder_name].append(item)

        # If everything falls into one folder, flatten
        if len(folders) == 1:
            return list(folders.values())[0]

        return [
            {"name": name, "item": items}
            for name, items in sorted(folders.items())
        ]

    def _endpoint_to_item(self, ep: Endpoint) -> dict:
        parsed = urlparse(ep.url)
        host_parts = (parsed.hostname or "").split(".")
        path_parts = [s for s in parsed.path.split("/") if s]
        method = ep.method.upper()

        # --- Query parameters ---
        query_params = self._extract_query_params(parsed.query, ep)

        # --- Headers ---
        headers = self._extract_headers(ep)

        # --- URL object ---
        url: dict = {
            "raw": ep.url,
            "protocol": parsed.scheme or "https",
            "host": host_parts,
            "path": path_parts,
        }
        if parsed.port:
            url["port"] = str(parsed.port)
        if query_params:
            url["query"] = query_params

        # --- Body (for POST/PUT/PATCH) ---
        body = self._extract_body(ep) if method in ("POST", "PUT", "PATCH") else None

        # --- Build request ---
        request: dict = {
            "method": method,
            "header": headers,
            "url": url,
        }
        if body:
            request["body"] = body

        # --- Name ---
        path_str = parsed.path or "/"
        name = f"{method} {path_str}"

        return {"name": name, "request": request, "response": []}

    def _extract_query_params(self, raw_query: str, ep: Endpoint) -> list[dict]:
        """Merge URL query string and Parameter model entries."""
        seen: set[str] = set()
        params: list[dict] = []

        # From the actual URL query string
        if raw_query:
            for key, values in parse_qs(raw_query, keep_blank_values=True).items():
                seen.add(key)
                params.append({"key": key, "value": values[0] if values else ""})

        # From discovered Parameter objects
        for p in ep.parameters:
            if p.location == ParameterLocation.QUERY and p.name not in seen:
                params.append({
                    "key": p.name,
                    "value": p.sample_values[0] if p.sample_values else "",
                })

        return params

    def _extract_headers(self, ep: Endpoint) -> list[dict]:
        headers: list[dict] = []

        for p in ep.parameters:
            if p.location == ParameterLocation.HEADER:
                headers.append({
                    "key": p.name,
                    "value": p.sample_values[0] if p.sample_values else "",
                })

        # Add Content-Type for body-bearing methods
        if ep.method.upper() in ("POST", "PUT", "PATCH") and ep.content_type:
            if not any(h["key"].lower() == "content-type" for h in headers):
                headers.append({"key": "Content-Type", "value": ep.content_type})

        # Cookie header from cookie parameters
        cookies = [
            p for p in ep.parameters if p.location == ParameterLocation.COOKIE
        ]
        if cookies:
            cookie_str = "; ".join(
                f"{p.name}={p.sample_values[0] if p.sample_values else ''}"
                for p in cookies
            )
            headers.append({"key": "Cookie", "value": cookie_str})

        return headers

    def _extract_body(self, ep: Endpoint) -> dict | None:
        body_params = [
            p for p in ep.parameters if p.location == ParameterLocation.BODY
        ]
        if not body_params:
            return None

        ct = ep.content_type.lower() if ep.content_type else ""

        if "json" in ct:
            raw = json.dumps(
                {
                    p.name: p.sample_values[0] if p.sample_values else ""
                    for p in body_params
                },
                ensure_ascii=False,
            )
            return {"mode": "raw", "raw": raw, "options": {"raw": {"language": "json"}}}

        # Default: form-data
        return {
            "mode": "formdata",
            "formdata": [
                {
                    "key": p.name,
                    "value": p.sample_values[0] if p.sample_values else "",
                    "type": "text",
                }
                for p in body_params
            ],
        }
