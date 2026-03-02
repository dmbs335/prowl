"""Burp Suite XML import format output."""

from __future__ import annotations

import json
from base64 import b64encode
from pathlib import Path
from urllib.parse import urlparse

import aiofiles

from prowl.models.report import CrawlReport
from prowl.models.target import Endpoint, ParameterLocation, Secret


class BurpOutput:
    """Generate Burp Suite-compatible XML for importing discovered items."""

    def __init__(self, output_dir: str) -> None:
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._endpoints: list[Endpoint] = []

    async def write_endpoint(self, endpoint: Endpoint) -> None:
        self._endpoints.append(endpoint)

    async def write_secret(self, secret: Secret) -> None:
        pass  # Burp XML format is for request/response items

    async def finalize(self, report: CrawlReport | None = None) -> None:
        path = self._dir / "burp-import.xml"

        items_xml = ""
        for ep in self._endpoints:
            items_xml += self._build_item(ep)

        xml = (
            '<?xml version="1.0"?>\n'
            "<!DOCTYPE items [<!ELEMENT items (item*)>]>\n"
            '<items burpVersion="2024.0" exportTime="">\n'
            f"{items_xml}</items>\n"
        )

        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(xml)

    # ------------------------------------------------------------------

    def _build_item(self, ep: Endpoint) -> str:
        parsed = urlparse(ep.url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        protocol = parsed.scheme or "https"
        path_str = parsed.path or "/"
        if parsed.query:
            path_str += f"?{parsed.query}"

        method = ep.method.upper()

        # --- Build full HTTP request ---
        headers_lines: list[str] = [f"Host: {host}"]

        # Content-Type
        body_params = [
            p for p in ep.parameters if p.location == ParameterLocation.BODY
        ]
        ct = ep.content_type or ""
        body_bytes = b""

        if method in ("POST", "PUT", "PATCH") and body_params:
            if "json" in ct.lower():
                body_bytes = json.dumps(
                    {
                        p.name: p.sample_values[0] if p.sample_values else ""
                        for p in body_params
                    },
                    ensure_ascii=False,
                ).encode()
                headers_lines.append("Content-Type: application/json")
            else:
                body_bytes = "&".join(
                    f"{p.name}={p.sample_values[0] if p.sample_values else ''}"
                    for p in body_params
                ).encode()
                headers_lines.append(
                    "Content-Type: application/x-www-form-urlencoded"
                )
            headers_lines.append(f"Content-Length: {len(body_bytes)}")

        # Header parameters
        for p in ep.parameters:
            if p.location == ParameterLocation.HEADER:
                val = p.sample_values[0] if p.sample_values else ""
                headers_lines.append(f"{p.name}: {val}")

        # Cookie parameters
        cookies = [
            p for p in ep.parameters if p.location == ParameterLocation.COOKIE
        ]
        if cookies:
            cookie_str = "; ".join(
                f"{p.name}={p.sample_values[0] if p.sample_values else ''}"
                for p in cookies
            )
            headers_lines.append(f"Cookie: {cookie_str}")

        request_line = f"{method} {path_str} HTTP/1.1"
        headers_block = "\r\n".join(headers_lines)
        request_raw = f"{request_line}\r\n{headers_block}\r\n\r\n".encode()
        if body_bytes:
            request_raw += body_bytes

        request_b64 = b64encode(request_raw).decode()

        return (
            "  <item>\n"
            f"    <url>{_xml_esc(ep.url)}</url>\n"
            f'    <host ip="">{_xml_esc(host)}</host>\n'
            f"    <port>{port}</port>\n"
            f"    <protocol>{protocol}</protocol>\n"
            f"    <method>{method}</method>\n"
            f"    <path>{_xml_esc(path_str)}</path>\n"
            f'    <request base64="true">{request_b64}</request>\n'
            f"    <status>{ep.status_code or 0}</status>\n"
            f"    <responselength>0</responselength>\n"
            f"    <mimetype>{_xml_esc(ep.content_type)}</mimetype>\n"
            f"    <comment>Prowl: {ep.source_module}</comment>\n"
            "  </item>\n"
        )


def _xml_esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )
