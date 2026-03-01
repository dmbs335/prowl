"""Burp Suite XML import format output."""

from __future__ import annotations

from pathlib import Path

import aiofiles

from prowl.models.report import CrawlReport
from prowl.models.target import Endpoint, Secret


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
            from urllib.parse import urlparse

            parsed = urlparse(ep.url)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            protocol = parsed.scheme or "https"
            path_str = parsed.path or "/"
            if parsed.query:
                path_str += f"?{parsed.query}"

            # Build minimal request
            request_line = f"{ep.method} {path_str} HTTP/1.1"
            request_headers = f"Host: {host}"
            request_raw = f"{request_line}\\r\\n{request_headers}\\r\\n\\r\\n"

            items_xml += f"""  <item>
    <url>{_xml_esc(ep.url)}</url>
    <host ip="">{_xml_esc(host)}</host>
    <port>{port}</port>
    <protocol>{protocol}</protocol>
    <method>{ep.method}</method>
    <path>{_xml_esc(path_str)}</path>
    <request base64="false">{_xml_esc(request_raw)}</request>
    <status>{ep.status_code or 0}</status>
    <responselength>0</responselength>
    <mimetype>{_xml_esc(ep.content_type)}</mimetype>
    <comment>Prowl: {ep.source_module}</comment>
  </item>
"""

        xml = f"""<?xml version="1.0"?>
<!DOCTYPE items [<!ELEMENT items (item*)>]>
<items burpVersion="2024.0" exportTime="">
{items_xml}</items>
"""

        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(xml)


def _xml_esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )
