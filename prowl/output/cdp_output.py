"""CDP security intelligence output (JSON + HTML report)."""

from __future__ import annotations

from pathlib import Path

import aiofiles

from prowl.models.cdp_metrics import CDPCrawlSummary, PageCDPMetrics


class CDPOutput:
    """Write CDP security findings as JSON summary + JSONL detail + HTML report."""

    def __init__(self, output_dir: str) -> None:
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    async def write_summary(self, summary: CDPCrawlSummary) -> None:
        path = self._dir / "cdp_summary.json"
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(summary.model_dump_json(indent=2))

    async def write_per_page_metrics(self, metrics: list[PageCDPMetrics]) -> None:
        path = self._dir / "cdp_pages.jsonl"
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            for m in metrics:
                await f.write(m.model_dump_json() + "\n")

    async def write_html_report(
        self, summary: CDPCrawlSummary, pages: list[PageCDPMetrics]
    ) -> None:
        path = self._dir / "cdp_report.html"

        # API endpoints table
        api_rows = ""
        for ep in summary.discovered_api_endpoints[:50]:
            api_rows += (
                f'<tr><td><code>{_esc(ep.get("method", ""))}</code></td>'
                f'<td class="url">{_esc(ep.get("url", ""))}</td>'
                f'<td>{ep.get("status_code", 0)}</td>'
                f'<td>{_esc(ep.get("resource_type", ""))}</td>'
                f'<td class="url">{_esc(ep.get("found_on", ""))}</td></tr>\n'
            )

        # WebSocket endpoints
        ws_items = ""
        for url in summary.ws_endpoints:
            ws_items += f"<li><code>{_esc(url)}</code></li>\n"

        # Console leaks table
        console_rows = ""
        for msg in summary.interesting_console_messages[:30]:
            level_cls = "error" if msg.get("level") == "error" else "warn"
            console_rows += (
                f'<tr><td class="{level_cls}">{_esc(msg.get("level", ""))}</td>'
                f'<td class="url">{_esc(msg.get("text", "")[:200])}</td>'
                f'<td class="url">{_esc(msg.get("url", ""))}</td>'
                f'<td class="url">{_esc(msg.get("found_on", ""))}</td></tr>\n'
            )

        # Security header issues table
        header_rows = ""
        seen_issues: set[str] = set()
        for issue in summary.security_header_issues[:50]:
            key = f"{issue.get('url', '')}|{issue.get('issue', '')}"
            if key in seen_issues:
                continue
            seen_issues.add(key)
            sev = issue.get("severity", "low")
            sev_cls = {"high": "sev-high", "medium": "sev-med"}.get(sev, "sev-low")
            header_rows += (
                f'<tr><td class="{sev_cls}">{_esc(sev.upper())}</td>'
                f'<td class="url">{_esc(issue.get("url", ""))}</td>'
                f'<td>{_esc(issue.get("issue", ""))}</td></tr>\n'
            )

        # Third-party domains
        tp_items = ""
        for domain in summary.third_party_domains[:50]:
            tp_items += f"<li><code>{_esc(domain)}</code></li>\n"

        # Redirect targets
        redirect_items = ""
        for url in summary.redirect_targets[:30]:
            redirect_items += f"<li><code>{_esc(url)}</code></li>\n"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Prowl CDP Security Intelligence Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:Inter,-apple-system,sans-serif;background:#0f1117;color:#e4e5e9;padding:24px}}
h1{{color:#3b82f6;margin-bottom:8px}}
h2{{color:#9ca0b0;margin:28px 0 12px;font-size:16px;text-transform:uppercase;letter-spacing:1px}}
.cards{{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}}
.card{{background:#1a1d27;padding:14px 20px;border-radius:8px;border:1px solid #2e3144;min-width:140px}}
.card .val{{font-size:22px;font-weight:700;color:#3b82f6}}
.card .lbl{{font-size:11px;color:#6b7084;margin-top:2px}}
.card.alert .val{{color:#e63946}}
table{{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}}
th{{text-align:left;padding:8px;background:#1a1d27;color:#9ca0b0;border-bottom:1px solid #2e3144}}
td{{padding:6px 8px;border-bottom:1px solid #1a1d27}}
.url{{font-family:monospace;font-size:11px;word-break:break-all;max-width:400px}}
code{{background:#242736;padding:2px 6px;border-radius:4px;font-size:12px}}
ul{{list-style:none;padding:0}}
li{{padding:4px 0}}
.error{{color:#e63946;font-weight:700}}
.warn{{color:#e67e22;font-weight:700}}
.sev-high{{color:#e63946;font-weight:700}}
.sev-med{{color:#e67e22;font-weight:700}}
.sev-low{{color:#9ca0b0}}
.section{{background:#1a1d27;border-radius:8px;border:1px solid #2e3144;padding:16px;margin:12px 0}}
</style>
</head>
<body>
<h1>CDP Security Intelligence Report</h1>
<p style="color:#6b7084">{summary.total_pages_profiled} pages profiled | {summary.unique_cdp_endpoints} new endpoints registered</p>

<div class="cards">
<div class="card"><div class="val">{len(summary.discovered_api_endpoints)}</div><div class="lbl">Hidden API Endpoints</div></div>
<div class="card"><div class="val">{len(summary.ws_endpoints)}</div><div class="lbl">WebSocket Endpoints</div></div>
<div class="card"><div class="val">{len(summary.interesting_console_messages)}</div><div class="lbl">Console Leaks</div></div>
<div class="card{"+ ' alert' if len(summary.security_header_issues) > 0 else '' +"}"><div class="val">{len(summary.security_header_issues)}</div><div class="lbl">Header Issues</div></div>
<div class="card"><div class="val">{len(summary.third_party_domains)}</div><div class="lbl">Third-Party Domains</div></div>
<div class="card"><div class="val">{summary.total_sub_requests}</div><div class="lbl">Total Sub-Requests</div></div>
<div class="card"><div class="val">{summary.total_js_errors}</div><div class="lbl">JS Errors</div></div>
<div class="card"><div class="val">{summary.pages_without_csp}</div><div class="lbl">Pages w/o CSP</div></div>
</div>

{"<h2>Hidden API Endpoints (XHR/Fetch)</h2>" + '''
<div class="section"><table>
<tr><th>Method</th><th>URL</th><th>Status</th><th>Type</th><th>Found On</th></tr>
''' + api_rows + "</table></div>" if api_rows else ""}

{"<h2>WebSocket Endpoints</h2><div class='section'><ul>" + ws_items + "</ul></div>" if ws_items else ""}

{"<h2>Console Intelligence (Potential Leaks)</h2>" + '''
<div class="section"><table>
<tr><th>Level</th><th>Message</th><th>Source</th><th>Found On</th></tr>
''' + console_rows + "</table></div>" if console_rows else ""}

{"<h2>Security Header Issues</h2>" + '''
<div class="section"><table>
<tr><th>Severity</th><th>URL</th><th>Issue</th></tr>
''' + header_rows + "</table></div>" if header_rows else ""}

{"<h2>Third-Party Domains</h2><div class='section'><ul>" + tp_items + "</ul></div>" if tp_items else ""}

{"<h2>Redirect Targets</h2><div class='section'><ul>" + redirect_items + "</ul></div>" if redirect_items else ""}

<p style="margin-top:32px;color:#6b7084;font-size:12px">Generated by Prowl CDP Security Intelligence</p>
</body></html>"""

        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(html)


def _esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
