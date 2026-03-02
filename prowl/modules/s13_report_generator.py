"""Report Generator - produces the final attack surface report in JSON
and Markdown formats.

Collects all findings from AttackSurfaceStore, module stats from the
orchestrator, and TransactionStore statistics to build a comprehensive
attack surface map.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from prowl.core.signals import Signal
from prowl.models.report import ModuleReport
from prowl.modules.base import BaseModule

logger = logging.getLogger(__name__)


class ReportGeneratorModule(BaseModule):
    """Generates the final attack surface report."""

    name = "s13_report"
    description = "Attack surface report generator"

    def __init__(self, engine: Any) -> None:
        super().__init__(engine)

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        await self.engine.signals.emit(Signal.MODULE_STARTED, module=self.name)
        self.logger.info("Generating attack surface report")

        # Collect module stats from orchestrator (passed via kwargs or engine)
        module_stats: dict[str, dict] = kwargs.get("module_stats", {})

        # Build module reports
        module_reports: list[ModuleReport] = []
        for mod_name, stats in module_stats.items():
            module_reports.append(ModuleReport(
                module_name=mod_name,
                endpoints_found=stats.get("endpoints_found", 0),
                requests_made=stats.get("requests_made", 0),
                errors=stats.get("errors", 0),
            ))

        # Build the report
        report = self.engine.attack_surface.build_report(
            target=self.engine.config.target_url,
            scan_duration=self.engine.elapsed,
        )
        report.module_reports = module_reports

        # Add transaction store stats
        txn_count = await self.engine.transaction_store.count()

        # Output
        output_dir = Path(self.engine.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        formats = self.engine.config.output_formats

        if "json" in formats:
            json_path = output_dir / "report.json"
            json_path.write_text(
                report.model_dump_json(indent=2),
                encoding="utf-8",
            )
            self.logger.info("JSON report: %s", json_path)

        if "markdown" in formats:
            md_path = output_dir / "report.md"
            md_content = self._render_markdown(report, txn_count)
            md_path.write_text(md_content, encoding="utf-8")
            self.logger.info("Markdown report: %s", md_path)

        self.endpoints_found = report.risk_summary.total_endpoints
        self._running = False
        await self.engine.signals.emit(
            Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats()
        )
        self.logger.info(
            "Report complete - risk score: %.0f/100, %d endpoints, "
            "%d input vectors, %d auth boundaries, %d secrets",
            report.risk_summary.score,
            report.risk_summary.total_endpoints,
            report.risk_summary.total_input_vectors,
            report.risk_summary.auth_boundaries_found,
            report.risk_summary.secrets_found,
        )

    @staticmethod
    def _render_markdown(report: Any, txn_count: int) -> str:
        """Render a human-readable Markdown report."""
        lines: list[str] = []
        a = lines.append

        a(f"# Attack Surface Report: {report.target}")
        a("")
        a(f"**Scan duration:** {report.scan_duration:.1f}s")
        a(f"**Total HTTP transactions:** {txn_count}")
        a("")

        # Risk summary - split active vs passive counts
        rs = report.risk_summary
        passive_tags = {"wayback", "commoncrawl", "otx"}
        active_count = sum(
            1 for ep in report.endpoints
            if not passive_tags.intersection(ep.tags)
        )
        passive_count = rs.total_endpoints - active_count

        a("## Risk Summary")
        a("")
        a(f"| Metric | Value |")
        a(f"|--------|-------|")
        a(f"| Risk Score | **{rs.score:.0f}/100** |")
        a(f"| Endpoints (crawled) | {active_count} |")
        a(f"| Endpoints (passive) | {passive_count} |")
        a(f"| Input Vectors | {rs.total_input_vectors} |")
        a(f"| High-Risk Vectors | {rs.high_risk_vectors} |")
        a(f"| Auth Boundaries | {rs.auth_boundaries_found} |")
        a(f"| Exposed Admin Paths | {rs.unprotected_admin_paths} |")
        a(f"| Exposed Debug Endpoints | {rs.exposed_debug_endpoints} |")
        a(f"| Secrets Found | {rs.secrets_found} |")
        a("")

        # Tech stack
        if report.tech_stack:
            a("## Technology Stack")
            a("")
            a("| Component | Category | Version | Confidence |")
            a("|-----------|----------|---------|------------|")
            for t in sorted(report.tech_stack, key=lambda x: x.category):
                ver = t.version or "-"
                a(f"| {t.name} | {t.category} | {ver} | {t.confidence:.0%} |")
            a("")

        # Separate active (crawled) vs passive (historical) endpoints
        passive_tags = {"wayback", "commoncrawl", "otx"}
        active_eps = [
            ep for ep in report.endpoints
            if not passive_tags.intersection(ep.tags)
        ]
        passive_eps = [
            ep for ep in report.endpoints
            if passive_tags.intersection(ep.tags)
        ]

        # Active endpoints
        if active_eps:
            a("## Endpoints")
            a("")
            a(f"*Showing top {min(50, len(active_eps))} of {len(active_eps)} crawled endpoints*")
            a("")
            a("| Method | URL | Status | Params | Tags |")
            a("|--------|-----|--------|--------|------|")
            for ep in active_eps[:50]:
                tags = ", ".join(ep.tags[:3]) if ep.tags else "-"
                a(f"| {ep.method} | `{ep.url}` | {ep.status_code or '-'} | {ep.param_count} | {tags} |")
            a("")

        # Passive endpoints (summary + top paths)
        if passive_eps:
            a("## Passive Endpoints (Historical)")
            a("")
            a(f"*{len(passive_eps)} unique paths from passive sources (Wayback, CommonCrawl, OTX)*")
            a("")
            shown = min(30, len(passive_eps))
            a(f"| URL | Source |")
            a(f"|-----|--------|")
            for ep in passive_eps[:shown]:
                src = ", ".join(t for t in ep.tags if t in passive_tags) or "passive"
                a(f"| `{ep.url}` | {src} |")
            if len(passive_eps) > shown:
                a(f"| ... and {len(passive_eps) - shown} more | |")
            a("")

        # High-risk input vectors
        high_risk = [iv for iv in report.input_vectors if iv.risk_indicators]
        if high_risk:
            a("## High-Risk Input Vectors")
            a("")
            a("| URL | Parameter | Location | Type | Risk |")
            a("|-----|-----------|----------|------|------|")
            for iv in high_risk[:30]:
                risks = ", ".join(iv.risk_indicators[:3])
                a(f"| `{iv.endpoint_url}` | {iv.name} | {iv.location} | {iv.input_type} | {risks} |")
            a("")

        # Auth boundaries
        if report.auth_boundaries:
            a("## Auth Boundaries")
            a("")
            a("| URL | Method | Type | Unauth Status | Auth Status |")
            a("|-----|--------|------|---------------|-------------|")
            for ab in report.auth_boundaries:
                a(f"| `{ab.url}` | {ab.method} | {ab.boundary_type} | {ab.unauth_status} | {ab.auth_status or '-'} |")
            a("")

        # Secrets
        if report.secrets:
            a("## Secrets")
            a("")
            a("| Kind | Source | Risk |")
            a("|------|--------|------|")
            for s in report.secrets:
                risks = ", ".join(s.risk_indicators[:2]) if s.risk_indicators else "-"
                # Mask secret value
                masked = s.value[:4] + "****" if len(s.value) > 4 else "****"
                a(f"| {s.kind} | `{s.source_url}` | {risks} |")
            a("")

        # API schemas
        if report.api_schemas:
            a("## API Schemas")
            a("")
            for schema in report.api_schemas:
                a(f"- **{schema.schema_type}**: `{schema.url}` ({len(schema.endpoints)} endpoints)")
            a("")

        # Module stats
        if report.module_reports:
            a("## Module Statistics")
            a("")
            a("| Module | Endpoints | Requests | Errors |")
            a("|--------|-----------|----------|--------|")
            for mr in report.module_reports:
                a(f"| {mr.module_name} | {mr.endpoints_found} | {mr.requests_made} | {mr.errors} |")
            a("")

        a("---")
        a("*Generated by Prowl Attack Surface Scanner*")
        a("")

        return "\n".join(lines)
