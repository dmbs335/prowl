"""CrawlSession -- application service that orchestrates a complete crawl lifecycle.

Extracted from cli.py to eliminate the cross-layer dependency where
api/router_crawl.py imported _write_output from the CLI layer.

Both CLI (cli.py) and API (router_crawl.py) delegate to CrawlSession
for the shared orchestration logic.
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class CrawlSession:
    """Orchestrates a complete crawl: engine setup, pipeline run, output write.

    Provides the shared logic used by both CLI and API entry points.
    """

    def __init__(self, config: Any) -> None:
        from prowl.core.config import CrawlConfig

        self.config: CrawlConfig = config
        self.engine: Any = None
        self.orchestrator: Any = None
        self.playbook: Any = None
        self.dashboard_state: Any = None
        self.bridge: Any = None
        self.intervention_mgr: Any = None
        self.approval_mgr: Any = None
        self.elapsed: float = 0.0

    async def setup(self) -> None:
        """Create engine and wire all supporting components.

        After calling setup(), the engine is started and ready for
        pipeline execution.
        """
        from prowl.core.engine import CrawlEngine
        from prowl.core.signals import Signal
        from prowl.dashboard.bridge import DashboardBridge
        from prowl.dashboard.state import DashboardState
        from prowl.intervention.manager import InterventionManager
        from prowl.pipeline.orchestrator import PipelineOrchestrator
        from prowl.playbook.engine import PlaybookEngine

        self.engine = CrawlEngine(self.config)
        self.playbook = PlaybookEngine(self.engine)
        self.playbook.connect()
        self.engine._playbook = self.playbook

        self.intervention_mgr = InterventionManager(self.engine.signals)
        self.dashboard_state = DashboardState()
        self.bridge = DashboardBridge(self.engine.signals, self.dashboard_state)
        self.orchestrator = PipelineOrchestrator(self.engine)

        # Approval guardrail
        if self.config.approve_unsafe:
            from prowl.intervention.approval import ApprovalManager

            self.approval_mgr = ApprovalManager(self.engine.signals)
            self.engine.set_approval_manager(self.approval_mgr)

            async def _on_approval_resolved(**kwargs: Any) -> None:
                action = kwargs.get("action")
                request = kwargs.get("request")
                if action == "approved" and request:
                    await self.engine.submit(request)

            self.engine.signals.connect(
                Signal.APPROVAL_RESOLVED, _on_approval_resolved
            )

        await self.engine.startup()

    async def run_pipeline(self) -> None:
        """Execute the full pipeline and record elapsed time."""
        start = time.time()
        try:
            await self.orchestrator.run()
        finally:
            self.elapsed = time.time() - start

    async def write_output(self) -> None:
        """Write output in all configured formats."""
        from prowl.models.report import ModuleReport

        config = self.config
        engine = self.engine
        orchestrator = self.orchestrator

        # Build module reports with per-module timing
        module_reports = []
        for name, stats in orchestrator.get_module_stats().items():
            module_reports.append(
                ModuleReport(
                    module_name=name,
                    endpoints_found=stats.get("endpoints_found", 0),
                    requests_made=stats.get("requests_made", 0),
                    errors=stats.get("errors", 0),
                    duration_seconds=stats.get("duration_seconds", 0.0),
                )
            )

        report = engine.attack_surface.build_report(
            target=config.target_url,
            scan_duration=self.elapsed,
        )
        report.module_reports = module_reports

        formats = config.output_formats

        if "json" in formats:
            from prowl.output.json_output import JsonOutput

            out = JsonOutput(config.output_dir)
            for ep in engine.discovered_endpoints:
                await out.write_endpoint(ep)
            await out.finalize(report)

        if "markdown" in formats:
            from prowl.output.markdown_output import MarkdownOutput

            out = MarkdownOutput(config.output_dir)
            for ep in engine.discovered_endpoints:
                await out.write_endpoint(ep)
            await out.finalize(report)

        if "html" in formats:
            from prowl.output.html_output import HtmlOutput

            out = HtmlOutput(config.output_dir)
            for ep in engine.discovered_endpoints:
                await out.write_endpoint(ep)
            await out.finalize(report)

        if "burp" in formats:
            from prowl.output.burp_output import BurpOutput

            out = BurpOutput(config.output_dir)
            for ep in engine.discovered_endpoints:
                await out.write_endpoint(ep)
            await out.finalize(report)

        if "postman" in formats:
            from prowl.output.postman_output import PostmanOutput

            out = PostmanOutput(config.output_dir)
            for ep in engine.discovered_endpoints:
                await out.write_endpoint(ep)
            await out.finalize(report)

        if "openapi" in formats:
            from prowl.output.openapi_output import OpenAPIOutput

            out = OpenAPIOutput(config.output_dir)
            for ep in engine.discovered_endpoints:
                await out.write_endpoint(ep)
            await out.finalize(report)

        # CDP security intelligence report
        if config.cdp_profiling and engine.cdp_store:
            from prowl.models.cdp_metrics import PageCDPMetrics
            from prowl.modules.s14_cdp_analysis import CDPAnalysisModule
            from prowl.output.cdp_output import CDPOutput

            cdp_out = CDPOutput(config.output_dir)
            all_cdp: list[PageCDPMetrics] = []
            async for m in engine.cdp_store.get_all():
                all_cdp.append(m)

            if all_cdp:
                analysis = CDPAnalysisModule(engine)
                summary = analysis.compute_summary(all_cdp)
                await cdp_out.write_summary(summary)
                await cdp_out.write_per_page_metrics(all_cdp)
                await cdp_out.write_html_report(summary, all_cdp)
                logger.info(
                    "CDP report: %d pages, %d API endpoints, %d WS, %d console leaks",
                    len(all_cdp),
                    len(summary.discovered_api_endpoints),
                    len(summary.ws_endpoints),
                    len(summary.interesting_console_messages),
                )

    async def shutdown(self) -> None:
        """Shut down the engine and flush all data."""
        if self.engine:
            await self.engine.shutdown()
