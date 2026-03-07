"""Pipeline orchestrator -- runs phases in dependency order."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from prowl.core.engine import CrawlEngine
from prowl.core.signals import Signal
from prowl.modules.base import BaseModule
from prowl.modules.s1_active_spider import ActiveSpiderModule
from prowl.modules.s2_dir_bruteforce import DirBruteforceModule
from prowl.modules.s3_param_discovery import ParamDiscoveryModule
from prowl.modules.s4_js_analysis import JSAnalysisModule
from prowl.modules.s5_api_discovery import APIDiscoveryModule
from prowl.modules.s6_passive_collection import PassiveCollectionModule
from prowl.modules.s7_auth_crawl import AuthCrawlModule
from prowl.modules.s8_state_transitions import StateTransitionModule
from prowl.modules.s9_infra_mapper import InfraMapperModule
from prowl.modules.s10_tech_fingerprinter import TechFingerprinterModule
from prowl.modules.s11_input_classifier import InputClassifierModule
from prowl.modules.s12_auth_boundary import AuthBoundaryModule
from prowl.modules.s13_report_generator import ReportGeneratorModule
from prowl.modules.s14_cdp_analysis import CDPAnalysisModule
from prowl.pipeline.phase import DEFAULT_PHASES, Phase, PhaseState

logger = logging.getLogger(__name__)

# Module registry
MODULE_MAP: dict[str, type[BaseModule]] = {
    "s6_passive": PassiveCollectionModule,
    "s1_spider": ActiveSpiderModule,
    "s2_bruteforce": DirBruteforceModule,
    "s4_js": JSAnalysisModule,
    "s5_api": APIDiscoveryModule,
    "s7_auth": AuthCrawlModule,
    "s8_states": StateTransitionModule,
    "s3_params": ParamDiscoveryModule,
    "s9_infra": InfraMapperModule,
    "s10_tech": TechFingerprinterModule,
    "s11_input": InputClassifierModule,
    "s12_auth": AuthBoundaryModule,
    "s13_report": ReportGeneratorModule,
    "s14_cdp": CDPAnalysisModule,
}


class PipelineOrchestrator:
    """Runs discovery modules in the correct order based on dependency DAG."""

    def __init__(self, engine: CrawlEngine, phases: list[Phase] | None = None) -> None:
        self.engine = engine
        self.phases = phases or [Phase(**p.__dict__) for p in DEFAULT_PHASES]
        self._module_instances: dict[str, BaseModule] = {}
        self._phase_map: dict[str, Phase] = {p.name: p for p in self.phases}

        # Exploration stats tracking per phase
        self._phase_exploration: dict[str, dict[str, Any]] = {}

    def _instantiate_modules(self) -> None:
        """Create module instances based on config.

        Modules that appear in multiple phases (e.g. s1_spider in both
        active_crawl and deep_crawl) share a single instance so that the
        BFS color state carries over between runs.
        """
        selected = self.engine.config.modules
        for phase in self.phases:
            for mod_name in phase.modules:
                if selected and mod_name not in selected:
                    continue
                if mod_name in self._module_instances:
                    continue  # reuse existing instance
                cls = MODULE_MAP.get(mod_name)
                if cls:
                    self._module_instances[mod_name] = cls(self.engine)

    async def run(self) -> None:
        """Execute the pipeline following dependency order."""
        self._instantiate_modules()
        completed_phases: set[str] = set()

        for phase in self.phases:
            # Check if all dependencies are satisfied
            if not all(dep in completed_phases for dep in phase.depends_on):
                # Should not happen with correct ordering, but handle gracefully
                logger.warning("Skipping phase %s -- deps not met", phase.name)
                phase.state = PhaseState.SKIPPED
                continue

            # Check if any modules in this phase are actually selected
            active_modules = [
                self._module_instances[m]
                for m in phase.modules
                if m in self._module_instances
            ]
            if not active_modules:
                phase.state = PhaseState.SKIPPED
                completed_phases.add(phase.name)
                continue

            # Reset auto-merge template counts so each phase gets a fresh budget
            self.engine.queue.reset_template_counts()

            # Snapshot exploration state before the phase
            coverage_before = self.engine.coverage.coverage_count
            corpus_before = self.engine.coverage.corpus_size
            requests_before = self.engine.requests_completed + self.engine.requests_failed
            insights_before = len(self.engine.hindsight.insights)
            templates_before = len(self.engine.template_inferrer.templates)

            # Run the phase
            phase.state = PhaseState.RUNNING
            await self.engine.signals.emit(
                Signal.PHASE_STARTED, phase=phase.name, modules=[m.name for m in active_modules]
            )
            logger.info("Phase '%s' started (%d modules)", phase.name, len(active_modules))

            start = time.time()
            try:
                if phase.parallel and len(active_modules) > 1:
                    # Run modules in parallel
                    await asyncio.gather(
                        *(self._run_module(m) for m in active_modules)
                    )
                else:
                    # Run sequentially
                    for mod in active_modules:
                        await self._run_module(mod)

                phase.state = PhaseState.COMPLETE
            except Exception as e:
                phase.state = PhaseState.ERROR
                logger.error("Phase '%s' failed: %s", phase.name, e)

            elapsed = time.time() - start
            completed_phases.add(phase.name)

            # Compute exploration delta for this phase
            coverage_after = self.engine.coverage.coverage_count
            requests_after = self.engine.requests_completed + self.engine.requests_failed
            requests_in_phase = requests_after - requests_before
            new_coverage = coverage_after - coverage_before
            new_insights = len(self.engine.hindsight.insights) - insights_before
            new_templates = len(self.engine.template_inferrer.templates) - templates_before

            discovery_rate = new_coverage / requests_in_phase if requests_in_phase > 0 else 0.0

            self._phase_exploration[phase.name] = {
                "new_coverage": new_coverage,
                "total_coverage": coverage_after,
                "new_corpus": self.engine.coverage.corpus_size - corpus_before,
                "requests": requests_in_phase,
                "discovery_rate": round(discovery_rate, 4),
                "new_insights": new_insights,
                "new_templates": new_templates,
                "elapsed": round(elapsed, 1),
            }

            # Update seed scheduler discovery rates per module
            for mod in active_modules:
                mod_requests = mod.requests_made
                if mod_requests > 0:
                    mod_rate = mod.endpoints_found / mod_requests
                    self.engine.scheduler.update_discovery_rate(mod.name, mod_rate)

            await self.engine.signals.emit(
                Signal.PHASE_COMPLETED,
                phase=phase.name,
                state=phase.state,
                elapsed=elapsed,
                exploration=self._phase_exploration[phase.name],
            )
            logger.info(
                "Phase '%s' completed in %.1fs -- coverage +%d (%d total), "
                "discovery_rate=%.2f, insights +%d, templates +%d",
                phase.name, elapsed, new_coverage, coverage_after,
                discovery_rate, new_insights, new_templates,
            )

    async def _run_module(self, module: BaseModule) -> None:
        """Run a single module with signal emission and timing."""
        start = time.time()
        try:
            await module.run()
        except Exception as e:
            module.errors += 1
            logger.exception("Module %s failed", module.name)
            await self.engine.signals.emit(
                Signal.MODULE_ERROR, module=module.name, error=str(e)
            )
        finally:
            module.duration_seconds = time.time() - start

    def get_phase_states(self) -> dict[str, str]:
        """Get current state of all phases."""
        return {p.name: p.state for p in self.phases}

    def get_phase_exploration(self) -> dict[str, dict[str, Any]]:
        """Get exploration statistics per phase."""
        return dict(self._phase_exploration)

    def get_module_stats(self) -> dict[str, dict]:
        """Get stats from all module instances."""
        return {
            name: mod.get_stats()
            for name, mod in self._module_instances.items()
        }
