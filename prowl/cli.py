"""Prowl CLI — Typer-based command line interface."""

from __future__ import annotations

import asyncio
import logging
import time
import webbrowser
from typing import Optional

import typer
from rich.console import Console
from rich.logging import RichHandler

from prowl import __version__

app = typer.Typer(
    name="prowl",
    help="Prowl — Security Reconnaissance Crawler",
    no_args_is_help=True,
)
console = Console()


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_time=False, show_path=False)],
    )


@app.command()
def crawl(
    target: str = typer.Argument(..., help="Target URL to crawl"),
    modules: Optional[str] = typer.Option(
        None, "--module", "-m", help="Modules to run (comma-separated: s1,s2,s6)"
    ),
    depth: int = typer.Option(10, "--depth", "-d", help="Max crawl depth"),
    concurrency: int = typer.Option(10, "--concurrency", "-c", help="Concurrent requests"),
    timeout: float = typer.Option(30.0, "--timeout", help="Request timeout (seconds)"),
    output_dir: str = typer.Option("./prowl-output", "--output", "-o", help="Output directory"),
    output_format: Optional[str] = typer.Option(
        "json,markdown", "--format", "-f", help="Output formats (comma-separated)"
    ),
    dashboard: bool = typer.Option(False, "--dashboard", help="Enable web dashboard"),
    dashboard_port: int = typer.Option(8484, "--dashboard-port", help="Dashboard port"),
    interactive: bool = typer.Option(False, "-i", "--interactive", help="Interactive mode"),
    pause_on_auth: bool = typer.Option(False, "--pause-on-auth", help="Pause when auth needed"),
    backend: str = typer.Option("hybrid", "--backend", "-b", help="Backend: http, browser, hybrid"),
    headless: bool = typer.Option(True, "--headless/--no-headless", help="Headless browser mode"),
    user_agent: str = typer.Option("Prowl/0.1", "--user-agent", help="User agent string"),
    delay: float = typer.Option(0.0, "--delay", help="Delay between requests (seconds)"),
    wordlist_dirs: Optional[str] = typer.Option(None, "--wordlist-dirs", help="Directory wordlist file"),
    wordlist_params: Optional[str] = typer.Option(None, "--wordlist-params", help="Parameter wordlist file"),
    llm_model: Optional[str] = typer.Option(None, "--llm-model", help="LLM model (e.g., gpt-4o-mini)"),
    llm_api_key: Optional[str] = typer.Option(None, "--llm-api-key", help="LLM API key"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
) -> None:
    """Crawl a target URL with security-focused discovery modules."""
    setup_logging(verbose)

    from prowl.core.config import CrawlConfig

    config = CrawlConfig(
        target_url=target,
        modules=modules.split(",") if modules else [],
        max_depth=depth,
        concurrency=concurrency,
        request_timeout=timeout,
        output_dir=output_dir,
        output_formats=output_format.split(",") if output_format else ["json", "markdown"],
        dashboard=dashboard,
        dashboard_port=dashboard_port,
        backend=backend,
        headless=headless,
        user_agent=user_agent,
        request_delay=delay,
        wordlist_dirs=wordlist_dirs or "",
        wordlist_params=wordlist_params or "",
        llm_model=llm_model or "",
        llm_api_key=llm_api_key or "",
    )

    asyncio.run(_run_crawl(config, interactive, pause_on_auth))


async def _run_crawl(
    config: CrawlConfig,
    interactive: bool,
    pause_on_auth: bool,
) -> None:
    """Main async crawl entry point."""
    from prowl.core.engine import CrawlEngine
    from prowl.core.signals import Signal
    from prowl.dashboard.bridge import DashboardBridge
    from prowl.dashboard.state import DashboardState
    from prowl.intervention.manager import InterventionManager
    from prowl.pipeline.orchestrator import PipelineOrchestrator

    engine = CrawlEngine(config)
    intervention_mgr = InterventionManager(engine.signals)
    dashboard_state = DashboardState()
    bridge = DashboardBridge(engine.signals, dashboard_state)

    console.print(f"\n[bold blue]Prowl[/] v{__version__}")
    console.print(f"Target: [cyan]{config.target_url}[/]")
    console.print(f"Backend: {config.backend} | Concurrency: {config.concurrency}")
    if config.modules:
        console.print(f"Modules: {', '.join(config.modules)}")
    console.print()

    # Start engine
    await engine.startup()

    # Start dashboard if requested
    dashboard_task = None
    if config.dashboard:
        from prowl.dashboard.server import start_dashboard

        dashboard_task = asyncio.create_task(
            start_dashboard(engine, dashboard_state, bridge, intervention_mgr, config.dashboard_port)
        )
        console.print(
            f"[green]Dashboard:[/] http://127.0.0.1:{config.dashboard_port}"
        )
        webbrowser.open(f"http://127.0.0.1:{config.dashboard_port}")

    # Start interactive session if requested
    interactive_task = None
    if interactive:
        from prowl.intervention.interactive import InteractiveSession

        session = InteractiveSession(engine, intervention_mgr)
        interactive_task = asyncio.create_task(session.run())

    # Pause engine when intervention requested (if pause_on_auth)
    if pause_on_auth:
        async def on_intervention(**kwargs):
            engine.pause()
            console.print(
                f"\n[yellow]INTERVENTION:[/] {kwargs.get('message', 'Action needed')}"
            )
        engine.signals.connect(Signal.INTERVENTION_REQUESTED, on_intervention)

    # Run the pipeline
    orchestrator = PipelineOrchestrator(engine)
    start = time.time()

    try:
        await orchestrator.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/]")
    finally:
        elapsed = time.time() - start

        # Generate output
        await _write_output(config, engine, orchestrator, elapsed)

        # Shutdown
        await engine.shutdown()

        if dashboard_task:
            dashboard_task.cancel()
        if interactive_task:
            interactive_task.cancel()

    # Summary
    console.print(f"\n[bold green]Done![/] ({elapsed:.1f}s)")
    console.print(f"  Endpoints: {engine.endpoints_found}")
    console.print(f"  Requests: {engine.requests_completed} ({engine.requests_failed} failed)")
    console.print(f"  Output: {config.output_dir}/")


async def _write_output(
    config: CrawlConfig,
    engine: CrawlEngine,
    orchestrator: PipelineOrchestrator,
    elapsed: float,
) -> None:
    """Write output in all configured formats."""
    from prowl.models.report import CrawlReport, ModuleReport

    # Build report
    module_reports = []
    for name, stats in orchestrator.get_module_stats().items():
        module_reports.append(
            ModuleReport(
                module_name=name,
                endpoints_found=stats.get("endpoints_found", 0),
                requests_made=stats.get("requests_made", 0),
                errors=stats.get("errors", 0),
            )
        )

    report = CrawlReport(
        target=config.target_url,
        start_time=engine.start_time,
        end_time=time.time(),
        duration_seconds=elapsed,
        endpoints=engine.discovered_endpoints,
        module_reports=module_reports,
    )

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


@app.command()
def version() -> None:
    """Show Prowl version."""
    console.print(f"Prowl v{__version__}")


if __name__ == "__main__":
    app()
