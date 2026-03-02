"""§2 Directory & File Bruteforcing module."""

from __future__ import annotations

import asyncio
import importlib.resources
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from prowl.core.signals import Signal
from prowl.models.request import CrawlRequest
from prowl.models.target import Endpoint
from prowl.modules.base import BaseModule

# Backup file suffixes to append to discovered files
_BACKUP_SUFFIXES = [".bak", ".old", ".orig", ".save", ".swp", "~", ".backup", ".copy"]

# Default wordlist (bundled)
DEFAULT_DIRS = [
    "admin", "api", "backup", "config", "console", "dashboard", "debug",
    "dev", "docs", "graphql", "health", "internal", "login", "manage",
    "monitoring", "panel", "private", "server-status", "staging", "status",
    "swagger", "test", "v1", "v2", "wp-admin", "wp-content", ".env",
    ".git", ".svn", "robots.txt", "sitemap.xml", "crossdomain.xml",
    ".well-known/security.txt", "actuator", "actuator/health",
    "actuator/env", "api-docs", "openapi.json", "swagger.json",
    "swagger-ui.html", "graphiql", "altair", "__graphql",
]


class DirBruteforceModule(BaseModule):
    """§2: Discover hidden directories and files via bruteforcing."""

    name = "s2_bruteforce"
    description = "Directory & File Bruteforcing (wordlist-based discovery)"

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        await self.engine.signals.emit(Signal.MODULE_STARTED, module=self.name)

        target = self.engine.config.target_url.rstrip("/")
        wordlist = self._load_wordlist()
        extensions = self.engine.config.bruteforce_extensions
        sem = asyncio.Semaphore(self.engine.config.bruteforce_threads)

        tasks: list[asyncio.Task] = []

        try:
            for word in wordlist:
                if not self._running:
                    break

                # Test the path without extension
                tasks.append(asyncio.create_task(
                    self._test_path(target, word, sem)
                ))

                # Test with each extension
                if "." not in word:
                    for ext in extensions:
                        tasks.append(asyncio.create_task(
                            self._test_path(target, f"{word}{ext}", sem)
                        ))

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            # Phase 2: Backup file detection on discovered files
            if self._running:
                await self._probe_backup_files(target, sem)

        finally:
            self._running = False
            await self.engine.signals.emit(
                Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats()
            )

    async def _test_path(
        self, base_url: str, path: str, sem: asyncio.Semaphore
    ) -> None:
        """Test a single path."""
        async with sem:
            if not self._running:
                return

            url = f"{base_url}/{path}"
            request = CrawlRequest(
                url=url,
                source_module=self.name,
                priority=5,
            )

            try:
                await self.engine.rate_limiter.wait()
                response = await asyncio.wait_for(
                    self.engine.execute(request), timeout=30.0
                )
            except (asyncio.TimeoutError, Exception) as exc:
                self.requests_made += 1
                self.errors += 1
                self.logger.debug("Bruteforce timeout/error for %s: %s", path, exc)
                return
            self.requests_made += 1

            # Filter out common false positives
            if self._is_interesting(response.status_code, response.body):
                endpoint = Endpoint(
                    url=url,
                    method="GET",
                    status_code=response.status_code,
                    content_type=response.content_type,
                    source_module=self.name,
                    tags=["bruteforce"],
                )
                await self.engine.register_endpoint(endpoint)
                self.endpoints_found += 1
                self.logger.info(
                    "Found: %s [%d]", path, response.status_code
                )

    def _is_interesting(self, status_code: int, body: bytes) -> bool:
        """Filter out uninteresting responses."""
        # 404 = not found (skip)
        if status_code == 404:
            return False
        # 200, 301, 302, 307, 308, 401, 403 = interesting
        if status_code in (200, 301, 302, 307, 308, 401, 403):
            return True
        return False

    def _load_wordlist(self) -> list[str]:
        """Load wordlist from config or use default."""
        if self.engine.config.wordlist_dirs:
            path = Path(self.engine.config.wordlist_dirs)
            if path.is_file():
                return [
                    line.strip()
                    for line in path.read_text().splitlines()
                    if line.strip() and not line.startswith("#")
                ]

        return DEFAULT_DIRS

    async def _probe_backup_files(
        self, base_url: str, sem: asyncio.Semaphore
    ) -> None:
        """Probe backup variants of discovered files (e.g. .bak, .old, ~).

        Processes in batches to avoid spawning thousands of concurrent tasks.
        """
        seen_paths: set[str] = set()
        all_probes: list[str] = []

        for ep in self.engine.discovered_endpoints:
            if not self._running:
                break

            parsed = urlparse(ep.url)
            path = parsed.path.rstrip("/")

            # Only probe files with extensions (not directories)
            if "." not in path.split("/")[-1]:
                continue
            if path in seen_paths:
                continue
            seen_paths.add(path)

            rel_path = path.lstrip("/")
            for suffix in _BACKUP_SUFFIXES:
                all_probes.append(f"{rel_path}{suffix}")

        if not all_probes:
            return

        self.logger.info("Probing %d backup file variants in batches", len(all_probes))
        batch_size = self.engine.config.bruteforce_threads * 2
        for i in range(0, len(all_probes), batch_size):
            if not self._running:
                break
            batch = all_probes[i : i + batch_size]
            tasks = [
                asyncio.create_task(self._test_path(base_url, probe, sem))
                for probe in batch
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
