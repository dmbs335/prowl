"""Hybrid backend: auto-switches between HTTP and Browser based on need."""

from __future__ import annotations

import logging

from prowl.backends.browser_backend import BrowserBackend
from prowl.backends.http_backend import HttpBackend
from prowl.models.request import CrawlRequest, CrawlResponse

logger = logging.getLogger(__name__)


class HybridBackend:
    """Dual-engine backend (Katana-inspired).

    Uses HTTP for most requests, switches to Browser when:
    - request.require_browser is True
    - Content hints suggest JS rendering is needed
    """

    def __init__(
        self,
        timeout: float = 30.0,
        follow_redirects: bool = True,
        user_agent: str = "Prowl/0.1",
        concurrency: int = 10,
        headless: bool = True,
    ) -> None:
        self._http = HttpBackend(
            timeout=timeout,
            follow_redirects=follow_redirects,
            user_agent=user_agent,
            concurrency=concurrency,
        )
        self._browser = BrowserBackend(
            headless=headless,
            timeout=timeout,
            user_agent=user_agent,
        )
        self._browser_started = False

    async def startup(self) -> None:
        await self._http.startup()
        # Browser starts lazily on first need

    async def shutdown(self) -> None:
        await self._http.shutdown()
        if self._browser_started:
            await self._browser.shutdown()

    async def execute(self, request: CrawlRequest) -> CrawlResponse:
        if request.require_browser:
            return await self._execute_browser(request)

        # Try HTTP first
        response = await self._http.execute(request)

        # If the response looks like it needs JS rendering, retry with browser
        if self._needs_browser(response):
            logger.debug("Switching to browser for %s", request.url)
            return await self._execute_browser(request)

        return response

    async def _execute_browser(self, request: CrawlRequest) -> CrawlResponse:
        """Execute with browser backend, starting it if needed."""
        if not self._browser_started:
            await self._browser.startup()
            self._browser_started = True
        return await self._browser.execute(request)

    def _needs_browser(self, response: CrawlResponse) -> bool:
        """Heuristic: does this response need JS rendering?"""
        if not response.is_success:
            return False

        body_str = response.body.decode("utf-8", errors="ignore").lower()

        # Empty body with HTML content type
        if "html" in response.content_type and len(body_str.strip()) < 200:
            return True

        # SPA indicators
        spa_indicators = [
            'id="__next"',
            'id="app"',
            'id="root"',
            "ng-app=",
            "data-reactroot",
            "window.__NUXT__",
            "window.__NEXT_DATA__",
        ]
        if any(indicator in body_str for indicator in spa_indicators):
            # Check if there's actual content or just skeleton
            if body_str.count("<a ") < 3 and body_str.count("href=") < 5:
                return True

        return False

    @property
    def browser(self) -> BrowserBackend:
        """Direct access to browser backend (for intervention)."""
        return self._browser
