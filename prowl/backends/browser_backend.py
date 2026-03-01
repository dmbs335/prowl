"""Playwright-based headless browser backend."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin

from prowl.models.request import (
    CrawlRequest,
    CrawlResponse,
    FormData,
    FormField,
    HttpMethod,
    LinkData,
)

logger = logging.getLogger(__name__)


class BrowserBackend:
    """Async browser backend using Playwright for JS-rendered pages."""

    def __init__(
        self,
        headless: bool = True,
        timeout: float = 30.0,
        user_agent: str = "Prowl/0.1",
    ) -> None:
        self._headless = headless
        self._timeout = timeout
        self._user_agent = user_agent
        self._browser: Any = None
        self._playwright: Any = None

    async def startup(self) -> None:
        try:
            from playwright.async_api import async_playwright

            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=self._headless,
            )
            logger.info("Browser backend started (headless=%s)", self._headless)
        except ImportError:
            raise RuntimeError(
                "Playwright not installed. Install with: pip install prowl[browser]"
            )

    async def shutdown(self) -> None:
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._browser = None
        self._playwright = None

    async def execute(self, request: CrawlRequest) -> CrawlResponse:
        if not self._browser:
            raise RuntimeError("Browser not started. Call startup() first.")

        context = await self._browser.new_context(
            user_agent=self._user_agent,
        )
        page = await context.new_page()

        try:
            response = await page.goto(
                request.url,
                timeout=int(self._timeout * 1000),
                wait_until="networkidle",
            )

            status_code = response.status if response else 0
            headers = dict(response.headers) if response else {}

            # Wait for dynamic content
            await page.wait_for_load_state("networkidle")

            # Get rendered HTML
            rendered_dom = await page.content()
            body = rendered_dom.encode("utf-8")
            content_type = headers.get("content-type", "text/html")

            # Extract links, forms, JS from rendered DOM
            links = await self._extract_links(page, request.url)
            forms = await self._extract_forms(page, request.url)
            js_files = await self._extract_js(page, request.url)

            return CrawlResponse(
                request=request,
                status_code=status_code,
                headers=headers,
                body=body,
                content_type=content_type,
                url_final=page.url,
                links=links,
                forms=forms,
                js_files=js_files,
                rendered_dom=rendered_dom,
            )

        except Exception as e:
            logger.warning("Browser error for %s: %s", request.url, e)
            return CrawlResponse(
                request=request, status_code=0, url_final=request.url
            )
        finally:
            await page.close()
            await context.close()

    async def _extract_links(self, page: Any, base_url: str) -> list[LinkData]:
        """Extract links from rendered page via JS evaluation."""
        raw_links = await page.evaluate("""
            () => Array.from(document.querySelectorAll('a[href], link[href], area[href]'))
                .map(el => ({
                    href: el.href,
                    text: el.textContent?.trim().slice(0, 100) || '',
                    tag: el.tagName.toLowerCase()
                }))
                .filter(l => l.href && !l.href.startsWith('javascript:') && !l.href.startsWith('mailto:'))
        """)
        return [
            LinkData(url=l["href"], text=l["text"], tag=l["tag"])
            for l in raw_links
        ]

    async def _extract_forms(self, page: Any, base_url: str) -> list[FormData]:
        """Extract forms from rendered page."""
        raw_forms = await page.evaluate("""
            () => Array.from(document.querySelectorAll('form')).map(form => ({
                action: form.action || '',
                method: (form.method || 'GET').toUpperCase(),
                enctype: form.enctype || 'application/x-www-form-urlencoded',
                fields: Array.from(form.querySelectorAll('input[name], textarea[name], select[name]'))
                    .map(f => ({
                        name: f.name,
                        type: f.type || 'text',
                        value: f.value || '',
                        required: f.required
                    }))
            }))
        """)
        forms: list[FormData] = []
        for f in raw_forms:
            try:
                method = HttpMethod(f["method"].lower())
            except ValueError:
                method = HttpMethod.GET
            forms.append(
                FormData(
                    action=f["action"],
                    method=method,
                    enctype=f["enctype"],
                    fields=[
                        FormField(
                            name=field["name"],
                            field_type=field["type"],
                            value=field["value"],
                            required=field["required"],
                        )
                        for field in f["fields"]
                    ],
                )
            )
        return forms

    async def _extract_js(self, page: Any, base_url: str) -> list[str]:
        """Extract JS file URLs from rendered page."""
        return await page.evaluate("""
            () => Array.from(document.querySelectorAll('script[src]'))
                .map(s => s.src)
                .filter(Boolean)
        """)

    async def get_visible_page(self) -> Any:
        """Return a page with visible browser for manual intervention."""
        if not self._browser:
            raise RuntimeError("Browser not started.")
        context = await self._browser.new_context(user_agent=self._user_agent)
        return await context.new_page()
