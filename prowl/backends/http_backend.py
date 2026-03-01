"""httpx-based async HTTP backend."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from prowl.models.request import (
    CrawlRequest,
    CrawlResponse,
    FormData,
    FormField,
    HttpMethod,
    LinkData,
)

logger = logging.getLogger(__name__)


class HttpBackend:
    """Async HTTP backend using httpx."""

    def __init__(
        self,
        timeout: float = 30.0,
        follow_redirects: bool = True,
        user_agent: str = "Prowl/0.1",
        concurrency: int = 10,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._timeout = timeout
        self._follow_redirects = follow_redirects
        self._user_agent = user_agent
        self._concurrency = concurrency
        self._extra_headers = headers or {}
        self._client: httpx.AsyncClient | None = None

    async def startup(self) -> None:
        default_headers = {"User-Agent": self._user_agent, **self._extra_headers}
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            follow_redirects=self._follow_redirects,
            headers=default_headers,
            limits=httpx.Limits(
                max_connections=self._concurrency,
                max_keepalive_connections=self._concurrency,
            ),
            http2=True,
        )

    async def shutdown(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def execute(self, request: CrawlRequest) -> CrawlResponse:
        if not self._client:
            raise RuntimeError("Backend not started. Call startup() first.")

        try:
            response = await self._client.request(
                method=request.method.upper(),
                url=request.url,
                headers=request.headers or None,
                content=request.body,
            )

            body = response.content
            content_type = response.headers.get("content-type", "")
            final_url = str(response.url)

            # Parse HTML for links, forms, JS
            links: list[LinkData] = []
            forms: list[FormData] = []
            js_files: list[str] = []

            if "html" in content_type:
                links, forms, js_files = self._parse_html(body, final_url)

            return CrawlResponse(
                request=request,
                status_code=response.status_code,
                headers=dict(response.headers),
                body=body,
                content_type=content_type,
                url_final=final_url,
                links=links,
                forms=forms,
                js_files=js_files,
            )

        except httpx.TimeoutException:
            logger.warning("Timeout: %s", request.url)
            return CrawlResponse(
                request=request, status_code=0, url_final=request.url
            )
        except httpx.HTTPError as e:
            logger.warning("HTTP error for %s: %s", request.url, e)
            return CrawlResponse(
                request=request, status_code=0, url_final=request.url
            )

    def _parse_html(
        self, body: bytes, base_url: str
    ) -> tuple[list[LinkData], list[FormData], list[str]]:
        """Extract links, forms, and JS files from HTML."""
        try:
            soup = BeautifulSoup(body, "html.parser")
        except Exception:
            return [], [], []

        links = self._extract_links(soup, base_url)
        forms = self._extract_forms(soup, base_url)
        js_files = self._extract_js(soup, base_url)

        return links, forms, js_files

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> list[LinkData]:
        links: list[LinkData] = []
        for tag in soup.find_all(["a", "link", "area"]):
            href = tag.get("href")
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            url = urljoin(base_url, href)
            links.append(
                LinkData(
                    url=url,
                    text=tag.get_text(strip=True)[:100],
                    tag=tag.name,
                )
            )
        return links

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> list[FormData]:
        forms: list[FormData] = []
        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action", ""))
            method_str = form.get("method", "GET").upper()
            try:
                method = HttpMethod(method_str.lower())
            except ValueError:
                method = HttpMethod.GET

            fields: list[FormField] = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                fields.append(
                    FormField(
                        name=name,
                        field_type=inp.get("type", "text"),
                        value=inp.get("value", ""),
                        required=inp.has_attr("required"),
                    )
                )

            forms.append(
                FormData(
                    action=action,
                    method=method,
                    fields=fields,
                    enctype=form.get("enctype", "application/x-www-form-urlencoded"),
                )
            )
        return forms

    def _extract_js(self, soup: BeautifulSoup, base_url: str) -> list[str]:
        js_files: list[str] = []
        for script in soup.find_all("script", src=True):
            src = script["src"]
            js_files.append(urljoin(base_url, src))
        return js_files
