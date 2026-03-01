"""Protocol interfaces for all pluggable components."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from prowl.models.request import CrawlRequest, CrawlResponse
    from prowl.models.target import Endpoint, Parameter, Secret


@runtime_checkable
class Backend(Protocol):
    """HTTP/browser backend that executes crawl requests."""

    async def execute(self, request: CrawlRequest) -> CrawlResponse: ...

    async def startup(self) -> None: ...

    async def shutdown(self) -> None: ...


@runtime_checkable
class DiscoveryModule(Protocol):
    """A discovery module (§1-§7) that finds endpoints/params/secrets."""

    name: str

    async def run(self, **kwargs: Any) -> None: ...

    async def stop(self) -> None: ...


@runtime_checkable
class LinkExtractor(Protocol):
    """Extracts links from response content."""

    def extract(self, html: str, base_url: str) -> list[str]: ...


@runtime_checkable
class ContentAnalyzer(Protocol):
    """Analyzes response content for interesting patterns."""

    async def analyze(self, url: str, content: str) -> list[dict[str, Any]]: ...


@runtime_checkable
class Deduplicator(Protocol):
    """Checks for duplicate URLs/content."""

    def is_duplicate_url(self, fingerprint: str) -> bool: ...

    def is_duplicate_content(self, content_hash: str) -> bool: ...

    def mark_seen_url(self, fingerprint: str) -> None: ...

    def mark_seen_content(self, content_hash: str) -> None: ...


@runtime_checkable
class ScopeChecker(Protocol):
    """Checks if a URL is within crawl scope."""

    def is_in_scope(self, url: str) -> bool: ...


@runtime_checkable
class OutputSink(Protocol):
    """Writes crawl results to an output format."""

    async def write_endpoint(self, endpoint: Endpoint) -> None: ...

    async def write_secret(self, secret: Secret) -> None: ...

    async def finalize(self) -> None: ...
