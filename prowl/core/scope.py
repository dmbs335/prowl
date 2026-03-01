"""Scope checking — determines if URLs are in-scope for crawling."""

from __future__ import annotations

import re
from urllib.parse import urlparse


class ScopeManager:
    """Checks if URLs fall within the configured crawl scope."""

    def __init__(
        self,
        target_url: str,
        include_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
    ) -> None:
        parsed = urlparse(target_url)
        self._target_host = parsed.hostname or ""
        self._target_scheme = parsed.scheme or "https"

        self._include_re = [re.compile(p) for p in (include_patterns or [])]
        self._exclude_re = [re.compile(p) for p in (exclude_patterns or [])]

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is within crawl scope."""
        parsed = urlparse(url)
        host = parsed.hostname or ""

        # Must match target host (or subdomain)
        if not self._is_same_or_sub_domain(host):
            return False

        # Check exclude patterns first
        for pattern in self._exclude_re:
            if pattern.search(url):
                return False

        # If include patterns are set, URL must match at least one
        if self._include_re:
            return any(p.search(url) for p in self._include_re)

        return True

    def _is_same_or_sub_domain(self, host: str) -> bool:
        """Check if host matches target or is a subdomain."""
        if host == self._target_host:
            return True
        if host.endswith(f".{self._target_host}"):
            return True
        return False
