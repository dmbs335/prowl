"""URL + content hash deduplication (Burp Scanner-inspired)."""

from __future__ import annotations

import asyncio


class DeduplicationManager:
    """Async-safe deduplication using URL fingerprints and content hashes."""

    def __init__(self) -> None:
        self._seen_urls: set[str] = set()
        self._seen_content: set[str] = set()
        self._lock = asyncio.Lock()

    async def is_duplicate_url(self, fingerprint: str) -> bool:
        async with self._lock:
            return fingerprint in self._seen_urls

    async def is_duplicate_content(self, content_hash: str) -> bool:
        async with self._lock:
            return content_hash in self._seen_content

    async def mark_seen_url(self, fingerprint: str) -> None:
        async with self._lock:
            self._seen_urls.add(fingerprint)

    async def mark_seen_content(self, content_hash: str) -> None:
        async with self._lock:
            self._seen_content.add(content_hash)

    async def check_and_mark_url(self, fingerprint: str) -> bool:
        """Returns True if already seen, False if new (and marks it)."""
        async with self._lock:
            if fingerprint in self._seen_urls:
                return True
            self._seen_urls.add(fingerprint)
            return False

    async def check_and_mark_content(self, content_hash: str) -> bool:
        """Returns True if already seen, False if new (and marks it)."""
        async with self._lock:
            if content_hash in self._seen_content:
                return True
            self._seen_content.add(content_hash)
            return False

    @property
    def url_count(self) -> int:
        return len(self._seen_urls)

    @property
    def content_count(self) -> int:
        return len(self._seen_content)

    async def clear(self) -> None:
        async with self._lock:
            self._seen_urls.clear()
            self._seen_content.clear()
