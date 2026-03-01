"""URL + content hash deduplication (Burp Scanner-inspired)."""

from __future__ import annotations

import threading


class DeduplicationManager:
    """Thread-safe deduplication using URL fingerprints and content hashes."""

    def __init__(self) -> None:
        self._seen_urls: set[str] = set()
        self._seen_content: set[str] = set()
        self._lock = threading.Lock()

    def is_duplicate_url(self, fingerprint: str) -> bool:
        with self._lock:
            return fingerprint in self._seen_urls

    def is_duplicate_content(self, content_hash: str) -> bool:
        with self._lock:
            return content_hash in self._seen_content

    def mark_seen_url(self, fingerprint: str) -> None:
        with self._lock:
            self._seen_urls.add(fingerprint)

    def mark_seen_content(self, content_hash: str) -> None:
        with self._lock:
            self._seen_content.add(content_hash)

    def check_and_mark_url(self, fingerprint: str) -> bool:
        """Returns True if already seen, False if new (and marks it)."""
        with self._lock:
            if fingerprint in self._seen_urls:
                return True
            self._seen_urls.add(fingerprint)
            return False

    def check_and_mark_content(self, content_hash: str) -> bool:
        """Returns True if already seen, False if new (and marks it)."""
        with self._lock:
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

    def clear(self) -> None:
        with self._lock:
            self._seen_urls.clear()
            self._seen_content.clear()
