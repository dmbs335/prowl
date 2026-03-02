"""Async priority queue with deduplication for crawl requests."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from prowl.models.request import CrawlRequest

from prowl.core.dedup import DeduplicationManager
from prowl.core.exploration import CoverageBitmap

logger = logging.getLogger(__name__)


class RequestQueue:
    """Async priority queue that rejects duplicate requests."""

    def __init__(self, dedup: DeduplicationManager, maxsize: int = 0) -> None:
        self._queue: asyncio.PriorityQueue[tuple[int, int, CrawlRequest]] = (
            asyncio.PriorityQueue(maxsize=maxsize)
        )
        self._dedup = dedup
        self._counter = 0
        self._total_queued = 0
        self._total_dropped = 0
        self._total_auto_merged = 0
        self._bulk_lock = asyncio.Lock()

        # Auto-merge: template → max allowed count.
        # When a URL's template already has >= cap entries queued, drop it.
        self._template_caps: dict[str, int] = {}
        self._template_counts: defaultdict[str, int] = defaultdict(int)

    async def put(self, request: CrawlRequest) -> bool:
        """Add a request to the queue. Returns False if duplicate or auto-merged."""
        if self._dedup.check_and_mark_url(request.fingerprint):
            self._total_dropped += 1
            return False

        # Auto-merge check: drop if template count exceeds cap
        if self._template_caps:
            template = CoverageBitmap._normalize_to_template(request.url)
            matched_cap = self._match_template_cap(template)
            if matched_cap is not None:
                if self._template_counts[template] >= matched_cap:
                    self._total_dropped += 1
                    self._total_auto_merged += 1
                    return False
                self._template_counts[template] += 1

        # Priority: lower number = higher priority. Negate so higher priority values come first.
        priority = -request.priority
        self._counter += 1
        await self._queue.put((priority, self._counter, request))
        self._total_queued += 1
        return True

    def _match_template_cap(self, template: str) -> int | None:
        """Return the cap for a template if any rule matches, else None.

        Matching rules:
        - Exact match: pattern == template
        - Prefix match: pattern ends with '*' and template starts with pattern[:-1]
        - Substring match: pattern is a substring of template (e.g. '/customer-stories/')
        """
        for pattern, cap in self._template_caps.items():
            if pattern == template:
                return cap
            if pattern.endswith("*") and len(pattern) > 1 and template.startswith(pattern[:-1]):
                return cap
            if not pattern.endswith("*") and pattern in template:
                return cap
        return None

    def add_auto_merge_rule(self, pattern: str, max_per_template: int) -> None:
        """Register an auto-merge rule: drop URLs whose template matches pattern after N entries."""
        self._template_caps[pattern] = max_per_template
        logger.info("Auto-merge rule added: %s (max %d)", pattern, max_per_template)

    def remove_auto_merge_rule(self, pattern: str) -> bool:
        """Remove an auto-merge rule. Returns True if it existed."""
        removed = self._template_caps.pop(pattern, None) is not None
        if removed:
            logger.info("Auto-merge rule removed: %s", pattern)
        return removed

    def get_auto_merge_rules(self) -> dict[str, int]:
        """Return current auto-merge rules."""
        return dict(self._template_caps)

    @property
    def total_auto_merged(self) -> int:
        return self._total_auto_merged

    async def get(self) -> CrawlRequest:
        """Get the highest priority request."""
        _, _, request = await self._queue.get()
        return request

    def task_done(self) -> None:
        self._queue.task_done()

    async def join(self) -> None:
        await self._queue.join()

    @property
    def qsize(self) -> int:
        return self._queue.qsize()

    @property
    def empty(self) -> bool:
        return self._queue.empty()

    @property
    def total_queued(self) -> int:
        return self._total_queued

    @property
    def total_dropped(self) -> int:
        return self._total_dropped

    async def peek_all(self) -> list[CrawlRequest]:
        """Non-destructive snapshot of all queued requests.

        Drains the internal queue and re-inserts all items.
        Use sparingly -- briefly holds items outside the queue.
        """
        async with self._bulk_lock:
            items: list[tuple[int, int, CrawlRequest]] = []
            while not self._queue.empty():
                try:
                    items.append(self._queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            for item in items:
                await self._queue.put(item)
            return [req for _, _, req in items]

    async def drain_matching(
        self, predicate: Callable[[CrawlRequest], bool]
    ) -> tuple[list[CrawlRequest], int]:
        """Remove all items matching *predicate*, return (removed, kept_count).

        Items that do NOT match the predicate are re-inserted.
        """
        async with self._bulk_lock:
            kept: list[tuple[int, int, CrawlRequest]] = []
            removed: list[CrawlRequest] = []
            while not self._queue.empty():
                try:
                    item = self._queue.get_nowait()
                    if predicate(item[2]):
                        removed.append(item[2])
                    else:
                        kept.append(item)
                except asyncio.QueueEmpty:
                    break
            for item in kept:
                await self._queue.put(item)
            return removed, len(kept)
