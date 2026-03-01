"""Async priority queue with deduplication for crawl requests."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from prowl.models.request import CrawlRequest

from prowl.core.dedup import DeduplicationManager


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

    async def put(self, request: CrawlRequest) -> bool:
        """Add a request to the queue. Returns False if duplicate."""
        if self._dedup.check_and_mark_url(request.fingerprint):
            self._total_dropped += 1
            return False

        # Priority: lower number = higher priority. Negate so higher priority values come first.
        priority = -request.priority
        self._counter += 1
        await self._queue.put((priority, self._counter, request))
        self._total_queued += 1
        return True

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
