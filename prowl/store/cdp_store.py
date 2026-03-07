"""SQLite-backed store for CDP performance metrics."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import AsyncIterator

import aiosqlite

from prowl.models.cdp_metrics import PageCDPMetrics

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cdp_metrics (
    id          TEXT PRIMARY KEY,
    timestamp   REAL NOT NULL,
    request_url TEXT NOT NULL,
    final_url   TEXT NOT NULL DEFAULT '',
    metrics_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cdp_url ON cdp_metrics(request_url);
CREATE INDEX IF NOT EXISTS idx_cdp_ts ON cdp_metrics(timestamp);
"""


class CDPMetricsStore:
    """Async SQLite store for per-page CDP metrics.

    Follows the same design as TransactionStore:
    - Append-only, buffered writes (flush every 50)
    - WAL mode for concurrent read/write
    - Async iterator for memory-efficient reads
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._db: aiosqlite.Connection | None = None
        self._write_buffer: list[PageCDPMetrics] = []
        self._buffer_size = 50
        self._total_stored: int = 0

    @property
    def total_stored(self) -> int:
        return self._total_stored

    async def initialize(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        logger.info("CDPMetricsStore initialized at %s", self._db_path)

    async def store(self, metrics: PageCDPMetrics) -> None:
        if not metrics.timestamp:
            metrics.timestamp = time.time()

        self._write_buffer.append(metrics)
        if len(self._write_buffer) >= self._buffer_size:
            await self.flush()

    async def flush(self) -> None:
        if not self._write_buffer or not self._db:
            return

        batch = self._write_buffer[:]
        self._write_buffer.clear()

        await self._db.executemany(
            """INSERT OR IGNORE INTO cdp_metrics
               (id, timestamp, request_url, final_url, metrics_json)
               VALUES (?, ?, ?, ?, ?)""",
            [
                (
                    self._compute_id(m),
                    m.timestamp,
                    m.request_url,
                    m.final_url,
                    m.model_dump_json(),
                )
                for m in batch
            ],
        )
        await self._db.commit()
        self._total_stored += len(batch)

    async def get_all(self) -> AsyncIterator[PageCDPMetrics]:
        if not self._db:
            return

        await self.flush()

        sql = "SELECT metrics_json FROM cdp_metrics ORDER BY timestamp"
        async with self._db.execute(sql) as cursor:
            async for row in cursor:
                yield PageCDPMetrics.model_validate_json(row[0])

    async def count(self) -> int:
        if not self._db:
            return 0

        await self.flush()

        async with self._db.execute("SELECT COUNT(*) FROM cdp_metrics") as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def close(self) -> None:
        await self.flush()
        if self._db:
            await self._db.close()
            self._db = None
            logger.info(
                "CDPMetricsStore closed - %d metrics stored", self._total_stored
            )

    @staticmethod
    def _compute_id(m: PageCDPMetrics) -> str:
        raw = f"{m.request_url}|{m.timestamp}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
