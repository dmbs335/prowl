"""SQLite-backed HTTP transaction store for full request/response persistence.

Every request/response pair is stored for later analysis by Phase 2-6 modules.
Writes are append-only; reads support filtering by URL, module, page type, etc.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, AsyncIterator

import aiosqlite
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class HttpTransaction(BaseModel):
    """A single HTTP request-response pair with metadata."""

    id: str = ""
    timestamp: float = 0.0

    # Request
    request_method: str = "GET"
    request_url: str = ""
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: bytes | None = None
    request_content_type: str = ""

    # Response
    response_status: int = 0
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: bytes = b""
    response_content_type: str = ""
    response_url_final: str = ""

    # Metadata
    source_module: str = ""
    depth: int = 0
    page_type: str = ""
    content_hash: str = ""

    model_config = {"arbitrary_types_allowed": True}

    def compute_id(self) -> str:
        """Generate deterministic ID from request properties + timestamp."""
        body_hash = ""
        if self.request_body:
            body_hash = hashlib.sha256(self.request_body).hexdigest()[:8]
        raw = f"{self.request_method}|{self.request_url}|{body_hash}|{self.timestamp}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS transactions (
    id              TEXT PRIMARY KEY,
    timestamp       REAL NOT NULL,
    request_method  TEXT NOT NULL,
    request_url     TEXT NOT NULL,
    request_headers TEXT NOT NULL DEFAULT '{}',
    request_body    BLOB,
    request_content_type TEXT NOT NULL DEFAULT '',
    response_status INTEGER NOT NULL DEFAULT 0,
    response_headers TEXT NOT NULL DEFAULT '{}',
    response_body   BLOB,
    response_content_type TEXT NOT NULL DEFAULT '',
    response_url_final TEXT NOT NULL DEFAULT '',
    source_module   TEXT NOT NULL DEFAULT '',
    depth           INTEGER NOT NULL DEFAULT 0,
    page_type       TEXT NOT NULL DEFAULT '',
    content_hash    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_txn_url ON transactions(request_url);
CREATE INDEX IF NOT EXISTS idx_txn_module ON transactions(source_module);
CREATE INDEX IF NOT EXISTS idx_txn_page_type ON transactions(page_type);
CREATE INDEX IF NOT EXISTS idx_txn_content_type ON transactions(response_content_type);
CREATE INDEX IF NOT EXISTS idx_txn_status ON transactions(response_status);
"""


class TransactionStore:
    """Async SQLite store for HTTP transactions.

    Design constraints:
    - Writes are append-only (no updates after insertion).
    - Reads support filtering by URL pattern, module, page_type, content_type.
    - Bodies stored as BLOBs, headers as JSON text.
    - Designed for 10k-100k transactions per scan.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._db: aiosqlite.Connection | None = None
        self._write_buffer: list[HttpTransaction] = []
        self._buffer_size = 50  # flush after N transactions
        self._total_stored: int = 0

    @property
    def total_stored(self) -> int:
        return self._total_stored

    async def initialize(self) -> None:
        """Create database and tables."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        # WAL mode for better concurrent read/write performance
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        logger.info("TransactionStore initialized at %s", self._db_path)

    async def store(self, txn: HttpTransaction) -> None:
        """Buffer a single transaction for batch write."""
        if not txn.timestamp:
            txn.timestamp = time.time()
        if not txn.id:
            txn.id = txn.compute_id()

        self._write_buffer.append(txn)
        if len(self._write_buffer) >= self._buffer_size:
            await self.flush()

    async def flush(self) -> None:
        """Write buffered transactions to SQLite."""
        if not self._write_buffer or not self._db:
            return

        batch = self._write_buffer[:]
        self._write_buffer.clear()

        await self._db.executemany(
            """INSERT OR IGNORE INTO transactions (
                id, timestamp, request_method, request_url,
                request_headers, request_body, request_content_type,
                response_status, response_headers, response_body,
                response_content_type, response_url_final,
                source_module, depth, page_type, content_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    txn.id,
                    txn.timestamp,
                    txn.request_method,
                    txn.request_url,
                    json.dumps(txn.request_headers),
                    txn.request_body,
                    txn.request_content_type,
                    txn.response_status,
                    json.dumps(txn.response_headers),
                    txn.response_body,
                    txn.response_content_type,
                    txn.response_url_final,
                    txn.source_module,
                    txn.depth,
                    txn.page_type,
                    txn.content_hash,
                )
                for txn in batch
            ],
        )
        await self._db.commit()
        self._total_stored += len(batch)

    async def query(
        self,
        *,
        url_pattern: str | None = None,
        source_module: str | None = None,
        page_type: str | None = None,
        content_type_contains: str | None = None,
        status_range: tuple[int, int] | None = None,
        limit: int = 1000,
    ) -> list[HttpTransaction]:
        """Query transactions with filters."""
        if not self._db:
            return []

        await self.flush()

        conditions: list[str] = []
        params: list[Any] = []

        if url_pattern:
            conditions.append("request_url LIKE ?")
            params.append(f"%{url_pattern}%")
        if source_module:
            conditions.append("source_module = ?")
            params.append(source_module)
        if page_type:
            conditions.append("page_type = ?")
            params.append(page_type)
        if content_type_contains:
            conditions.append("response_content_type LIKE ?")
            params.append(f"%{content_type_contains}%")
        if status_range:
            conditions.append("response_status >= ? AND response_status <= ?")
            params.extend(status_range)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM transactions {where} ORDER BY timestamp LIMIT ?"
        params.append(limit)

        results: list[HttpTransaction] = []
        async with self._db.execute(sql, params) as cursor:
            async for row in cursor:
                results.append(self._row_to_txn(row))
        return results

    async def get_all_js_responses(self) -> AsyncIterator[HttpTransaction]:
        """Yield all transactions where content_type contains 'javascript'."""
        if not self._db:
            return

        await self.flush()

        sql = """SELECT * FROM transactions
                 WHERE response_content_type LIKE '%javascript%'
                 ORDER BY timestamp"""
        async with self._db.execute(sql) as cursor:
            async for row in cursor:
                yield self._row_to_txn(row)

    async def get_all_html_responses(self) -> AsyncIterator[HttpTransaction]:
        """Yield all transactions where content_type contains 'html'."""
        if not self._db:
            return

        await self.flush()

        sql = """SELECT * FROM transactions
                 WHERE response_content_type LIKE '%html%'
                   AND page_type = 'real_content'
                 ORDER BY timestamp"""
        async with self._db.execute(sql) as cursor:
            async for row in cursor:
                yield self._row_to_txn(row)

    async def get_all_transactions(self) -> AsyncIterator[HttpTransaction]:
        """Yield all transactions as an async iterator (memory-efficient)."""
        if not self._db:
            return

        await self.flush()

        sql = "SELECT * FROM transactions ORDER BY timestamp"
        async with self._db.execute(sql) as cursor:
            async for row in cursor:
                yield self._row_to_txn(row)

    async def get_response_body(self, transaction_id: str) -> bytes | None:
        """Get just the response body by ID."""
        if not self._db:
            return None

        async with self._db.execute(
            "SELECT response_body FROM transactions WHERE id = ?",
            (transaction_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None

    async def get_urls(self) -> list[str]:
        """Get all unique request URLs."""
        if not self._db:
            return []

        await self.flush()

        urls: list[str] = []
        async with self._db.execute(
            "SELECT DISTINCT request_url FROM transactions ORDER BY timestamp"
        ) as cursor:
            async for row in cursor:
                urls.append(row[0])
        return urls

    async def count(self) -> int:
        """Total number of stored transactions."""
        if not self._db:
            return 0

        await self.flush()

        async with self._db.execute("SELECT COUNT(*) FROM transactions") as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def close(self) -> None:
        """Flush remaining buffer and close database."""
        await self.flush()
        if self._db:
            await self._db.close()
            self._db = None
            logger.info(
                "TransactionStore closed — %d transactions stored", self._total_stored
            )

    @staticmethod
    def _row_to_txn(row: tuple) -> HttpTransaction:
        """Convert a SQLite row to HttpTransaction."""
        return HttpTransaction(
            id=row[0],
            timestamp=row[1],
            request_method=row[2],
            request_url=row[3],
            request_headers=json.loads(row[4]) if row[4] else {},
            request_body=row[5],
            request_content_type=row[6],
            response_status=row[7],
            response_headers=json.loads(row[8]) if row[8] else {},
            response_body=row[9] or b"",
            response_content_type=row[10],
            response_url_final=row[11],
            source_module=row[12],
            depth=row[13],
            page_type=row[14],
            content_hash=row[15],
        )
