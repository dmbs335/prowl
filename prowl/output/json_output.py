"""JSON/JSONL output sink."""

from __future__ import annotations

import json
from pathlib import Path

import aiofiles

from prowl.models.report import CrawlReport
from prowl.models.target import Endpoint, Secret


class JsonOutput:
    """Write crawl results as JSONL (streaming) + summary JSON."""

    def __init__(self, output_dir: str) -> None:
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._endpoints_path = self._dir / "endpoints.jsonl"
        self._secrets_path = self._dir / "secrets.jsonl"

    async def write_endpoint(self, endpoint: Endpoint) -> None:
        async with aiofiles.open(self._endpoints_path, "a") as f:
            await f.write(endpoint.model_dump_json() + "\n")

    async def write_secret(self, secret: Secret) -> None:
        async with aiofiles.open(self._secrets_path, "a") as f:
            await f.write(secret.model_dump_json() + "\n")

    async def finalize(self, report: CrawlReport | None = None) -> None:
        if report:
            report_path = self._dir / "report.json"
            async with aiofiles.open(report_path, "w") as f:
                await f.write(report.model_dump_json(indent=2))
