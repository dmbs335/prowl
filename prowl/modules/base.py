"""Base class for all discovery modules."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from prowl.core.context import DiscoveryContext
    from prowl.core.engine import CrawlEngine


class BaseModule(ABC):
    """Abstract base for discovery modules (§1-§7)."""

    name: str = "base"
    description: str = ""

    def __init__(self, engine: CrawlEngine) -> None:
        self.engine = engine  # Backward compat: full engine access
        self.logger = logging.getLogger(f"prowl.modules.{self.name}")
        self._running = False

        # Narrow interface for new code
        from prowl.core.context import DiscoveryContext
        self.ctx: DiscoveryContext = DiscoveryContext(engine)

        # Module-level stats
        self.requests_made = 0
        self.endpoints_found = 0
        self.errors = 0
        self.duration_seconds = 0.0

    @abstractmethod
    async def run(self, **kwargs: Any) -> None:
        """Execute the module's discovery logic."""
        ...

    async def stop(self) -> None:
        """Signal the module to stop."""
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict[str, Any]:
        return {
            "module": self.name,
            "requests_made": self.requests_made,
            "endpoints_found": self.endpoints_found,
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
        }
