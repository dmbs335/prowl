"""Adaptive rate limiter (AIAD leaky-bucket)."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any


class AdaptiveRateLimiter:
    """Leaky-bucket rate limiter for constant server rate limits.

    Server rate limits are a fixed wall, not variable like network
    congestion.  No need for TCP's exponential phases -- simple
    additive adjustments converge fast and stay stable.

    429 hit:  delay += backoff_step   (slow down a little)
    N OK:     delay -= recover_step   (speed up a little)

    Converges to just below the server limit with minimal oscillation.
    Leaky bucket ensures global inter-request pacing across all workers.
    """

    def __init__(
        self,
        initial_delay: float = 0.1,
        min_delay: float = 0.01,
        max_delay: float = 10.0,
        backoff_step: float = 0.05,
        recover_step: float = 0.01,
        success_window: int = 10,
    ) -> None:
        self._delay = initial_delay
        self._min_delay = min_delay
        self._max_delay = max_delay
        self._backoff_step = backoff_step
        self._recover_step = recover_step
        self._success_window = success_window
        self._consecutive_ok: int = 0
        self._total_backoffs: int = 0
        self._lock = asyncio.Lock()
        # Leaky bucket: track last request time for global pacing
        self._pace_lock = asyncio.Lock()
        self._last_request_time: float = 0.0

    @property
    def current_delay(self) -> float:
        return self._delay

    @property
    def total_backoffs(self) -> int:
        return self._total_backoffs

    async def wait(self) -> None:
        """Leaky bucket: ensure minimum gap between any two requests globally."""
        async with self._pace_lock:
            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < self._delay:
                await asyncio.sleep(self._delay - elapsed)
                now = time.time()
            self._last_request_time = now

    async def on_success(self) -> None:
        """N consecutive OK -> speed up a little."""
        async with self._lock:
            self._consecutive_ok += 1
            if self._consecutive_ok >= self._success_window:
                old = self._delay
                self._delay = max(self._min_delay, self._delay - self._recover_step)
                self._consecutive_ok = 0
                if old != self._delay:
                    logging.getLogger(__name__).debug(
                        "Rate limiter: %.3fs -> %.3fs (-%.3f)",
                        old, self._delay, self._recover_step,
                    )

    async def on_rate_limited(self) -> None:
        """429 hit -> slow down a little."""
        async with self._lock:
            old = self._delay
            self._delay = min(self._max_delay, self._delay + self._backoff_step)
            self._consecutive_ok = 0
            self._total_backoffs += 1
            logging.getLogger(__name__).info(
                "Rate limiter: 429 %.3fs -> %.3fs (+%.3f, #%d)",
                old, self._delay, self._backoff_step, self._total_backoffs,
            )

    def get_stats(self) -> dict[str, Any]:
        return {
            "current_delay": round(self._delay, 4),
            "total_backoffs": self._total_backoffs,
            "consecutive_ok": self._consecutive_ok,
        }


class DomainRateLimiter:
    """Per-domain rate limiting wrapper.

    Each domain gets its own AdaptiveRateLimiter so that one domain's
    429s don't slow down requests to other domains.
    """

    def __init__(self, **default_kwargs: Any) -> None:
        self._default_kwargs = default_kwargs
        self._limiters: dict[str, AdaptiveRateLimiter] = {}
        self._global = AdaptiveRateLimiter(**default_kwargs)

    def _get_limiter(self, url: str) -> AdaptiveRateLimiter:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        if not domain:
            return self._global
        if domain not in self._limiters:
            self._limiters[domain] = AdaptiveRateLimiter(**self._default_kwargs)
        return self._limiters[domain]

    async def wait(self, url: str = "") -> None:
        limiter = self._get_limiter(url) if url else self._global
        await limiter.wait()

    async def on_success(self, url: str = "") -> None:
        limiter = self._get_limiter(url) if url else self._global
        await limiter.on_success()

    async def on_rate_limited(self, url: str = "") -> None:
        limiter = self._get_limiter(url) if url else self._global
        await limiter.on_rate_limited()

    @property
    def current_delay(self) -> float:
        return self._global.current_delay

    @property
    def total_backoffs(self) -> int:
        return sum(l.total_backoffs for l in self._limiters.values()) + self._global.total_backoffs

    def get_stats(self) -> dict[str, Any]:
        # Overall stats from the most active limiter
        worst = max(self._limiters.values(), key=lambda l: l.current_delay) if self._limiters else self._global
        stats = {
            "current_delay": round(worst.current_delay, 4),
            "total_backoffs": self.total_backoffs,
            "consecutive_ok": worst._consecutive_ok,
        }
        if self._limiters:
            stats["domains"] = {
                domain: {"delay": round(l.current_delay, 4), "backoffs": l.total_backoffs}
                for domain, l in self._limiters.items()
                if l.total_backoffs > 0 or l.current_delay > l._min_delay
            }
        return stats
