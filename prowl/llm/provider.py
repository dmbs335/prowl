"""LiteLLM-based provider with caching and rate limiting."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class LiteLLMProvider:
    """LLM provider using LiteLLM for 100+ model support."""

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: str = "",
        max_concurrent: int = 5,
    ) -> None:
        self._model = model
        self._api_key = api_key
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._cache: dict[str, str] = {}

    async def complete(self, prompt: str, **kwargs: Any) -> str:
        """Complete a prompt using the configured LLM."""
        cache_key = self._cache_key(prompt)
        if cache_key in self._cache:
            return self._cache[cache_key]

        async with self._semaphore:
            try:
                from litellm import acompletion

                response = await asyncio.wait_for(
                    acompletion(
                        model=self._model,
                        messages=[{"role": "user", "content": prompt}],
                        api_key=self._api_key or None,
                        **kwargs,
                    ),
                    timeout=120.0,
                )
                result = response.choices[0].message.content or ""
                self._cache[cache_key] = result
                return result
            except ImportError:
                raise RuntimeError(
                    "LiteLLM not installed. Install with: pip install prowl[llm]"
                )
            except Exception as e:
                logger.error("LLM completion failed: %s", e)
                return ""

    async def complete_json(self, prompt: str, **kwargs: Any) -> dict:
        """Complete and parse JSON response."""
        result = await self.complete(
            prompt + "\n\nRespond ONLY with valid JSON.",
            **kwargs,
        )
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks (safe regex)
            import re
            m = re.search(r"```(?:json)?\s*\n?(.*?)```", result, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(1).strip())
                except json.JSONDecodeError:
                    pass
            logger.warning("Failed to parse LLM JSON response")
            return {}

    def _cache_key(self, prompt: str) -> str:
        return hashlib.sha256(f"{self._model}:{prompt}".encode()).hexdigest()[:32]
