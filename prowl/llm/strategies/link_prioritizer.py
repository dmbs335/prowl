"""LLM strategy: Prioritize URLs by security interest."""

from __future__ import annotations

from typing import Any

from prowl.llm.protocols import LLMProvider


class LinkPrioritizerStrategy:
    """Score URLs by security relevance using LLM."""

    name = "link_prioritizer"

    def __init__(self, provider: LLMProvider) -> None:
        self._provider = provider

    async def execute(self, context: dict[str, Any]) -> Any:
        urls: list[str] = context.get("urls", [])
        if not urls:
            return []

        # Batch URLs for efficiency
        url_list = "\n".join(f"- {u}" for u in urls[:50])
        prompt = f"""Score each URL from 1-10 for security testing interest.
Higher scores for: admin panels, API endpoints, auth flows, file uploads, debug pages.
Lower scores for: static assets, public pages, documentation.

URLs:
{url_list}

Return JSON array of objects: [{{"url": "...", "score": N, "reason": "..."}}]"""

        result = await self._provider.complete_json(prompt)
        if isinstance(result, list):
            return result
        return result.get("urls", result.get("results", []))
