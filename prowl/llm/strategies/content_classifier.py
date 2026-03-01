"""LLM strategy: Classify page content type."""

from __future__ import annotations

from typing import Any

from prowl.llm.protocols import LLMProvider


class ContentClassifierStrategy:
    """Classify pages by security-relevant categories."""

    name = "content_classifier"

    def __init__(self, provider: LLMProvider) -> None:
        self._provider = provider

    async def execute(self, context: dict[str, Any]) -> Any:
        url: str = context.get("url", "")
        content_snippet: str = context.get("content", "")[:2000]
        status_code: int = context.get("status_code", 200)

        prompt = f"""Classify this web page into security-relevant categories.

URL: {url}
Status: {status_code}
Content (first 2000 chars):
{content_snippet}

Categories: admin_panel, api_endpoint, auth_page, file_upload, debug_page,
config_page, user_profile, search_page, error_page, documentation, static_page, other

Return JSON: {{"category": "...", "confidence": 0.0-1.0, "interesting_elements": ["..."]}}"""

        return await self._provider.complete_json(prompt)
