"""LLM strategy: Infer API schema from discovered endpoints."""

from __future__ import annotations

from typing import Any

from prowl.llm.protocols import LLMProvider


class APISchemaInferrerStrategy:
    """Infer API structure and undiscovered endpoints from patterns."""

    name = "api_schema_inferrer"

    def __init__(self, provider: LLMProvider) -> None:
        self._provider = provider

    async def execute(self, context: dict[str, Any]) -> Any:
        endpoints: list[dict] = context.get("endpoints", [])
        if not endpoints:
            return {}

        ep_list = "\n".join(
            f"- {e.get('method', 'GET')} {e.get('url', '')}"
            for e in endpoints[:50]
        )

        prompt = f"""Analyze these API endpoints and infer the API schema.

Discovered endpoints:
{ep_list}

Based on REST API patterns, predict:
1. Missing CRUD endpoints (if /users exists, likely /users/{{id}}, /users/{{id}}/delete, etc.)
2. API versioning patterns
3. Admin/internal endpoints that likely exist
4. Common related endpoints

Return JSON:
{{
    "inferred_endpoints": [
        {{"method": "GET", "path": "/...", "reason": "..."}}
    ],
    "api_patterns": ["REST", "versioned", etc.],
    "confidence": 0.0-1.0
}}"""

        return await self._provider.complete_json(prompt)
