"""LLM strategy: Generate parameter names for fuzzing."""

from __future__ import annotations

from typing import Any

from prowl.llm.protocols import LLMProvider


class ParamGeneratorStrategy:
    """Generate context-aware parameter names for discovery."""

    name = "param_generator"

    def __init__(self, provider: LLMProvider) -> None:
        self._provider = provider

    async def execute(self, context: dict[str, Any]) -> Any:
        url: str = context.get("url", "")
        known_params: list[str] = context.get("known_params", [])
        tech_stack: list[str] = context.get("tech_stack", [])

        known = ", ".join(known_params[:20]) if known_params else "none"
        tech = ", ".join(tech_stack[:10]) if tech_stack else "unknown"

        prompt = f"""Generate likely hidden parameter names for this endpoint.

URL: {url}
Technology stack: {tech}
Already known parameters: {known}

Generate 30 parameter names that are:
1. Common in this tech stack
2. Security-relevant (debug, admin, auth, config parameters)
3. Not already in the known list

Return JSON array of strings: ["param1", "param2", ...]"""

        result = await self._provider.complete_json(prompt)
        if isinstance(result, list):
            return result
        return result.get("params", result.get("parameters", []))
