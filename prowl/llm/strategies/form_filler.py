"""LLM strategy: Intelligent form field generation."""

from __future__ import annotations

from typing import Any

from prowl.llm.protocols import LLMProvider


class FormFillerStrategy:
    """Generate intelligent form field values for testing."""

    name = "form_filler"

    def __init__(self, provider: LLMProvider) -> None:
        self._provider = provider

    async def execute(self, context: dict[str, Any]) -> Any:
        fields: list[dict] = context.get("fields", [])
        form_action: str = context.get("action", "")

        if not fields:
            return {}

        field_desc = "\n".join(
            f"- {f['name']} (type={f.get('field_type', 'text')}, required={f.get('required', False)})"
            for f in fields
        )

        prompt = f"""Generate realistic test values for this HTML form.
Form action: {form_action}
Fields:
{field_desc}

Generate values suitable for security testing (not malicious, but covering edge cases).
For each field, provide a reasonable value.

Return JSON object: {{"field_name": "value", ...}}"""

        return await self._provider.complete_json(prompt)
