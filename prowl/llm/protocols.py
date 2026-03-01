"""LLM integration protocols."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class LLMProvider(Protocol):
    """Abstraction over LLM API providers."""

    async def complete(self, prompt: str, **kwargs: Any) -> str: ...

    async def complete_json(self, prompt: str, **kwargs: Any) -> dict: ...


@runtime_checkable
class LLMStrategy(Protocol):
    """A pluggable strategy that uses LLM for a specific task."""

    name: str

    async def execute(self, context: dict[str, Any]) -> Any: ...
