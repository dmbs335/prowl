"""Async signal bus for lifecycle events (Scrapy-inspired)."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from enum import auto

from prowl._compat import StrEnum
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)

# Signal handler type: async callable that receives **kwargs
SignalHandler = Callable[..., Coroutine[Any, Any, None]]


class Signal(StrEnum):
    """All lifecycle signals emitted by the engine."""

    # Engine lifecycle
    ENGINE_STARTED = auto()
    ENGINE_STOPPED = auto()
    ENGINE_PAUSED = auto()
    ENGINE_RESUMED = auto()

    # Request lifecycle
    REQUEST_QUEUED = auto()
    REQUEST_STARTED = auto()
    REQUEST_COMPLETED = auto()
    REQUEST_FAILED = auto()
    REQUEST_DROPPED = auto()

    # Discovery events
    ENDPOINT_FOUND = auto()
    PARAMETER_FOUND = auto()
    SECRET_FOUND = auto()
    JS_FILE_FOUND = auto()
    FORM_FOUND = auto()
    API_SCHEMA_FOUND = auto()
    TECH_DETECTED = auto()

    # Attack surface events
    INPUT_VECTOR_FOUND = auto()
    AUTH_BOUNDARY_FOUND = auto()
    TECH_FINGERPRINT_UPDATED = auto()
    RESPONSE_CLASSIFIED = auto()

    # Module lifecycle
    MODULE_STARTED = auto()
    MODULE_COMPLETED = auto()
    MODULE_ERROR = auto()

    # Phase lifecycle
    PHASE_STARTED = auto()
    PHASE_COMPLETED = auto()

    # Intervention
    INTERVENTION_REQUESTED = auto()
    INTERVENTION_RESOLVED = auto()

    # Approval (unsafe-method / auth guardrail)
    APPROVAL_REQUESTED = auto()
    APPROVAL_RESOLVED = auto()

    # Transaction persistence
    TRANSACTION_STORED = auto()

    # JS AST analysis
    JS_ENDPOINT_EXTRACTED = auto()

    # Parameter discovery
    METHOD_DISCOVERED = auto()
    CONTENT_TYPE_ACCEPTED = auto()
    HIDDEN_PARAM_FOUND = auto()

    # State transitions
    STATE_CHANGED = auto()
    FLOW_DISCOVERED = auto()
    STATE_ENDPOINT_FOUND = auto()

    # Infrastructure mapping
    INFRA_DETECTED = auto()

    # Stats
    STATS_UPDATE = auto()

    # Orchestration events
    QUEUE_MERGED = auto()
    AUTH_LOGIN_ATTEMPTED = auto()
    STRATEGY_ADJUSTED = auto()


class SignalBus:
    """Async event bus that dispatches signals to registered handlers."""

    def __init__(self) -> None:
        self._handlers: dict[Signal, list[SignalHandler]] = defaultdict(list)

    def connect(self, signal: Signal, handler: SignalHandler) -> None:
        """Register a handler for a signal."""
        self._handlers[signal].append(handler)

    def disconnect(self, signal: Signal, handler: SignalHandler) -> None:
        """Remove a handler for a signal."""
        try:
            self._handlers[signal].remove(handler)
        except ValueError:
            pass

    async def emit(self, signal: Signal, **kwargs: Any) -> None:
        """Emit a signal, calling all registered handlers concurrently."""
        handlers = self._handlers.get(signal, [])
        if not handlers:
            return

        tasks = []
        for handler in handlers:
            tasks.append(self._safe_call(handler, signal, **kwargs))

        await asyncio.gather(*tasks)

    async def _safe_call(
        self, handler: SignalHandler, signal: Signal, **kwargs: Any
    ) -> None:
        """Call handler with error isolation."""
        try:
            await handler(**kwargs)
        except Exception:
            logger.exception(
                "Error in signal handler %s for %s", handler.__name__, signal
            )
