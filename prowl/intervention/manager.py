"""Intervention manager — handles pause/resume for human interaction."""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from enum import auto

from prowl._compat import StrEnum
from typing import Any

from prowl.core.signals import Signal, SignalBus

logger = logging.getLogger(__name__)


class InterventionKind(StrEnum):
    LOGIN = auto()
    CAPTCHA = auto()
    TWO_FA = auto()
    MANUAL = auto()


class InterventionState(StrEnum):
    PENDING = auto()
    IN_PROGRESS = auto()
    RESOLVED = auto()
    EXPIRED = auto()


@dataclass
class Intervention:
    """A single intervention request."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    kind: InterventionKind = InterventionKind.MANUAL
    message: str = ""
    module: str = ""
    state: InterventionState = InterventionState.PENDING
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "message": self.message,
            "module": self.module,
            "state": self.state,
            "data": self.data,
        }


class InterventionManager:
    """Manages human intervention requests with pause/resume coordination."""

    def __init__(self, signals: SignalBus) -> None:
        self._signals = signals
        self._interventions: dict[str, Intervention] = {}
        self._pending_event = asyncio.Event()
        self._pending_event.set()  # No pending interventions

        # Listen for intervention signals
        signals.connect(Signal.INTERVENTION_REQUESTED, self._on_intervention_requested)

    async def _on_intervention_requested(self, **kwargs: Any) -> None:
        """Handle a new intervention request from a module."""
        kind_str = kwargs.get("kind", "manual")
        try:
            kind = InterventionKind(kind_str)
        except ValueError:
            kind = InterventionKind.MANUAL

        intervention = Intervention(
            kind=kind,
            message=kwargs.get("message", ""),
            module=kwargs.get("module", ""),
        )

        self._interventions[intervention.id] = intervention
        self._pending_event.clear()  # Signal that there are pending interventions
        logger.info(
            "Intervention requested [%s]: %s (module: %s)",
            intervention.kind,
            intervention.message,
            intervention.module,
        )

    async def resolve(
        self, intervention_id: str, data: dict[str, Any] | None = None
    ) -> bool:
        """Resolve an intervention (e.g., user completed login)."""
        intervention = self._interventions.get(intervention_id)
        if not intervention or intervention.state == InterventionState.RESOLVED:
            return False

        intervention.state = InterventionState.RESOLVED
        if data:
            intervention.data.update(data)

        logger.info("Intervention resolved: %s", intervention_id)

        # Check if all interventions are resolved
        pending = [
            i for i in self._interventions.values()
            if i.state == InterventionState.PENDING
        ]
        if not pending:
            self._pending_event.set()

        await self._signals.emit(
            Signal.INTERVENTION_RESOLVED,
            intervention_id=intervention_id,
            data=data or {},
        )
        return True

    async def wait_for_resolution(self) -> None:
        """Block until all pending interventions are resolved."""
        await self._pending_event.wait()

    @property
    def pending_interventions(self) -> list[Intervention]:
        return [
            i for i in self._interventions.values()
            if i.state == InterventionState.PENDING
        ]

    @property
    def has_pending(self) -> bool:
        return bool(self.pending_interventions)

    def get_all(self) -> list[dict]:
        return [i.to_dict() for i in self._interventions.values()]
