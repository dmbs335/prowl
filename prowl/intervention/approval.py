"""Approval manager -- per-request guardrail for unsafe methods and auth."""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import auto
from typing import Any

from prowl._compat import StrEnum
from prowl.core.signals import Signal, SignalBus
from prowl.models.request import CrawlRequest

logger = logging.getLogger(__name__)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class ApprovalKind(StrEnum):
    UNSAFE_METHOD = auto()  # POST, PUT, DELETE, PATCH
    AUTH = auto()           # login / credential submission


class ApprovalState(StrEnum):
    PENDING = auto()
    APPROVED = auto()
    REJECTED = auto()


@dataclass
class ApprovalItem:
    """A single request awaiting user approval."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    kind: ApprovalKind = ApprovalKind.UNSAFE_METHOD
    request: CrawlRequest | None = None
    state: ApprovalState = ApprovalState.PENDING
    created_at: float = field(default_factory=time.time)
    resolved_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        req = self.request
        body_preview = ""
        if req and req.body:
            try:
                body_preview = req.body[:512].decode("utf-8", errors="replace")
            except Exception:
                body_preview = f"<binary {len(req.body)} bytes>"

        return {
            "id": self.id,
            "kind": self.kind,
            "state": self.state,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
            "request": {
                "url": req.url if req else "",
                "method": req.method.upper() if req else "",
                "headers": dict(req.headers) if req else {},
                "body": body_preview,
                "source_module": req.source_module if req else "",
                "depth": req.depth if req else 0,
                "auth_role": req.auth_role if req else None,
            },
        }


class ApprovalManager:
    """Per-request approval queue for unsafe methods and auth requests.

    Unlike InterventionManager (which pauses the entire engine),
    this allows safe GET requests to continue while unsafe requests
    wait for individual approval.
    """

    def __init__(self, signals: SignalBus) -> None:
        self._signals = signals
        self._items: dict[str, ApprovalItem] = {}

    async def submit(
        self, request: CrawlRequest, kind: ApprovalKind,
    ) -> ApprovalItem:
        """Park a request in the approval queue."""
        item = ApprovalItem(kind=kind, request=request)
        self._items[item.id] = item

        logger.info(
            "Approval required [%s]: %s %s (module: %s)",
            kind, request.method.upper(), request.url, request.source_module,
        )

        await self._signals.emit(
            Signal.APPROVAL_REQUESTED,
            item=item,
        )
        return item

    async def approve(self, item_id: str) -> CrawlRequest | None:
        """Approve a pending request. Returns the request for re-submission."""
        item = self._items.get(item_id)
        if not item or item.state != ApprovalState.PENDING:
            return None

        item.state = ApprovalState.APPROVED
        item.resolved_at = time.time()

        # Mark as approved so workers don't intercept again
        req = item.request
        if req:
            req.meta["approved"] = True

        logger.info("Approved: %s %s", req.method.upper() if req else "?", req.url if req else "?")

        await self._signals.emit(
            Signal.APPROVAL_RESOLVED,
            item_id=item_id,
            action="approved",
            request=req,
        )
        return req

    async def reject(self, item_id: str) -> bool:
        """Reject a pending request."""
        item = self._items.get(item_id)
        if not item or item.state != ApprovalState.PENDING:
            return False

        item.state = ApprovalState.REJECTED
        item.resolved_at = time.time()

        req = item.request
        logger.info("Rejected: %s %s", req.method.upper() if req else "?", req.url if req else "?")

        await self._signals.emit(
            Signal.APPROVAL_RESOLVED,
            item_id=item_id,
            action="rejected",
        )
        return True

    async def approve_all(self) -> list[CrawlRequest]:
        """Approve all pending items. Returns list of requests for re-submission."""
        approved: list[CrawlRequest] = []
        for item in list(self._items.values()):
            if item.state == ApprovalState.PENDING:
                req = await self.approve(item.id)
                if req:
                    approved.append(req)
        return approved

    @property
    def pending_items(self) -> list[ApprovalItem]:
        return [i for i in self._items.values() if i.state == ApprovalState.PENDING]

    @property
    def pending_count(self) -> int:
        return sum(1 for i in self._items.values() if i.state == ApprovalState.PENDING)

    def get_all(self) -> list[dict]:
        return [i.to_dict() for i in self._items.values()]

    @staticmethod
    def needs_approval(request: CrawlRequest, approve_unsafe: bool) -> bool:
        """Check whether a request requires approval."""
        if not approve_unsafe:
            return False
        if request.meta.get("approved"):
            return False
        if request.method.upper() not in _SAFE_METHODS:
            return True
        if request.meta.get("requires_approval"):
            return True
        return False

    @staticmethod
    def classify(request: CrawlRequest) -> ApprovalKind:
        """Classify the approval kind for a request."""
        if request.source_module.startswith("s7_auth"):
            return ApprovalKind.AUTH
        if request.meta.get("requires_approval") == "auth":
            return ApprovalKind.AUTH
        return ApprovalKind.UNSAFE_METHOD
