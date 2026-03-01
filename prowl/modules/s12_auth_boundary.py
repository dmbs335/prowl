"""Auth Boundary Mapper — identifies authentication and authorisation
boundaries by comparing endpoint accessibility across security contexts.

Analyses StateTransitionGraph data and TransactionStore responses to find:
- Endpoints that return different status codes for different auth levels
- Redirect-to-login patterns indicating auth-required resources
- Role-based access differences (when auth_roles are configured)

No additional HTTP requests unless auth_roles are configured, in which
case it replays known endpoints with different auth sessions to detect
access control boundaries.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from prowl.core.signals import Signal
from prowl.models.target import AuthBoundary
from prowl.modules.base import BaseModule

logger = logging.getLogger(__name__)

# Status codes that indicate auth requirements
_AUTH_STATUSES = {401, 403}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

# Patterns indicating login/auth redirect targets
_LOGIN_PATH_KEYWORDS = {"login", "signin", "sign-in", "auth", "sso", "cas", "oauth", "saml"}


class AuthBoundaryModule(BaseModule):
    """Maps authentication and authorisation boundaries across endpoints."""

    name = "s12_auth"
    description = "Auth boundary mapper — access control boundary detection"

    def __init__(self, engine: Any) -> None:
        super().__init__(engine)
        self._boundaries_found = 0

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        self.logger.info("Starting auth boundary mapping")

        # Phase A: Analyse stored transactions for auth signals
        await self._analyse_transaction_auth()

        # Phase B: Compare endpoint accessibility from state tracker (if available)
        self._analyse_state_contexts()

        # Phase C: Compare anonymous vs authenticated (if auth sessions exist)
        await self._compare_auth_roles()

        self.endpoints_found = self._boundaries_found
        self._running = False
        self.logger.info(
            "Auth boundary mapping complete — %d boundaries found",
            self._boundaries_found,
        )

    # ------------------------------------------------------------------
    # Phase A: Transaction-based auth signal detection
    # ------------------------------------------------------------------

    async def _analyse_transaction_auth(self) -> None:
        """Scan TransactionStore for auth-indicating responses."""

        # Group transactions by URL path (normalised)
        url_statuses: dict[str, list[tuple[int, str, str]]] = {}

        async for txn in self.engine.transaction_store.get_all_transactions():
            if not self._running:
                break

            path = urlparse(txn.request_url).path
            headers_lower = {k.lower(): v for k, v in txn.response_headers.items()}
            location = headers_lower.get("location", "")

            url_statuses.setdefault(path, []).append(
                (txn.response_status, txn.request_method, location)
            )

            # Direct 401/403 → auth boundary
            if txn.response_status in _AUTH_STATUSES:
                boundary = AuthBoundary(
                    url=txn.request_url,
                    method=txn.request_method,
                    unauth_status=txn.response_status,
                    boundary_type="forbidden" if txn.response_status == 403 else "unauthorized",
                    access_matrix={"anonymous": txn.response_status},
                )
                self.engine.attack_surface.register_auth_boundary(boundary)
                self._boundaries_found += 1
                await self.engine.signals.emit(
                    Signal.AUTH_BOUNDARY_FOUND, boundary=boundary,
                )

            # Redirect to login page → auth boundary
            elif txn.response_status in _REDIRECT_STATUSES and location:
                loc_path = urlparse(location).path.lower()
                if any(kw in loc_path for kw in _LOGIN_PATH_KEYWORDS):
                    boundary = AuthBoundary(
                        url=txn.request_url,
                        method=txn.request_method,
                        unauth_status=txn.response_status,
                        boundary_type="redirect_to_login",
                        access_matrix={"anonymous": txn.response_status},
                    )
                    self.engine.attack_surface.register_auth_boundary(boundary)
                    self._boundaries_found += 1
                    await self.engine.signals.emit(
                        Signal.AUTH_BOUNDARY_FOUND, boundary=boundary,
                    )

        # Check for same path returning both 200 and 401/403 (different requests)
        for path, entries in url_statuses.items():
            statuses = {s for s, _, _ in entries}
            if statuses & _AUTH_STATUSES and statuses & {200}:
                # Same path has both success and auth-failure — IDOR candidate
                for status, method, _loc in entries:
                    if status in _AUTH_STATUSES:
                        boundary = AuthBoundary(
                            url=path,
                            method=method,
                            unauth_status=status,
                            auth_status=200,
                            boundary_type="idor_candidate",
                            access_matrix={"anonymous": status, "some_user": 200},
                        )
                        self.engine.attack_surface.register_auth_boundary(boundary)
                        self._boundaries_found += 1
                        break  # one per path

    # ------------------------------------------------------------------
    # Phase B: State context comparison
    # ------------------------------------------------------------------

    def _analyse_state_contexts(self) -> None:
        """Compare endpoints visible in different security contexts."""
        state_tracker = getattr(self.engine, "state_tracker", None)
        if not state_tracker:
            return

        graph = getattr(state_tracker, "graph", None)
        if not graph or not hasattr(graph, "get_all_states"):
            return

        try:
            states = graph.get_all_states()
        except Exception:
            return

        if len(states) < 2:
            return

        # Compare endpoint sets between states
        state_endpoints: dict[str, set[str]] = {}
        for state in states:
            try:
                eps = graph.get_state_specific_endpoints(state)
                state_endpoints[str(state)] = set(eps)
            except Exception:
                continue

        # Find endpoints unique to specific states
        all_eps: set[str] = set()
        for eps in state_endpoints.values():
            all_eps |= eps

        for state_name, eps in state_endpoints.items():
            exclusive = eps - set().union(
                *(other_eps for other_name, other_eps in state_endpoints.items()
                  if other_name != state_name)
            )
            for ep_url in exclusive:
                self.logger.info(
                    "Endpoint %s exclusive to state %s", ep_url, state_name
                )

    # ------------------------------------------------------------------
    # Phase C: Role-based comparison
    # ------------------------------------------------------------------

    async def _compare_auth_roles(self) -> None:
        """If auth roles are configured, compare access across roles.

        This phase only works if auth sessions were established by s7_auth_crawl.
        It does NOT make new requests — it reads TransactionStore entries
        grouped by source_module containing auth role info.
        """
        roles = self.engine.config.auth_roles
        if not roles:
            return

        # Group transaction statuses by (url, method) and by role
        role_access: dict[tuple[str, str], dict[str, int]] = {}

        async for txn in self.engine.transaction_store.get_all_transactions():
            if not self._running:
                break

            # Determine role from source_module metadata
            role = "anonymous"
            if txn.source_module and "auth" in txn.source_module.lower():
                role = txn.source_module

            key = (txn.request_url, txn.request_method)
            role_access.setdefault(key, {})[role] = txn.response_status

        # Find endpoints where different roles get different statuses
        for (url, method), role_statuses in role_access.items():
            unique_statuses = set(role_statuses.values())
            if len(unique_statuses) > 1:
                # Different roles see different responses → boundary
                unauth = role_statuses.get("anonymous", 0)
                auth = max(
                    (s for r, s in role_statuses.items() if r != "anonymous"),
                    default=0,
                )
                boundary = AuthBoundary(
                    url=url,
                    method=method,
                    unauth_status=unauth,
                    auth_status=auth,
                    boundary_type="role_difference",
                    access_matrix=role_statuses,
                )
                self.engine.attack_surface.register_auth_boundary(boundary)
                self._boundaries_found += 1
                await self.engine.signals.emit(
                    Signal.AUTH_BOUNDARY_FOUND, boundary=boundary,
                )
