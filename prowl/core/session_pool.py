"""Session pool for managing authentication sessions (Crawlee-inspired)."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from prowl.models.session import AuthRole, AuthSession

logger = logging.getLogger(__name__)


class SessionPool:
    """Manages multiple authenticated sessions with rotation."""

    def __init__(self, max_sessions_per_role: int = 3) -> None:
        self._roles: dict[str, AuthRole] = {}
        self._sessions: dict[str, list[AuthSession]] = {}
        self._max_per_role = max_sessions_per_role
        self._lock = asyncio.Lock()

    async def add_role(self, role: AuthRole) -> None:
        """Register an auth role."""
        async with self._lock:
            self._roles[role.name] = role
            if role.name not in self._sessions:
                self._sessions[role.name] = []

    async def add_session(self, session: AuthSession) -> None:
        """Add an active session for a role."""
        async with self._lock:
            role_name = session.role.name
            if role_name not in self._roles:
                self._roles[role_name] = session.role
            if role_name not in self._sessions:
                self._sessions[role_name] = []
            sessions = self._sessions[role_name]
            if len(sessions) >= self._max_per_role:
                # Remove oldest
                sessions.pop(0)
            sessions.append(session)

    async def get_session(self, role_name: str) -> AuthSession | None:
        """Get a valid session for the given role, rotating usage."""
        async with self._lock:
            sessions = self._sessions.get(role_name, [])
            valid = [s for s in sessions if s.is_valid]
            if not valid:
                return None

            # Least recently used
            valid.sort(key=lambda s: s.last_used)
            session = valid[0]
            session.last_used = time.time()
            session.request_count += 1
            return session

    def invalidate_session(self, role_name: str, session: AuthSession) -> None:
        """Mark a session as invalid."""
        session.is_valid = False
        logger.info("Session invalidated for role: %s", role_name)

    async def update_session_cookies(
        self, role_name: str, cookies: dict[str, str]
    ) -> None:
        """Update cookies for the most recent session of a role.

        If no session exists for the role, creates one automatically.
        """
        async with self._lock:
            if role_name not in self._sessions:
                self._sessions[role_name] = []
            sessions = self._sessions[role_name]
            valid = [s for s in sessions if s.is_valid]
            if valid:
                valid[-1].session_cookies.update(cookies)
            else:
                # Create a new session for this role
                role = self._roles.get(role_name, AuthRole(name=role_name))
                self._roles[role_name] = role
                session = AuthSession(role=role, session_cookies=dict(cookies))
                sessions.append(session)
                logger.info("Created new session for role '%s' with %d cookies", role_name, len(cookies))

    @property
    def role_names(self) -> list[str]:
        return list(self._sessions.keys())

    @property
    def active_session_count(self) -> int:
        return sum(
            len([s for s in sessions if s.is_valid])
            for sessions in self._sessions.values()
        )

    async def get_headers_for_role(self, role_name: str) -> dict[str, str]:
        """Get auth headers (cookies + custom headers) for a role."""
        session = await self.get_session(role_name)
        if not session:
            return {}

        headers: dict[str, str] = {}

        # Merge role headers
        headers.update(session.role.headers)

        # Add bearer token if present
        if session.role.token:
            headers["Authorization"] = f"Bearer {session.role.token}"

        # Build cookie header
        all_cookies = {**session.role.cookies, **session.session_cookies}
        if all_cookies:
            headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in all_cookies.items()
            )

        # Add CSRF token if known
        if session.csrf_token:
            headers["X-CSRF-Token"] = session.csrf_token

        return headers
