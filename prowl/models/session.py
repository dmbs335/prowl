"""Authentication and session models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Credential(BaseModel):
    """Login credentials for authenticated crawling."""

    username: str
    password: str
    login_url: str = ""
    extra_fields: dict[str, str] = Field(default_factory=dict)


class AuthRole(BaseModel):
    """An authentication role (e.g., admin, user, guest)."""

    name: str
    credential: Credential | None = None
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    token: str = ""
    is_active: bool = False


class AuthSession(BaseModel):
    """Active authenticated session with state tracking."""

    role: AuthRole
    session_cookies: dict[str, str] = Field(default_factory=dict)
    csrf_token: str = ""
    last_used: float = 0.0
    request_count: int = 0
    is_valid: bool = True
