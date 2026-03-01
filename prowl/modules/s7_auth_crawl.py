"""§7 Authenticated Crawling module."""

from __future__ import annotations

from typing import Any

from prowl.core.signals import Signal
from prowl.models.request import CrawlRequest
from prowl.models.session import AuthRole, AuthSession, Credential
from prowl.models.target import Endpoint
from prowl.modules.base import BaseModule


class AuthCrawlModule(BaseModule):
    """§7: Crawl the target as authenticated users with different roles."""

    name = "s7_auth"
    description = "Authenticated Crawling (multi-role session management)"

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        await self.engine.signals.emit(Signal.MODULE_STARTED, module=self.name)

        roles = self.engine.config.auth_roles

        try:
            if not roles:
                # Request manual intervention for login
                await self.engine.signals.emit(
                    Signal.INTERVENTION_REQUESTED,
                    kind="login",
                    message="No auth roles configured. Please log in manually or provide credentials.",
                    module=self.name,
                )
                # The intervention system will pause/resume engine
                return

            for role_config in roles:
                if not self._running:
                    break
                await self._crawl_as_role(role_config)

        finally:
            self._running = False
            await self.engine.signals.emit(
                Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats()
            )

    async def _crawl_as_role(self, role_config: dict) -> None:
        """Set up auth session and crawl as this role."""
        role_name = role_config.get("name", "default")

        role = AuthRole(
            name=role_name,
            cookies=role_config.get("cookies", {}),
            headers=role_config.get("headers", {}),
            token=role_config.get("token", ""),
        )

        # If credentials provided, attempt login
        if "username" in role_config and "login_url" in role_config:
            role.credential = Credential(
                username=role_config["username"],
                password=role_config.get("password", ""),
                login_url=role_config["login_url"],
            )
            await self._perform_login(role)
        elif not role.cookies and not role.token and not role.headers:
            # No auth info at all — request intervention
            await self.engine.signals.emit(
                Signal.INTERVENTION_REQUESTED,
                kind="login",
                message=f"Login required for role '{role_name}'. Please authenticate manually.",
                module=self.name,
            )
            return

        # Register session
        session = AuthSession(role=role)
        self.engine.sessions.add_role(role)
        self.engine.sessions.add_session(session)

        # Re-crawl known endpoints with this auth role
        self.logger.info("Crawling as role: %s", role_name)
        for ep in self.engine.discovered_endpoints[:200]:
            if not self._running:
                break
            request = CrawlRequest(
                url=ep.url,
                method=ep.method,
                source_module=self.name,
                auth_role=role_name,
                priority=7,
            )
            response = await self.engine.execute(request)
            self.requests_made += 1

            if response.is_success:
                # Check for new content not seen unauthenticated
                if not self.engine.dedup.is_duplicate_content(response.content_hash):
                    self.engine.dedup.mark_seen_content(response.content_hash)
                    auth_endpoint = Endpoint(
                        url=ep.url,
                        method=ep.method,
                        status_code=response.status_code,
                        content_type=response.content_type,
                        source_module=self.name,
                        tags=[f"auth:{role_name}"],
                    )
                    await self.engine.register_endpoint(auth_endpoint)
                    self.endpoints_found += 1

                    # Follow new links discovered in authenticated pages
                    for link in response.links:
                        child = CrawlRequest(
                            url=link.url,
                            source_module=self.name,
                            auth_role=role_name,
                            priority=6,
                        )
                        await self.engine.submit(child)

    async def _perform_login(self, role: AuthRole) -> None:
        """Attempt automated login using provided credentials."""
        if not role.credential:
            return

        import httpx

        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
            try:
                # POST login form
                resp = await client.post(
                    role.credential.login_url,
                    data={
                        "username": role.credential.username,
                        "password": role.credential.password,
                        **role.credential.extra_fields,
                    },
                )
                self.requests_made += 1

                if resp.status_code < 400:
                    # Extract cookies from response
                    for cookie in resp.cookies.jar:
                        role.cookies[cookie.name] = cookie.value
                    role.is_active = True
                    self.logger.info(
                        "Login successful for role: %s", role.name
                    )
                else:
                    self.logger.warning(
                        "Login failed for %s (status %d)", role.name, resp.status_code
                    )
                    await self.engine.signals.emit(
                        Signal.INTERVENTION_REQUESTED,
                        kind="login",
                        message=f"Automated login failed for '{role.name}'. Please log in manually.",
                        module=self.name,
                    )
            except Exception as e:
                self.errors += 1
                self.logger.error("Login error: %s", e)
