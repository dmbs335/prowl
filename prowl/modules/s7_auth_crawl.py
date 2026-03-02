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

        # Auth method priority: raw request > credentials > static cookies/token
        if "raw_request_file" in role_config:
            await self._replay_raw_requests(role, role_config["raw_request_file"])
        elif "username" in role_config and "login_url" in role_config:
            role.credential = Credential(
                username=role_config["username"],
                password=role_config.get("password", ""),
                login_url=role_config["login_url"],
            )
            await self._perform_login(role)
        elif not role.cookies and not role.token and not role.headers:
            # No auth info at all - request intervention
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
        ep_count = len(self.engine.discovered_endpoints)
        self.logger.info(
            "Crawling as role: %s (%d endpoints, %d cookies)",
            role_name, ep_count, len(role.cookies),
        )
        crawled_urls: set[str] = {ep.url for ep in self.engine.discovered_endpoints}
        follow_queue: list[str] = []

        for ep in self.engine.discovered_endpoints[:200]:
            if not self._running:
                break
            request = CrawlRequest(
                url=ep.url,
                method=ep.method.lower(),
                source_module=self.name,
                auth_role=role_name,
                priority=7,
            )
            await self.engine.rate_limiter.wait()
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
                        if link.url not in crawled_urls:
                            follow_queue.append(link.url)

        # Phase 2: crawl auth-only links (e.g. userinfo.php, profile pages)
        if follow_queue:
            self.logger.info("Following %d new auth-only links", len(follow_queue))
        seen_follow: set[str] = set()
        for url in follow_queue:
            if not self._running or url in seen_follow:
                continue
            seen_follow.add(url)
            request = CrawlRequest(
                url=url,
                method="get",
                source_module=self.name,
                auth_role=role_name,
                priority=6,
            )
            await self.engine.rate_limiter.wait()
            response = await self.engine.execute(request)
            self.requests_made += 1
            if response.is_success:
                auth_endpoint = Endpoint(
                    url=response.url_final or url,
                    method="GET",
                    status_code=response.status_code,
                    content_type=response.content_type,
                    source_module=self.name,
                    tags=[f"auth:{role_name}", "auth_only"],
                )
                await self.engine.register_endpoint(auth_endpoint)
                self.endpoints_found += 1

    async def _replay_raw_requests(self, role: AuthRole, file_path: str) -> None:
        """Authenticate by replaying raw HTTP request(s) from a file."""
        from prowl.core.auth_utils import load_raw_requests, replay_raw_request

        try:
            parsed_requests = load_raw_requests(file_path)
        except FileNotFoundError as e:
            self.logger.error("%s", e)
            self.errors += 1
            return

        if not parsed_requests:
            self.logger.warning("No valid requests found in %s", file_path)
            return

        self.logger.info(
            "Replaying %d raw request(s) for role '%s' from %s",
            len(parsed_requests), role.name, file_path,
        )

        for i, parsed in enumerate(parsed_requests, 1):
            result = await replay_raw_request(parsed)
            self.requests_made += 1

            if result["success"]:
                role.cookies.update(result["cookies"])
                role.is_active = True
                self.logger.info(
                    "  [%d/%d] %s %s -> %s",
                    i, len(parsed_requests),
                    parsed["method"], parsed["url"], result["message"],
                )
            else:
                self.logger.warning(
                    "  [%d/%d] %s %s -> %s",
                    i, len(parsed_requests),
                    parsed["method"], parsed["url"], result["message"],
                )

        if role.is_active:
            self.logger.info(
                "Raw request auth complete for '%s' (%d cookies)",
                role.name, len(role.cookies),
            )
        else:
            self.errors += 1
            await self.engine.signals.emit(
                Signal.INTERVENTION_REQUESTED,
                kind="login",
                message=f"Raw request replay failed for '{role.name}'. Check the request file.",
                module=self.name,
            )

    async def _perform_login(self, role: AuthRole) -> None:
        """Attempt automated login using provided credentials.

        Auto-detects form field names by fetching and parsing the login page.
        Falls back to common field names if parsing fails.
        """
        if not role.credential:
            return

        import httpx
        from lxml.html import fromstring as html_fromstring

        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
            try:
                # Step 1: Fetch login page to discover form field names
                user_field = "username"
                pass_field = "password"
                form_action = role.credential.login_url
                extra_hidden: dict[str, str] = {}

                try:
                    get_resp = await client.get(role.credential.login_url)
                    self.requests_made += 1
                    if get_resp.status_code == 200 and "html" in get_resp.headers.get("content-type", ""):
                        doc = html_fromstring(get_resp.content)
                        doc.make_links_absolute(role.credential.login_url, resolve_base_href=True)
                        detected = self._detect_login_fields(doc)
                        if detected:
                            user_field = detected["user_field"]
                            pass_field = detected["pass_field"]
                            if detected.get("action"):
                                form_action = detected["action"]
                            extra_hidden = detected.get("hidden", {})
                            self.logger.info(
                                "Detected login fields: user=%s pass=%s action=%s",
                                user_field, pass_field, form_action,
                            )
                except Exception as e:
                    self.logger.debug("Could not parse login page: %s", e)

                # Step 2: POST login form with detected field names
                login_data = {
                    user_field: role.credential.username,
                    pass_field: role.credential.password,
                    **extra_hidden,
                    **role.credential.extra_fields,
                }
                resp = await client.post(form_action, data=login_data)
                self.requests_made += 1

                if resp.status_code < 400:
                    # Extract cookies from response
                    for cookie in resp.cookies.jar:
                        role.cookies[cookie.name] = cookie.value
                    role.is_active = True
                    self.logger.info(
                        "Login successful for role: %s (%d cookies)",
                        role.name, len(role.cookies),
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

    @staticmethod
    def _detect_login_fields(doc) -> dict | None:
        """Parse HTML to find login form fields (username + password inputs)."""
        _USER_HINTS = {"user", "uname", "username", "login", "email", "account", "name", "usr"}
        _PASS_HINTS = {"pass", "password", "passwd", "pwd", "secret"}

        for form in doc.xpath("//form"):
            inputs = form.xpath(".//input[@name]")
            user_field = None
            pass_field = None
            hidden_fields: dict[str, str] = {}

            for inp in inputs:
                name = inp.get("name", "")
                inp_type = inp.get("type", "text").lower()

                if inp_type == "password":
                    pass_field = name
                elif inp_type == "hidden":
                    hidden_fields[name] = inp.get("value", "")
                elif inp_type in ("text", "email", "") and not user_field:
                    # First text/email input or name hints at username
                    if name.lower() in _USER_HINTS or not user_field:
                        user_field = name

            if pass_field:
                action = form.get("action", "")
                return {
                    "user_field": user_field or "username",
                    "pass_field": pass_field,
                    "action": action or None,
                    "hidden": hidden_fields,
                }
        return None
