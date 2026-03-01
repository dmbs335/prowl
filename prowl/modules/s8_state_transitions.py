"""§8 State Transition Discovery — map application state machines.

Discovery Only:
- Phase A: Identify forms (login, register, checkout, etc.) — read only
- Phase B: Execute safe transitions (login with provided credentials) — login only
- Phase C: Map multi-step flows (track request sequences) — read only
- Phase D: Classify state-specific endpoints — read only

NEVER executes: registration, payment, deletion, password changes, or any
other action with side effects.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

from prowl.core.signals import Signal
from prowl.core.state_tracker import (
    FlowSequence,
    SecurityContext,
    StateTransitionGraph,
)
from prowl.models.request import CrawlRequest, CrawlResponse, FormData, HttpMethod
from prowl.models.target import Endpoint
from prowl.modules.base import BaseModule


# Forms with side effects — NEVER auto-execute
_UNSAFE_FORM_TYPES = frozenset({"register", "checkout", "password_reset"})


class StateTransitionModule(BaseModule):
    """§8: Discover application state transitions and map state-specific endpoints."""

    name = "s8_states"
    description = "State Transition Discovery (form identification, auth crawling, flow mapping)"

    def __init__(self, engine: Any) -> None:
        super().__init__(engine)
        self.state_graph = StateTransitionGraph()
        self._discovered_forms: list[dict[str, Any]] = []
        self._state_endpoints: dict[str, set[str]] = {}  # auth_level → endpoint URLs

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        await self.engine.signals.emit(Signal.MODULE_STARTED, module=self.name)

        try:
            # Phase A: Identify and classify all discovered forms
            await self._identify_forms()

            # Phase B: Execute safe state transitions (login only)
            await self._execute_safe_transitions()

            # Phase C: Map multi-step flows from transaction history
            await self._map_flows()

            # Phase D: Classify endpoints by state
            await self._classify_state_endpoints()

        finally:
            self._running = False
            await self.engine.signals.emit(
                Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats()
            )

    def get_stats(self) -> dict[str, Any]:
        stats = super().get_stats()
        stats.update({
            "forms_identified": len(self._discovered_forms),
            "state_graph": self.state_graph.get_stats(),
            "state_specific_endpoints": {
                level: len(eps)
                for level, eps in self._state_endpoints.items()
            },
        })
        return stats

    # ------------------------------------------------------------------
    # Phase A: Form identification (read-only)
    # ------------------------------------------------------------------

    async def _identify_forms(self) -> None:
        """Identify and classify all forms found during crawling."""
        for endpoint in self.engine.discovered_endpoints:
            if not self._running:
                return

        # Check forms stored in transaction responses
        txns = await self.engine.transaction_store.query(
            content_type_contains="html",
            page_type="real_content",
            limit=500,
        )

        for txn in txns:
            if not self._running:
                return

            forms = self._extract_forms_from_html(txn.response_body, txn.request_url)
            for form_info in forms:
                field_names = set(form_info["fields"])
                form_type = self.state_graph.classify_form(field_names)

                if form_type:
                    form_info["type"] = form_type
                    form_info["source_url"] = txn.request_url
                    self._discovered_forms.append(form_info)

                    self.logger.info(
                        "Form [%s] found at %s → %s (fields: %s)",
                        form_type, txn.request_url, form_info["action"],
                        ", ".join(sorted(field_names)),
                    )

        self.logger.info("Phase A: identified %d forms", len(self._discovered_forms))

    def _extract_forms_from_html(
        self, body: bytes, base_url: str
    ) -> list[dict[str, Any]]:
        """Extract form data from HTML body."""
        text = body.decode("utf-8", errors="replace")
        forms: list[dict[str, Any]] = []

        # Simple form extraction (not using BS4 to avoid dependency in this module)
        form_pattern = re.compile(
            r"<form\s+([^>]*)>(.*?)</form>", re.DOTALL | re.IGNORECASE
        )
        input_pattern = re.compile(
            r'<input\s+[^>]*name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
        )
        action_pattern = re.compile(
            r'action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE
        )
        method_pattern = re.compile(
            r'method\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE
        )

        for form_match in form_pattern.finditer(text):
            attrs = form_match.group(1)
            content = form_match.group(2)

            action_m = action_pattern.search(attrs)
            method_m = method_pattern.search(attrs)

            action = action_m.group(1) if action_m else ""
            method = (method_m.group(1) if method_m else "GET").upper()

            if action and not action.startswith("http"):
                action = urljoin(base_url, action)

            field_names = input_pattern.findall(content)

            if field_names:
                forms.append({
                    "action": action,
                    "method": method,
                    "fields": field_names,
                })

        return forms

    # ------------------------------------------------------------------
    # Phase B: Safe state transitions (login only)
    # ------------------------------------------------------------------

    async def _execute_safe_transitions(self) -> None:
        """Execute login with user-provided credentials.

        ONLY executes login forms. NEVER executes register, checkout, or delete forms.
        """
        if not self.engine.config.auth_roles:
            self.logger.info("Phase B: no auth credentials provided, skipping")
            return

        login_forms = [f for f in self._discovered_forms if f.get("type") == "login"]
        if not login_forms:
            self.logger.info("Phase B: no login forms found, skipping")
            return

        # Record anonymous state first
        anon_context = SecurityContext(auth_level="anonymous")
        anon_endpoints = {ep.url for ep in self.engine.discovered_endpoints}
        self.state_graph.record_state(anon_context)
        for ep_url in anon_endpoints:
            self.state_graph.record_endpoint_for_state(anon_context.identity, ep_url)

        # Try each auth role
        for role_config in self.engine.config.auth_roles:
            if not self._running:
                return

            role_name = role_config.get("name", "user")
            username = role_config.get("username", "")
            password = role_config.get("password", "")

            if not username or not password:
                continue

            for login_form in login_forms:
                if not self._running:
                    return

                self.logger.info(
                    "Phase B: attempting login as '%s' via %s",
                    role_name, login_form["action"],
                )

                # Build login request
                login_fields = {}
                for field_name in login_form["fields"]:
                    fl = field_name.lower()
                    if fl in ("username", "user", "email", "login", "name"):
                        login_fields[field_name] = username
                    elif fl in ("password", "passwd", "pwd", "pass"):
                        login_fields[field_name] = password
                    # CSRF token — try to get from the form page
                    elif fl in ("csrf", "token", "_token", "csrf_token", "csrfmiddlewaretoken"):
                        csrf_val = await self._get_csrf_token(
                            login_form.get("source_url", ""), field_name
                        )
                        if csrf_val:
                            login_fields[field_name] = csrf_val

                if not login_fields:
                    continue

                body = "&".join(f"{k}={v}" for k, v in login_fields.items())
                request = CrawlRequest(
                    url=login_form["action"],
                    method=HttpMethod.POST,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=body.encode(),
                    source_module=self.name,
                )

                try:
                    response = await self.engine.execute(request)
                    self.requests_made += 1

                    # Detect auth level from response
                    auth_level = self.state_graph.detect_auth_level(response)

                    if auth_level != "anonymous":
                        self.logger.info(
                            "Login successful: %s → auth_level=%s", role_name, auth_level
                        )

                        # Record new state
                        auth_context = SecurityContext(auth_level=auth_level)
                        self.state_graph.record_state(auth_context)

                        # Record transition
                        self.state_graph.record_transition(
                            before=anon_context,
                            request=request,
                            response=response,
                            after=auth_context,
                        )

                        await self.engine.signals.emit(
                            Signal.STATE_CHANGED,
                            from_state=anon_context.auth_level,
                            to_state=auth_level,
                            trigger_url=login_form["action"],
                        )

                        # Store auth session for re-crawling
                        self.engine.sessions.store_role_session(
                            role_name, response.headers
                        )

                        # Re-crawl discovered endpoints with auth
                        await self._recrawl_with_auth(role_name, auth_context)

                        break  # Success, move to next role

                except Exception as e:
                    self.errors += 1
                    self.logger.warning("Login attempt failed: %s", e)

    async def _get_csrf_token(self, form_page_url: str, field_name: str) -> str:
        """Try to get a CSRF token from the form page."""
        if not form_page_url:
            return ""

        txns = await self.engine.transaction_store.query(
            url_pattern=form_page_url, limit=1,
        )
        if not txns:
            return ""

        body_text = txns[0].response_body.decode("utf-8", errors="replace")
        pattern = re.compile(
            rf'name\s*=\s*["\']?{re.escape(field_name)}["\']?\s+value\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        match = pattern.search(body_text)
        if match:
            return match.group(1)

        # Try reversed order: value before name
        pattern2 = re.compile(
            rf'value\s*=\s*["\']([^"\']+)["\']\s+name\s*=\s*["\']?{re.escape(field_name)}["\']?',
            re.IGNORECASE,
        )
        match2 = pattern2.search(body_text)
        return match2.group(1) if match2 else ""

    def _select_recrawl_targets(
        self, endpoints: list[Endpoint], max_count: int
    ) -> list[Endpoint]:
        """Select recrawl targets prioritized by coverage insights.

        Priority order:
        1. Auth boundaries (403/401 from HindsightFeedback) — most likely to reveal new content
        2. Unvisited templates — never explored under any auth
        3. Shallow depth — broader coverage first
        """
        from prowl.core.exploration import CoverageBitmap

        boundary_urls = {
            i.url for i in self.engine.hindsight.get_auth_boundaries()
        }

        scored: list[tuple[float, Endpoint]] = []
        for ep in endpoints:
            score = 0.0
            # Auth boundary endpoints get highest priority
            if ep.url in boundary_urls:
                score += 10.0
            # Unvisited templates get next priority
            template = CoverageBitmap._normalize_to_template(ep.url)
            hit_count = self.engine.scheduler._endpoint_hit_count.get(template, 0)
            if hit_count == 0:
                score += 5.0
            elif hit_count < 3:
                score += 2.0
            # Shallow endpoints first
            score -= (ep.depth or 0) * 0.3
            scored.append((score, ep))

        scored.sort(key=lambda x: -x[0])
        return [ep for _, ep in scored[:max_count]]

    async def _recrawl_with_auth(
        self, role_name: str, auth_context: SecurityContext
    ) -> None:
        """Re-visit known endpoints with auth to discover state-specific content."""
        auth_endpoints: set[str] = set()

        targets = self._select_recrawl_targets(
            self.engine.discovered_endpoints, max_count=200
        )
        for ep in targets:
            if not self._running:
                return

            request = CrawlRequest(
                url=ep.url,
                method=HttpMethod.GET,
                auth_role=role_name,
                source_module=self.name,
                depth=ep.depth,
            )

            try:
                response = await self.engine.execute(request)
                self.requests_made += 1

                if response.status_code < 400:
                    auth_endpoints.add(ep.url)
                    self.state_graph.record_endpoint_for_state(
                        auth_context.identity, ep.url
                    )

                    # Check for new links/forms in authenticated response
                    for link in response.links:
                        if self.engine.scope.is_in_scope(link.url):
                            new_request = CrawlRequest(
                                url=link.url,
                                method=HttpMethod.GET,
                                auth_role=role_name,
                                source_module=self.name,
                                depth=ep.depth + 1,
                            )
                            await self.engine.submit(new_request)

            except Exception:
                self.errors += 1

        # Find endpoints only accessible when authenticated
        anon_eps = self.state_graph.get_state_specific_endpoints(
            SecurityContext().identity
        )
        new_eps = auth_endpoints - anon_eps
        if new_eps:
            self.logger.info(
                "Phase B: found %d endpoints accessible only as '%s'",
                len(new_eps), role_name,
            )
            for ep_url in new_eps:
                await self.engine.signals.emit(
                    Signal.STATE_ENDPOINT_FOUND,
                    url=ep_url,
                    auth_level=auth_context.auth_level,
                    role=role_name,
                )

    # ------------------------------------------------------------------
    # Phase C: Multi-step flow mapping (read-only)
    # ------------------------------------------------------------------

    async def _map_flows(self) -> None:
        """Map multi-step flows from transaction history.

        Identifies sequential request chains that form logical flows
        (e.g., GET /cart → POST /cart/add → GET /checkout).
        """
        txns = await self.engine.transaction_store.query(limit=5000)
        if len(txns) < 2:
            return

        # Group sequential redirects into flows
        current_flow_steps: list[dict] = []
        prev_url = ""

        for txn in txns:
            # Detect flow continuity: redirect chain or form submission chain
            is_continuation = False
            if txn.response_status in (301, 302, 303, 307, 308):
                is_continuation = True
            elif txn.request_method == "POST" and txn.response_status in (200, 302):
                is_continuation = True
            elif prev_url and txn.request_url == prev_url:
                is_continuation = True

            if is_continuation and current_flow_steps:
                current_flow_steps.append({
                    "url": txn.request_url,
                    "method": txn.request_method,
                    "status": txn.response_status,
                })
            else:
                # Save previous flow if long enough
                if len(current_flow_steps) >= 2:
                    self._record_flow(current_flow_steps)
                current_flow_steps = [{
                    "url": txn.request_url,
                    "method": txn.request_method,
                    "status": txn.response_status,
                }]

            # Track redirect targets
            if txn.response_status in (301, 302, 303, 307, 308):
                location = txn.response_headers.get("location", "")
                if location:
                    prev_url = urljoin(txn.request_url, location)
                else:
                    prev_url = ""
            else:
                prev_url = txn.response_url_final or txn.request_url

        # Don't forget the last flow
        if len(current_flow_steps) >= 2:
            self._record_flow(current_flow_steps)

        self.logger.info("Phase C: mapped %d multi-step flows", len(self.state_graph.flows))

    def _record_flow(self, steps: list[dict]) -> None:
        """Record a multi-step flow."""
        # Infer flow name from URLs
        urls = [s["url"] for s in steps]
        name = self._infer_flow_name(urls)

        has_side_effects = any(
            s["method"] == "POST" and any(
                kw in s["url"].lower()
                for kw in ("register", "signup", "create", "delete", "payment", "checkout")
            )
            for s in steps
        )

        flow = FlowSequence(
            name=name,
            total_new_endpoints=len(steps),
            requires_credentials=any("login" in s["url"].lower() for s in steps),
            has_side_effects=has_side_effects,
        )
        self.state_graph.record_flow(flow)

        if has_side_effects:
            self.logger.info("Flow [%s] has side effects — marked as unsafe", name)

    @staticmethod
    def _infer_flow_name(urls: list[str]) -> str:
        """Infer a descriptive name for a flow from its URLs."""
        url_text = " ".join(urls).lower()
        if "login" in url_text or "signin" in url_text:
            return "login_flow"
        if "register" in url_text or "signup" in url_text:
            return "registration_flow"
        if "checkout" in url_text or "payment" in url_text:
            return "checkout_flow"
        if "cart" in url_text:
            return "cart_flow"
        if "password" in url_text or "reset" in url_text:
            return "password_reset_flow"
        if "oauth" in url_text or "authorize" in url_text:
            return "oauth_flow"
        return f"flow_{len(urls)}_steps"

    # ------------------------------------------------------------------
    # Phase D: State-specific endpoint classification (read-only)
    # ------------------------------------------------------------------

    async def _classify_state_endpoints(self) -> None:
        """Classify endpoints by which state they're accessible from."""
        # Collect anonymous endpoints
        anon_eps: set[str] = set()
        for ep in self.engine.discovered_endpoints:
            if not ep.requires_auth and ep.status_code and ep.status_code < 400:
                anon_eps.add(ep.url)
        self._state_endpoints["anonymous"] = anon_eps

        # Authenticated endpoints come from Phase B recrawl
        for state_id, ep_urls in self.state_graph._state_endpoints.items():
            state = self.state_graph._states.get(state_id)
            if state and state.auth_level != "anonymous":
                state_only = ep_urls - anon_eps
                self._state_endpoints[state.auth_level] = state_only

        for level, eps in self._state_endpoints.items():
            self.logger.info(
                "Phase D: %s → %d endpoints (%d state-specific)",
                level, len(eps),
                len(eps - anon_eps) if level != "anonymous" else 0,
            )
