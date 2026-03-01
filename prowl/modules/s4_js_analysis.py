"""§4 JavaScript Analysis — tree-sitter AST-based endpoint and parameter extraction.

Replaces the regex-only approach with proper AST parsing for accurate extraction
of endpoints, HTTP methods, body fields, route definitions, and secrets from JS.
Falls back to regex for inline patterns that AST may miss.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import tree_sitter_javascript as ts_js
from tree_sitter import Language, Parser, Node

from prowl.core.signals import Signal
from prowl.models.target import Endpoint, Parameter, ParameterLocation, Secret
from prowl.modules.base import BaseModule


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class JSEndpoint:
    """An endpoint extracted from JS source."""

    url: str
    method: str = "GET"
    parameters: list[Parameter] = field(default_factory=list)
    source_file: str = ""
    line_number: int = 0
    confidence: float = 1.0
    tags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# AST Analyzer
# ---------------------------------------------------------------------------


# Method inference map for axios/jquery shorthand
_METHOD_MAP = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "delete": "DELETE",
    "patch": "PATCH",
    "head": "HEAD",
    "options": "OPTIONS",
}

# Patterns for URL-like strings (used in Pass 3: string literal fallback)
_URL_STRING_RE = re.compile(
    r"""^(?:https?://[^\s'"]+|/(?:api|v\d+|graphql|auth|admin|internal|ws)[/\w\-.{}:]*)$"""
)

# Secret patterns (re-used from legacy for AST-contextualized detection)
_SECRET_PATTERNS = [
    (re.compile(r"AKIA[A-Z0-9]{16}"), "aws_access_key"),
    (re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"), "jwt_token"),
]

_SECRET_VAR_NAMES = frozenset({
    "api_key", "apikey", "api-key", "secret", "secret_key", "secretkey",
    "token", "auth_token", "access_token", "password", "passwd", "pwd",
    "private_key", "privatekey", "aws_secret", "aws_access_key_id",
})


class JSASTAnalyzer:
    """Static analysis of JavaScript using tree-sitter AST.

    4-pass extraction:
    1. Base URL constants (variable assignments containing URL strings)
    2. HTTP call sites (fetch, axios, $.ajax, XMLHttpRequest)
    3. String literal URLs (fallback for patterns AST doesn't capture)
    4. Framework route definitions (React Router, Vue, Angular, Next.js)
    """

    def __init__(self) -> None:
        self._lang = Language(ts_js.language())
        self._parser = Parser(self._lang)

    def analyze(self, source: str | bytes, source_url: str = "") -> list[JSEndpoint]:
        """Parse JS source and extract all endpoints."""
        if isinstance(source, str):
            source_bytes = source.encode("utf-8", errors="replace")
        else:
            source_bytes = source

        tree = self._parser.parse(source_bytes)
        root = tree.root_node
        endpoints: list[JSEndpoint] = []
        seen_urls: set[str] = set()

        # Pass 1: Resolve base URL constants
        base_urls = self._extract_base_urls(root, source_bytes)

        # Pass 2: HTTP call sites
        for ep in self._extract_call_sites(root, source_bytes, base_urls):
            if ep.url and ep.url not in seen_urls:
                ep.source_file = source_url
                seen_urls.add(ep.url)
                endpoints.append(ep)

        # Pass 3: String literal URLs (lower confidence, catches what AST misses)
        for ep in self._extract_string_urls(root, source_bytes):
            if ep.url and ep.url not in seen_urls:
                ep.source_file = source_url
                ep.confidence = 0.6
                seen_urls.add(ep.url)
                endpoints.append(ep)

        # Pass 4: Framework route definitions
        for ep in self._extract_routes(root, source_bytes):
            if ep.url and ep.url not in seen_urls:
                ep.source_file = source_url
                seen_urls.add(ep.url)
                endpoints.append(ep)

        return endpoints

    def extract_secrets(self, source: str | bytes, source_url: str = "") -> list[Secret]:
        """Extract secrets from JS using AST context (variable name + string value)."""
        if isinstance(source, str):
            source_bytes = source.encode("utf-8", errors="replace")
        else:
            source_bytes = source

        tree = self._parser.parse(source_bytes)
        secrets: list[Secret] = []
        seen: set[str] = set()

        # AST-based: find assignments where LHS name is secret-like
        for node in self._walk(tree.root_node):
            if node.type in ("variable_declarator", "assignment_expression", "pair"):
                name_node, value_node = self._get_assignment_parts(node)
                if not name_node or not value_node:
                    continue

                var_name = self._node_text(name_node, source_bytes).lower().strip("'\"` ")
                if var_name not in _SECRET_VAR_NAMES:
                    continue

                if value_node.type in ("string", "template_string"):
                    value = self._extract_string_value(value_node, source_bytes)
                    if value and len(value) >= 8 and value not in seen:
                        seen.add(value)
                        secrets.append(Secret(
                            kind="credential",
                            value=value[:200],
                            source_url=source_url,
                            line=value_node.start_point[0] + 1,
                        ))

        # Pattern-based: AWS keys, JWTs in any string
        text = source_bytes.decode("utf-8", errors="replace")
        for pattern, kind in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                val = match.group(0)
                if val not in seen:
                    seen.add(val)
                    secrets.append(Secret(
                        kind=kind,
                        value=val[:200],
                        source_url=source_url,
                    ))

        return secrets

    # ------------------------------------------------------------------
    # Pass 1: Base URL constants
    # ------------------------------------------------------------------

    def _extract_base_urls(self, root: Node, source: bytes) -> dict[str, str]:
        """Find assignments like `const API_BASE = 'https://api.example.com'`."""
        base_urls: dict[str, str] = {}
        url_keywords = {"url", "api", "base", "endpoint", "host", "origin", "server"}

        for node in self._walk(root):
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if not name_node or not value_node:
                    continue

                var_name = self._node_text(name_node, source).lower()
                if not any(kw in var_name for kw in url_keywords):
                    continue

                if value_node.type in ("string", "template_string"):
                    value = self._extract_string_value(value_node, source)
                    if value and (value.startswith("http") or value.startswith("/")):
                        base_urls[self._node_text(name_node, source)] = value

        return base_urls

    # ------------------------------------------------------------------
    # Pass 2: HTTP call sites
    # ------------------------------------------------------------------

    def _extract_call_sites(
        self, root: Node, source: bytes, base_urls: dict[str, str]
    ) -> list[JSEndpoint]:
        """Walk AST to find fetch/axios/XHR/$.ajax calls."""
        endpoints: list[JSEndpoint] = []

        for node in self._walk(root):
            if node.type != "call_expression":
                continue

            fn_node = node.child_by_field_name("function")
            if not fn_node:
                continue

            fn_text = self._node_text(fn_node, source)
            args_node = node.child_by_field_name("arguments")
            if not args_node:
                continue

            args = [c for c in args_node.children if c.type not in ("(", ")", ",")]

            ep = None

            # fetch(url, options?)
            if fn_text == "fetch" and args:
                ep = self._parse_fetch(args, source, base_urls, node)

            # axios.get/post/put/delete/patch(url, data?, config?)
            elif fn_node.type == "member_expression":
                obj_text, method_text = self._parse_member(fn_node, source)
                if obj_text in ("axios", "$http", "http", "api", "client", "request"):
                    ep = self._parse_axios_call(method_text, args, source, base_urls, node)
                elif obj_text == "$" and method_text in ("ajax", "get", "post", "getJSON"):
                    ep = self._parse_jquery(method_text, args, source, base_urls, node)

            # XMLHttpRequest.open(method, url)
            if not ep and fn_node.type == "member_expression":
                _, method_text = self._parse_member(fn_node, source)
                if method_text == "open" and len(args) >= 2:
                    ep = self._parse_xhr_open(args, source, base_urls, node)

            if ep and ep.url:
                endpoints.append(ep)

        return endpoints

    def _parse_fetch(
        self, args: list[Node], source: bytes, base_urls: dict, node: Node
    ) -> JSEndpoint | None:
        """Parse fetch(url, {method, headers, body})."""
        url = self._resolve_url(args[0], source, base_urls)
        if not url:
            return None

        method = "GET"
        params: list[Parameter] = []
        tags = ["js_ast", "fetch"]

        # Second arg is options object
        if len(args) >= 2 and args[1].type == "object":
            for pair in self._get_object_pairs(args[1], source):
                key, value_node = pair
                if key == "method":
                    method = self._extract_string_value(value_node, source).upper() or "GET"
                elif key == "body" and value_node.type == "object":
                    params = self._extract_body_params(value_node, source)
                elif key == "headers" and value_node.type == "object":
                    for hdr_pair in self._get_object_pairs(value_node, source):
                        hdr_name, _ = hdr_pair
                        params.append(Parameter(
                            name=hdr_name,
                            location=ParameterLocation.HEADER,
                            source_module="s4_js",
                        ))

        return JSEndpoint(
            url=url, method=method, parameters=params,
            line_number=node.start_point[0] + 1, tags=tags,
        )

    def _parse_axios_call(
        self, method_name: str, args: list[Node], source: bytes,
        base_urls: dict, node: Node,
    ) -> JSEndpoint | None:
        """Parse axios.get(url) or axios.post(url, data)."""
        if not args:
            return None

        url = self._resolve_url(args[0], source, base_urls)
        if not url:
            return None

        method = _METHOD_MAP.get(method_name.lower(), "GET")
        params: list[Parameter] = []

        # axios.post(url, data) — second arg is body
        if len(args) >= 2 and args[1].type == "object" and method in ("POST", "PUT", "PATCH"):
            params = self._extract_body_params(args[1], source)

        return JSEndpoint(
            url=url, method=method, parameters=params,
            line_number=node.start_point[0] + 1, tags=["js_ast", "axios"],
        )

    def _parse_jquery(
        self, method_name: str, args: list[Node], source: bytes,
        base_urls: dict, node: Node,
    ) -> JSEndpoint | None:
        """Parse $.ajax({url, method, data}) or $.get/$.post(url, data)."""
        if not args:
            return None

        if method_name == "ajax" and args[0].type == "object":
            url = ""
            method = "GET"
            params: list[Parameter] = []
            for pair in self._get_object_pairs(args[0], source):
                key, value_node = pair
                if key == "url":
                    url = self._resolve_url(value_node, source, base_urls) or ""
                elif key in ("method", "type"):
                    method = self._extract_string_value(value_node, source).upper() or "GET"
                elif key == "data" and value_node.type == "object":
                    params = self._extract_body_params(value_node, source)
            if url:
                return JSEndpoint(
                    url=url, method=method, parameters=params,
                    line_number=node.start_point[0] + 1, tags=["js_ast", "jquery"],
                )
        else:
            url = self._resolve_url(args[0], source, base_urls)
            if url:
                method = "POST" if method_name == "post" else "GET"
                params = []
                if len(args) >= 2 and args[1].type == "object":
                    params = self._extract_body_params(args[1], source)
                return JSEndpoint(
                    url=url, method=method, parameters=params,
                    line_number=node.start_point[0] + 1, tags=["js_ast", "jquery"],
                )

        return None

    def _parse_xhr_open(
        self, args: list[Node], source: bytes, base_urls: dict, node: Node
    ) -> JSEndpoint | None:
        """Parse XMLHttpRequest.open(method, url)."""
        method_str = self._extract_string_value(args[0], source).upper()
        url = self._resolve_url(args[1], source, base_urls)
        if url and method_str:
            return JSEndpoint(
                url=url, method=method_str,
                line_number=node.start_point[0] + 1, tags=["js_ast", "xhr"],
            )
        return None

    # ------------------------------------------------------------------
    # Pass 3: String literal URLs
    # ------------------------------------------------------------------

    def _extract_string_urls(self, root: Node, source: bytes) -> list[JSEndpoint]:
        """Find string literals that look like API paths (lower-confidence fallback)."""
        endpoints: list[JSEndpoint] = []
        for node in self._walk(root):
            if node.type in ("string", "template_string"):
                value = self._extract_string_value(node, source)
                if value and _URL_STRING_RE.match(value):
                    endpoints.append(JSEndpoint(
                        url=value,
                        line_number=node.start_point[0] + 1,
                        tags=["js_ast", "string_literal"],
                    ))
        return endpoints

    # ------------------------------------------------------------------
    # Pass 4: Framework routes
    # ------------------------------------------------------------------

    def _extract_routes(self, root: Node, source: bytes) -> list[JSEndpoint]:
        """Find React Router / Vue / Angular / Next.js route definitions."""
        endpoints: list[JSEndpoint] = []

        for node in self._walk(root):
            # React Router: <Route path="/dashboard" ...>
            if node.type == "jsx_self_closing_element" or node.type == "jsx_opening_element":
                tag_node = node.child(0) if node.child_count > 0 else None
                # Look for tag name containing "Route"
                if tag_node:
                    tag_text = self._node_text(tag_node, source)
                    if "Route" in tag_text or "route" in tag_text:
                        path = self._get_jsx_attribute(node, "path", source)
                        if path and path.startswith("/"):
                            endpoints.append(JSEndpoint(
                                url=path,
                                line_number=node.start_point[0] + 1,
                                tags=["js_ast", "react_route"],
                            ))

            # Vue/Angular: { path: '/...' } inside arrays
            elif node.type == "pair":
                key_node = node.child_by_field_name("key")
                value_node = node.child_by_field_name("value")
                if key_node and value_node:
                    key_text = self._node_text(key_node, source).strip("'\"` ")
                    if key_text == "path" and value_node.type == "string":
                        path = self._extract_string_value(value_node, source)
                        if path and path.startswith("/"):
                            endpoints.append(JSEndpoint(
                                url=path,
                                line_number=node.start_point[0] + 1,
                                tags=["js_ast", "framework_route"],
                            ))

        return endpoints

    # ------------------------------------------------------------------
    # AST helpers
    # ------------------------------------------------------------------

    def _walk(self, node: Node) -> list[Node]:
        """Pre-order traversal of the AST."""
        result: list[Node] = []
        stack = [node]
        while stack:
            current = stack.pop()
            result.append(current)
            # Push children in reverse so leftmost is processed first
            for i in range(current.child_count - 1, -1, -1):
                child = current.child(i)
                if child:
                    stack.append(child)
        return result

    def _node_text(self, node: Node, source: bytes) -> str:
        """Get the source text for a node."""
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def _extract_string_value(self, node: Node, source: bytes) -> str:
        """Extract the content of a string/template_string node (strips quotes)."""
        text = self._node_text(node, source)
        if node.type == "string":
            # Remove surrounding quotes
            if len(text) >= 2 and text[0] in "'\"`" and text[-1] == text[0]:
                return text[1:-1]
            return text
        elif node.type == "template_string":
            # Remove backticks, replace ${...} with {param}
            inner = text.strip("`")
            inner = re.sub(r"\$\{(\w+)\}", r"{\1}", inner)
            return inner
        return text

    def _resolve_url(self, node: Node, source: bytes, base_urls: dict) -> str | None:
        """Resolve a URL from a node. Handles strings, template literals, identifiers."""
        if node.type in ("string", "template_string"):
            return self._extract_string_value(node, source) or None

        if node.type == "identifier":
            var_name = self._node_text(node, source)
            return base_urls.get(var_name)

        # Binary expression: baseUrl + "/path"
        if node.type == "binary_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right:
                left_val = self._resolve_url(left, source, base_urls)
                right_val = self._resolve_url(right, source, base_urls)
                if left_val and right_val:
                    return left_val.rstrip("/") + "/" + right_val.lstrip("/")
                return left_val or right_val

        return None

    def _parse_member(self, node: Node, source: bytes) -> tuple[str, str]:
        """Parse a member_expression into (object, property)."""
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        obj_text = self._node_text(obj, source) if obj else ""
        prop_text = self._node_text(prop, source) if prop else ""
        return obj_text, prop_text

    def _get_object_pairs(self, obj_node: Node, source: bytes) -> list[tuple[str, Node]]:
        """Extract key-value pairs from an object literal."""
        pairs: list[tuple[str, Node]] = []
        for child in obj_node.children:
            if child.type == "pair":
                key_node = child.child_by_field_name("key")
                value_node = child.child_by_field_name("value")
                if key_node and value_node:
                    key = self._node_text(key_node, source).strip("'\"` ")
                    pairs.append((key, value_node))
        return pairs

    def _extract_body_params(self, obj_node: Node, source: bytes) -> list[Parameter]:
        """Extract parameter names from an object literal (e.g., body of POST)."""
        params: list[Parameter] = []
        for key, _ in self._get_object_pairs(obj_node, source):
            if key:
                params.append(Parameter(
                    name=key,
                    location=ParameterLocation.BODY,
                    source_module="s4_js",
                ))
        return params

    def _get_jsx_attribute(self, node: Node, attr_name: str, source: bytes) -> str:
        """Get a JSX attribute value by name."""
        for child in node.children:
            if child.type == "jsx_attribute":
                name_node = child.child(0)
                if name_node and self._node_text(name_node, source) == attr_name:
                    value_node = child.child(2) if child.child_count >= 3 else None
                    if value_node:
                        return self._extract_string_value(value_node, source)
        return ""

    def _get_assignment_parts(self, node: Node) -> tuple[Node | None, Node | None]:
        """Get name and value nodes from variable_declarator, assignment, or pair."""
        if node.type == "variable_declarator":
            return node.child_by_field_name("name"), node.child_by_field_name("value")
        elif node.type == "assignment_expression":
            return node.child_by_field_name("left"), node.child_by_field_name("right")
        elif node.type == "pair":
            return node.child_by_field_name("key"), node.child_by_field_name("value")
        return None, None


# ---------------------------------------------------------------------------
# Module wrapper
# ---------------------------------------------------------------------------


class JSAnalysisModule(BaseModule):
    """§4: Analyze JavaScript files for endpoints using AST parsing.

    Reads JS responses from TransactionStore (no re-download needed).
    Also analyzes inline <script> content in HTML responses.
    """

    name = "s4_js"
    description = "JavaScript AST Analysis (tree-sitter endpoint extraction)"

    def __init__(self, engine: Any) -> None:
        super().__init__(engine)
        self._analyzer = JSASTAnalyzer()
        self._analyzed_urls: set[str] = set()

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        await self.engine.signals.emit(Signal.MODULE_STARTED, module=self.name)

        try:
            # Phase A: Analyze JS files from TransactionStore
            async for txn in self.engine.transaction_store.get_all_js_responses():
                if not self._running:
                    break
                if txn.request_url in self._analyzed_urls:
                    continue
                # Size check
                if len(txn.response_body) > self.engine.config.js_max_file_size:
                    self.logger.warning(
                        "Skipping large JS: %s (%d bytes)",
                        txn.request_url, len(txn.response_body),
                    )
                    continue

                self._analyzed_urls.add(txn.request_url)
                await self._analyze(txn.response_body, txn.request_url)

            # Phase B: Analyze inline <script> tags in HTML responses
            async for txn in self.engine.transaction_store.get_all_html_responses():
                if not self._running:
                    break
                if txn.request_url in self._analyzed_urls:
                    continue
                self._analyzed_urls.add(txn.request_url)

                for script in self._extract_inline_scripts(txn.response_body):
                    if len(script) > 100:  # Skip trivially short scripts
                        await self._analyze(script.encode("utf-8"), txn.request_url)

        finally:
            self._running = False
            await self.engine.signals.emit(
                Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats()
            )

    async def _analyze(self, source: bytes, source_url: str) -> None:
        """Run AST analysis and register discovered endpoints/secrets."""
        endpoints = self._analyzer.analyze(source, source_url)
        secrets = self._analyzer.extract_secrets(source, source_url)

        for ep in endpoints:
            # Resolve relative URLs
            if ep.url.startswith("/"):
                full_url = urljoin(self.engine.config.target_url, ep.url)
            elif ep.url.startswith("http"):
                full_url = ep.url
            else:
                continue

            # Check scope
            if not self.engine.scope.is_in_scope(full_url):
                continue

            endpoint = Endpoint(
                url=full_url,
                method=ep.method,
                parameters=ep.parameters,
                source_module=self.name,
                tags=ep.tags,
            )
            await self.engine.register_endpoint(endpoint)
            await self.engine.signals.emit(
                Signal.JS_ENDPOINT_EXTRACTED,
                endpoint=endpoint,
                confidence=ep.confidence,
                source_file=source_url,
                line=ep.line_number,
            )
            self.endpoints_found += 1

        for secret in secrets:
            await self.engine.signals.emit(Signal.SECRET_FOUND, secret=secret)
            self.logger.warning("Secret [%s] in %s", secret.kind, source_url)

    @staticmethod
    def _extract_inline_scripts(html_body: bytes) -> list[str]:
        """Extract content of <script> tags from HTML."""
        text = html_body.decode("utf-8", errors="replace")
        scripts: list[str] = []
        # Simple but effective: find <script>...</script> blocks
        pattern = re.compile(
            r"<script[^>]*>(.+?)</script>", re.DOTALL | re.IGNORECASE
        )
        for match in pattern.finditer(text):
            content = match.group(1).strip()
            if content:
                scripts.append(content)
        return scripts
