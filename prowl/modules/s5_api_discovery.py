"""§5 API Surface Discovery module."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin

import httpx

from prowl.core.signals import Signal
from prowl.models.target import APISchema, Endpoint, Parameter, ParameterLocation
from prowl.modules.base import BaseModule

# Common API documentation paths
OPENAPI_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs.json", "/v2/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json", "/swagger-resources",
    "/.well-known/openapi.json",
]

GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/altair", "/playground",
    "/api/graphql", "/v1/graphql", "/__graphql",
]

WSDL_PATHS = [
    "?wsdl", "?WSDL", "/ws?wsdl", "/service?wsdl",
    "/services?wsdl",
]


class APIDiscoveryModule(BaseModule):
    """§5: Discover API surfaces (REST/OpenAPI, GraphQL, SOAP/WSDL)."""

    name = "s5_api"
    description = "API Surface Discovery (OpenAPI, GraphQL introspection, WSDL)"

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        await self.engine.signals.emit(Signal.MODULE_STARTED, module=self.name)

        target = self.engine.config.target_url.rstrip("/")

        try:
            # Run all API probes in parallel for speed
            import asyncio
            await asyncio.gather(
                self._probe_openapi(target),
                self._probe_graphql(target),
                self._probe_wsdl(target),
                return_exceptions=True,
            )

        finally:
            self._running = False
            await self.engine.signals.emit(
                Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats()
            )

    async def _probe_openapi(self, base_url: str) -> None:
        """Probe for OpenAPI/Swagger documentation (all paths concurrently)."""
        import asyncio

        async def _try_path(client: httpx.AsyncClient, path: str) -> None:
            if not self._running:
                return
            url = f"{base_url}{path}"
            try:
                resp = await client.get(url)
                self.requests_made += 1
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    if "json" in content_type or "yaml" in content_type:
                        self.logger.info("Found OpenAPI doc: %s", url)
                        await self._parse_openapi(url, resp.text)
            except Exception:
                self.errors += 1

        async with httpx.AsyncClient(timeout=10.0) as client:
            await asyncio.gather(*[_try_path(client, p) for p in OPENAPI_PATHS])

    async def _parse_openapi(self, url: str, content: str) -> None:
        """Deep-parse OpenAPI spec: parameters, requestBody with $ref resolution, security."""
        try:
            spec = json.loads(content)
        except json.JSONDecodeError:
            return

        base_url = self.engine.config.target_url.rstrip("/")
        paths = spec.get("paths", {})
        endpoints: list[Endpoint] = []

        loc_map = {
            "query": ParameterLocation.QUERY,
            "header": ParameterLocation.HEADER,
            "path": ParameterLocation.PATH,
            "cookie": ParameterLocation.COOKIE,
        }

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    continue

                full_url = f"{base_url}{path}"
                params: list[Parameter] = []
                tags = ["openapi"]

                # 1. Path/query/header/cookie parameters
                for p in details.get("parameters", []):
                    params.append(Parameter(
                        name=p.get("name", ""),
                        location=loc_map.get(p.get("in", "query"), ParameterLocation.QUERY),
                        param_type=self._resolve_schema_type(p.get("schema", {}), spec),
                        required=p.get("required", False),
                        source_module=self.name,
                    ))

                # 2. requestBody (OpenAPI 3.x)
                request_body = details.get("requestBody", {})
                if "$ref" in request_body:
                    request_body = self._resolve_ref(request_body["$ref"], spec) or {}
                for ct, media in request_body.get("content", {}).items():
                    schema = media.get("schema", {})
                    if "$ref" in schema:
                        schema = self._resolve_ref(schema["$ref"], spec) or schema
                    body_params = self._flatten_schema(schema, spec, prefix="")
                    params.extend(body_params)
                    if "json" in ct:
                        tags.append("json_body")
                    elif "xml" in ct:
                        tags.append("xml_body")
                    elif "form" in ct or "multipart" in ct:
                        tags.append("form_body")

                # 3. Security requirements
                security = details.get("security", spec.get("security", []))
                if security:
                    auth_schemes = []
                    for sec_item in security:
                        auth_schemes.extend(sec_item.keys())
                    if auth_schemes:
                        tags.append(f"auth:{','.join(auth_schemes)}")

                ep = Endpoint(
                    url=full_url,
                    method=method.upper(),
                    parameters=params,
                    source_module=self.name,
                    tags=tags,
                    requires_auth=bool(security),
                )
                endpoints.append(ep)
                await self.engine.register_endpoint(ep)
                self.endpoints_found += 1

        schema_obj = APISchema(
            schema_type="openapi",
            url=url,
            endpoints=endpoints,
            raw_content=content[:10000],
            auth_schemes=self._extract_auth_schemes(spec),
        )
        await self.engine.signals.emit(Signal.API_SCHEMA_FOUND, schema=schema_obj)

    def _resolve_ref(self, ref: str, spec: dict) -> dict | None:
        """Resolve a JSON $ref pointer (e.g., '#/components/schemas/User')."""
        if not ref.startswith("#/"):
            return None
        parts = ref[2:].split("/")
        current: Any = spec
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current if isinstance(current, dict) else None

    def _flatten_schema(
        self, schema: dict, spec: dict, prefix: str = "", depth: int = 0,
        _visited_refs: set[str] | None = None,
    ) -> list[Parameter]:
        """Flatten an OpenAPI schema into a list of body parameters (dot-notation for nested)."""
        if depth > 5:
            return []
        if _visited_refs is None:
            _visited_refs = set()

        params: list[Parameter] = []

        if "$ref" in schema:
            ref = schema["$ref"]
            if ref in _visited_refs:
                return []  # circular reference
            _visited_refs.add(ref)
            resolved = self._resolve_ref(ref, spec)
            if resolved:
                return self._flatten_schema(resolved, spec, prefix, depth, _visited_refs)

        schema_type = schema.get("type", "object")

        if schema_type == "object":
            properties = schema.get("properties", {})
            required_fields = set(schema.get("required", []))
            for prop_name, prop_schema in properties.items():
                full_name = f"{prefix}.{prop_name}" if prefix else prop_name
                prop_type = prop_schema.get("type", "string")
                if "$ref" in prop_schema:
                    resolved = self._resolve_ref(prop_schema["$ref"], spec)
                    if resolved and resolved.get("type") == "object":
                        params.extend(self._flatten_schema(
                            resolved, spec, full_name, depth + 1, _visited_refs
                        ))
                        continue
                    prop_type = resolved.get("type", "string") if resolved else "string"

                params.append(Parameter(
                    name=full_name,
                    location=ParameterLocation.BODY,
                    param_type=prop_type,
                    required=prop_name in required_fields,
                    source_module=self.name,
                ))

        elif schema_type == "array":
            items = schema.get("items", {})
            if items:
                item_name = f"{prefix}[]" if prefix else "items[]"
                params.extend(self._flatten_schema(items, spec, item_name, depth + 1, _visited_refs))

        return params

    def _resolve_schema_type(self, schema: dict, spec: dict) -> str:
        """Resolve a parameter's schema type, following $ref if needed."""
        if "$ref" in schema:
            resolved = self._resolve_ref(schema["$ref"], spec)
            if resolved:
                return resolved.get("type", "string")
        return schema.get("type", "string")

    def _extract_auth_schemes(self, spec: dict) -> list[str]:
        """Extract authentication scheme names from OpenAPI spec."""
        components = spec.get("components", spec.get("securityDefinitions", {}))
        if isinstance(components, dict):
            schemes = components.get("securitySchemes", components)
            if isinstance(schemes, dict):
                return list(schemes.keys())
        return []

    async def _probe_graphql(self, base_url: str) -> None:
        """Probe for GraphQL endpoints and run full introspection (all paths concurrently)."""
        import asyncio

        introspection_query = json.dumps({
            "query": """
            {
              __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                  name
                  kind
                  fields {
                    name
                    args {
                      name
                      type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
                      defaultValue
                    }
                    type { kind name ofType { kind name ofType { kind name } } }
                  }
                  inputFields {
                    name
                    type { kind name ofType { kind name ofType { kind name } } }
                  }
                }
              }
            }
            """
        })

        async def _try_path(client: httpx.AsyncClient, path: str) -> None:
            if not self._running:
                return
            url = f"{base_url}{path}"
            try:
                resp = await client.get(url)
                self.requests_made += 1
                if resp.status_code in (200, 400, 405):
                    resp2 = await client.post(
                        url,
                        content=introspection_query,
                        headers={"Content-Type": "application/json"},
                    )
                    self.requests_made += 1
                    if resp2.status_code == 200 and "__schema" in resp2.text:
                        self.logger.info("Found GraphQL endpoint: %s", url)
                        await self._parse_graphql_deep(url, resp2.text)
            except Exception:
                self.errors += 1

        async with httpx.AsyncClient(timeout=10.0) as client:
            await asyncio.gather(*[_try_path(client, p) for p in GRAPHQL_PATHS])

    async def _parse_graphql_deep(self, url: str, content: str) -> None:
        """Deep GraphQL introspection: extract fields as endpoints with their arguments."""
        try:
            data = json.loads(content)
            schema = data.get("data", {}).get("__schema", {})
            types_by_name = {t["name"]: t for t in schema.get("types", [])}

            query_type = (schema.get("queryType") or {}).get("name", "Query")
            mutation_type = (schema.get("mutationType") or {}).get("name", "Mutation")
            subscription_type = (schema.get("subscriptionType") or {}).get("name", "Subscription")

            for root_name, gql_op in [
                (query_type, "query"),
                (mutation_type, "mutation"),
                (subscription_type, "subscription"),
            ]:
                root_type = types_by_name.get(root_name)
                if not root_type or not root_type.get("fields"):
                    continue

                for field in root_type["fields"]:
                    field_name = field.get("name", "")
                    if not field_name or field_name.startswith("__"):
                        continue

                    params: list[Parameter] = []
                    for arg in field.get("args", []):
                        arg_type = self._resolve_gql_type(arg.get("type", {}))
                        is_required = self._is_gql_non_null(arg.get("type", {}))

                        # Expand InputType fields as sub-parameters
                        arg_type_name = self._get_gql_type_name(arg.get("type", {}))
                        input_type = types_by_name.get(arg_type_name, {})
                        if input_type.get("kind") == "INPUT_OBJECT" and input_type.get("inputFields"):
                            for input_field in input_type["inputFields"]:
                                params.append(Parameter(
                                    name=f"{arg['name']}.{input_field['name']}",
                                    location=ParameterLocation.BODY,
                                    param_type=self._resolve_gql_type(input_field.get("type", {})),
                                    required=self._is_gql_non_null(input_field.get("type", {})),
                                    source_module=self.name,
                                ))
                        else:
                            params.append(Parameter(
                                name=arg["name"],
                                location=ParameterLocation.BODY,
                                param_type=arg_type,
                                required=is_required,
                                source_module=self.name,
                            ))

                    ep = Endpoint(
                        url=url,
                        method="POST",
                        parameters=params,
                        source_module=self.name,
                        tags=["graphql", f"gql_{gql_op}", f"field:{field_name}"],
                        requires_auth=False,
                    )
                    await self.engine.register_endpoint(ep)
                    self.endpoints_found += 1

        except Exception:
            self.errors += 1

        schema_obj = APISchema(schema_type="graphql", url=url, raw_content=content[:10000])
        await self.engine.signals.emit(Signal.API_SCHEMA_FOUND, schema=schema_obj)

    def _resolve_gql_type(self, type_obj: dict) -> str:
        """Recursively resolve GraphQL type to string (e.g., '[String]!')."""
        kind = type_obj.get("kind", "")
        if kind == "NON_NULL":
            return f"{self._resolve_gql_type(type_obj.get('ofType', {}))}!"
        elif kind == "LIST":
            return f"[{self._resolve_gql_type(type_obj.get('ofType', {}))}]"
        return type_obj.get("name", "unknown")

    def _is_gql_non_null(self, type_obj: dict) -> bool:
        """Check if a GraphQL type is NON_NULL (required)."""
        return type_obj.get("kind") == "NON_NULL"

    def _get_gql_type_name(self, type_obj: dict) -> str:
        """Get the innermost type name (unwrap NON_NULL/LIST)."""
        kind = type_obj.get("kind", "")
        if kind in ("NON_NULL", "LIST"):
            return self._get_gql_type_name(type_obj.get("ofType", {}))
        return type_obj.get("name", "")

    async def _probe_wsdl(self, base_url: str) -> None:
        """Probe for SOAP/WSDL services (all paths concurrently)."""
        import asyncio

        async def _try_path(client: httpx.AsyncClient, suffix: str) -> None:
            if not self._running:
                return
            url = f"{base_url}{suffix}"
            try:
                resp = await client.get(url)
                self.requests_made += 1
                if resp.status_code == 200 and "<wsdl:" in resp.text.lower():
                    self.logger.info("Found WSDL: %s", url)
                    ep = Endpoint(
                        url=url,
                        method="POST",
                        source_module=self.name,
                        tags=["wsdl"],
                    )
                    await self.engine.register_endpoint(ep)
                    self.endpoints_found += 1
                    schema = APISchema(
                        schema_type="wsdl", url=url, raw_content=resp.text[:10000]
                    )
                    await self.engine.signals.emit(Signal.API_SCHEMA_FOUND, schema=schema)
            except Exception:
                self.errors += 1

        async with httpx.AsyncClient(timeout=10.0) as client:
            await asyncio.gather(*[_try_path(client, s) for s in WSDL_PATHS])
