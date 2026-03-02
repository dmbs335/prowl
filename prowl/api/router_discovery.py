"""Discovery query endpoints: endpoints, input-vectors, tech, secrets, transactions, sitemap, graph."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from prowl.api.deps import get_api_state
from prowl.api.schemas import (
    AuthBoundaryResponse,
    EndpointResponse,
    InputVectorResponse,
    PaginatedResponse,
    ParameterResponse,
    SecretResponse,
    TechFingerprintResponse,
    TransactionDetail,
    TransactionSummary,
)

router = APIRouter()


# ── Converters ────────────────────────────────────────────────────────────────


def _endpoint_to_response(ep: Any) -> EndpointResponse:
    return EndpointResponse(
        url=ep.url,
        method=ep.method,
        parameters=[
            ParameterResponse(
                name=p.name,
                location=str(p.location),
                sample_values=p.sample_values,
                param_type=p.param_type,
                required=p.required,
                source_module=p.source_module,
            )
            for p in ep.parameters
        ],
        status_code=ep.status_code,
        content_type=ep.content_type,
        source_module=ep.source_module,
        depth=ep.depth,
        tags=ep.tags,
        page_type=ep.page_type,
        requires_auth=ep.requires_auth,
        input_vector_count=len(ep.input_vectors),
        param_count=ep.param_count,
        path_template=ep.path_template,
        fingerprint=ep.fingerprint,
    )


def _iv_to_response(iv: Any) -> InputVectorResponse:
    return InputVectorResponse(
        endpoint_url=iv.endpoint_url,
        name=iv.name,
        location=str(iv.location),
        input_type=iv.input_type,
        is_reflected=iv.is_reflected,
        sample_values=iv.sample_values,
        risk_indicators=iv.risk_indicators,
        source_module=iv.source_module,
        fingerprint=iv.fingerprint,
    )


def _tech_to_response(t: Any) -> TechFingerprintResponse:
    return TechFingerprintResponse(
        name=t.name,
        version=t.version,
        category=t.category,
        confidence=t.confidence,
        evidence=t.evidence,
        implied_paths=t.implied_paths,
    )


def _secret_to_response(s: Any) -> SecretResponse:
    return SecretResponse(
        kind=s.kind,
        value=s.value,
        source_url=s.source_url,
        entropy=s.entropy,
        risk_indicators=s.risk_indicators,
    )


def _ab_to_response(ab: Any) -> AuthBoundaryResponse:
    return AuthBoundaryResponse(
        url=ab.url,
        method=ab.method,
        unauth_status=ab.unauth_status,
        auth_status=ab.auth_status,
        boundary_type=ab.boundary_type,
        access_matrix=ab.access_matrix,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get(
    "/endpoints",
    response_model=PaginatedResponse,
    summary="Query discovered endpoints",
    description="Returns endpoints with rich filtering. Supports filtering by tag, page_type, "
    "HTTP method, auth requirement, parameter presence, source module, and URL pattern.",
)
async def list_endpoints(
    limit: int = Query(50, le=500, description="Page size (max 500)"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    tag: str | None = Query(None, description="Filter by tag (e.g. api, admin, debug)"),
    page_type: str | None = Query(None, description="Filter by page type (login, error, api_json, admin, etc.)"),
    method: str | None = Query(None, description="Filter by HTTP method (GET, POST, PUT, etc.)"),
    requires_auth: bool | None = Query(None, description="Filter by auth requirement"),
    has_params: bool | None = Query(None, description="Filter by parameter presence"),
    source_module: str | None = Query(None, description="Filter by source module (s1_spider, s4_js, etc.)"),
    url_pattern: str | None = Query(None, description="Substring match on URL"),
) -> PaginatedResponse:
    api = get_api_state()
    results = api.engine.attack_surface.endpoints

    if tag:
        results = [ep for ep in results if tag in ep.tags]
    if page_type:
        results = [ep for ep in results if ep.page_type == page_type]
    if method:
        results = [ep for ep in results if ep.method.upper() == method.upper()]
    if requires_auth is not None:
        results = [ep for ep in results if ep.requires_auth == requires_auth]
    if has_params is not None:
        results = [ep for ep in results if (ep.param_count > 0) == has_params]
    if source_module:
        results = [ep for ep in results if ep.source_module == source_module]
    if url_pattern:
        lp = url_pattern.lower()
        results = [ep for ep in results if lp in ep.url.lower()]

    total = len(results)
    page = results[offset : offset + limit]

    return PaginatedResponse(
        items=[_endpoint_to_response(ep) for ep in page],
        total=total,
        offset=offset,
        limit=limit,
        has_more=(offset + limit) < total,
    )


@router.get(
    "/endpoints/{fingerprint}",
    response_model=EndpointResponse,
    summary="Get endpoint by fingerprint",
    description="Returns a single endpoint by its fingerprint hash.",
)
async def get_endpoint(fingerprint: str) -> EndpointResponse:
    api = get_api_state()
    for ep in api.engine.attack_surface.endpoints:
        if ep.fingerprint == fingerprint:
            return _endpoint_to_response(ep)
    raise HTTPException(404, f"Endpoint '{fingerprint}' not found")


# ── Input Vectors ─────────────────────────────────────────────────────────────


@router.get(
    "/input-vectors",
    response_model=PaginatedResponse,
    summary="Query input vectors",
    description="Returns input vectors (attack surface parameters) with filtering by "
    "risk indicator, location, reflection status, and endpoint URL.",
)
async def list_input_vectors(
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    risk_indicator: str | None = Query(
        None, description="Filter by risk tag (ssrf_candidate, sqli_candidate, cmdi_candidate, etc.)"
    ),
    location: str | None = Query(None, description="Filter by location (query, body, header, cookie, path)"),
    is_reflected: bool | None = Query(None, description="Filter by reflection status (XSS candidates)"),
    endpoint_url: str | None = Query(None, description="Filter by endpoint URL substring"),
    source_module: str | None = Query(None, description="Filter by source module"),
) -> PaginatedResponse:
    api = get_api_state()
    results = api.engine.attack_surface.input_vectors

    if risk_indicator:
        results = [iv for iv in results if risk_indicator in iv.risk_indicators]
    if location:
        results = [iv for iv in results if str(iv.location) == location]
    if is_reflected is not None:
        results = [iv for iv in results if iv.is_reflected == is_reflected]
    if endpoint_url:
        lp = endpoint_url.lower()
        results = [iv for iv in results if lp in iv.endpoint_url.lower()]
    if source_module:
        results = [iv for iv in results if iv.source_module == source_module]

    total = len(results)
    page = results[offset : offset + limit]

    return PaginatedResponse(
        items=[_iv_to_response(iv) for iv in page],
        total=total,
        offset=offset,
        limit=limit,
        has_more=(offset + limit) < total,
    )


# ── Tech Stack ────────────────────────────────────────────────────────────────


@router.get(
    "/tech-stack",
    response_model=list[TechFingerprintResponse],
    summary="Get detected technologies",
    description="Returns all detected technologies with confidence scores and evidence.",
)
async def list_tech_stack(
    category: str | None = Query(None, description="Filter by category (framework, server, cms, frontend, waf)"),
    min_confidence: float = Query(0.0, description="Minimum confidence threshold"),
) -> list[TechFingerprintResponse]:
    api = get_api_state()
    results = api.engine.attack_surface.tech_stack

    if category:
        results = [t for t in results if t.category == category]
    if min_confidence > 0:
        results = [t for t in results if t.confidence >= min_confidence]

    return [_tech_to_response(t) for t in results]


# ── Secrets ───────────────────────────────────────────────────────────────────


@router.get(
    "/secrets",
    response_model=list[SecretResponse],
    summary="Get discovered secrets",
    description="Returns all discovered secrets (API keys, tokens, passwords).",
)
async def list_secrets(
    kind: str | None = Query(None, description="Filter by secret kind (api_key, token, etc.)"),
    limit: int = Query(100, le=500),
) -> list[SecretResponse]:
    api = get_api_state()
    results = api.engine.attack_surface.secrets

    if kind:
        results = [s for s in results if s.kind == kind]

    return [_secret_to_response(s) for s in results[:limit]]


# ── Auth Boundaries ───────────────────────────────────────────────────────────


@router.get(
    "/auth-boundaries",
    response_model=list[AuthBoundaryResponse],
    summary="Get auth boundaries",
    description="Returns authentication boundary transitions.",
)
async def list_auth_boundaries(
    boundary_type: str | None = Query(None, description="Filter by type (redirect_to_login, 403_forbidden, etc.)"),
    limit: int = Query(100, le=500),
) -> list[AuthBoundaryResponse]:
    api = get_api_state()
    results = api.engine.attack_surface.auth_boundaries

    if boundary_type:
        results = [ab for ab in results if ab.boundary_type == boundary_type]

    return [_ab_to_response(ab) for ab in results[:limit]]


# ── Transactions ──────────────────────────────────────────────────────────────


@router.get(
    "/transactions",
    response_model=PaginatedResponse,
    summary="Query HTTP transactions",
    description="Query stored HTTP transactions (request/response pairs) without bodies. "
    "Use GET /transactions/{id} for full detail and /transactions/{id}/response-body for body content.",
)
async def list_transactions(
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    url_pattern: str | None = Query(None, description="URL LIKE pattern (use % as wildcard)"),
    source_module: str | None = Query(None, description="Filter by source module"),
    page_type: str | None = Query(None, description="Filter by page type"),
    content_type: str | None = Query(None, description="Filter by response content type (substring)"),
    status_min: int | None = Query(None, description="Minimum response status code"),
    status_max: int | None = Query(None, description="Maximum response status code"),
) -> PaginatedResponse:
    api = get_api_state()
    store = api.engine.transaction_store

    status_range = None
    if status_min is not None or status_max is not None:
        status_range = (status_min or 0, status_max or 999)

    txns = await store.query(
        url_pattern=url_pattern,
        source_module=source_module,
        page_type=page_type,
        content_type_contains=content_type,
        status_range=status_range,
        limit=offset + limit,
    )

    # Manual offset since SQLite query doesn't support it directly
    total_estimate = len(txns)
    page = txns[offset:]

    items = [
        TransactionSummary(
            id=txn.id,
            timestamp=txn.timestamp,
            request_method=txn.request_method,
            request_url=txn.request_url,
            response_status=txn.response_status,
            response_content_type=txn.response_content_type,
            source_module=txn.source_module,
            depth=txn.depth,
            page_type=txn.page_type,
        )
        for txn in page
    ]

    return PaginatedResponse(
        items=items,
        total=total_estimate,
        offset=offset,
        limit=limit,
        has_more=False,
    )


@router.get(
    "/transactions/{txn_id}",
    response_model=TransactionDetail,
    summary="Get transaction detail",
    description="Returns full transaction detail including headers and body sizes.",
)
async def get_transaction(txn_id: str) -> TransactionDetail:
    api = get_api_state()
    store = api.engine.transaction_store

    txns = await store.query(limit=1)
    # Query by URL pattern isn't ideal -- get all and filter by ID
    # Use the full transaction iterator for single lookup
    async for txn in store.get_all_transactions():
        if txn.id == txn_id:
            return TransactionDetail(
                id=txn.id,
                timestamp=txn.timestamp,
                request_method=txn.request_method,
                request_url=txn.request_url,
                request_headers=txn.request_headers,
                request_body_size=len(txn.request_body) if txn.request_body else 0,
                request_content_type=txn.request_content_type,
                response_status=txn.response_status,
                response_headers=txn.response_headers,
                response_body_size=len(txn.response_body) if txn.response_body else 0,
                response_content_type=txn.response_content_type,
                response_url_final=txn.response_url_final,
                source_module=txn.source_module,
                depth=txn.depth,
                page_type=txn.page_type,
                content_hash=txn.content_hash,
            )
    raise HTTPException(404, f"Transaction '{txn_id}' not found")


@router.get(
    "/transactions/{txn_id}/response-body",
    summary="Get transaction response body",
    description="Returns the raw response body bytes for a specific transaction.",
)
async def get_transaction_body(txn_id: str) -> Response:
    api = get_api_state()
    body = await api.engine.transaction_store.get_response_body(txn_id)
    if body is None:
        raise HTTPException(404, f"Transaction '{txn_id}' not found")
    return Response(content=body, media_type="application/octet-stream")


# ── Sitemap / Graph ───────────────────────────────────────────────────────────


@router.get(
    "/sitemap",
    summary="Get hierarchical sitemap",
    description="Returns a tree structure of discovered endpoints organized by host and path.",
)
async def get_sitemap() -> dict:
    return get_api_state().state.build_sitemap_tree()


@router.get(
    "/graph",
    summary="Get site structure graph",
    description="Returns a node/edge graph of discovered paths for visualization.",
)
async def get_graph(
    limit: int = Query(500, description="Maximum number of endpoints to include"),
) -> dict:
    return get_api_state().state.build_graph(limit)
