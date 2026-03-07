"""Cluster HTTP response patterns to identify soft 404s, WAF blocks, error pages, etc."""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from prowl.models.request import CrawlRequest, CrawlResponse, HttpMethod

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# WAF signature database
# ---------------------------------------------------------------------------

_WAF_HEADER_SIGNATURES: list[tuple[str, str, re.Pattern[str]]] = [
    # (waf_name, header_key_lower, compiled_pattern)
    ("cloudflare", "cf-ray", re.compile(r".")),
    ("cloudflare", "server", re.compile(r"cloudflare", re.IGNORECASE)),
    ("aws_waf", "x-amzn-requestid", re.compile(r".")),
    ("akamai", "x-akamai-transformed", re.compile(r".")),
    ("sucuri", "x-sucuri-id", re.compile(r".")),
    ("imperva", "x-cdn", re.compile(r"imperva|incapsula", re.IGNORECASE)),
]

_WAF_BODY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"Attention\s+Required[^<]*Cloudflare", re.IGNORECASE | re.DOTALL),
    re.compile(r"Access\s+Denied[^<]*AWS", re.IGNORECASE | re.DOTALL),
    re.compile(r"Request\s+blocked", re.IGNORECASE),
    re.compile(r"ModSecurity", re.IGNORECASE),
    re.compile(r"Not\s+Acceptable!?\s*</", re.IGNORECASE),
    re.compile(r"Web\s+Application\s+Firewall", re.IGNORECASE),
    re.compile(r"This\s+request\s+has\s+been\s+blocked", re.IGNORECASE),
    re.compile(r"<title>\s*403\s+Forbidden\s*</title>", re.IGNORECASE),
    re.compile(r"Access\s+Denied.*?Incapsula|Powered\s+By\s+Incapsula", re.IGNORECASE | re.DOTALL),
    re.compile(r"AkamaiGHost|Request\s+ID.*?akamai", re.IGNORECASE | re.DOTALL),
    re.compile(r"Fastly\s+error:\s+unknown\s+domain|Varnish\s+cache\s+server", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Error / stack-trace patterns
# ---------------------------------------------------------------------------

_ERROR_BODY_PATTERNS: list[re.Pattern[str]] = [
    # Python
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"(?:File|Module)\s+\"[^\"]+\",\s+line\s+\d+"),
    # Java / JVM
    re.compile(r"\bat\s+[\w$.]+\([\w]+\.java:\d+\)"),
    re.compile(r"\bat\s+(?:com|org|net|io)\.\w+"),
    re.compile(r"java\.lang\.\w+Exception"),
    # .NET
    re.compile(r"System\.\w+Exception"),
    re.compile(r"Stack\s*Trace:", re.IGNORECASE),
    re.compile(r"Server\s+Error\s+in\s+'/", re.IGNORECASE),
    # PHP
    re.compile(r"(?:Fatal|Parse)\s+error:.*on\s+line\s+\d+", re.IGNORECASE),
    re.compile(r"<b>(?:Warning|Notice)</b>:.*in\s+<b>/", re.IGNORECASE),
    # Framework error pages
    re.compile(r"Whitelabel\s+Error\s+Page", re.IGNORECASE),
    re.compile(r"Django\s+Debug", re.IGNORECASE),
    re.compile(r"<title>Error</title>", re.IGNORECASE),
    re.compile(r"Internal\s+Server\s+Error", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Auth / login patterns
# ---------------------------------------------------------------------------

_AUTH_REDIRECT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"login", re.IGNORECASE),
    re.compile(r"signin", re.IGNORECASE),
    re.compile(r"sign-in", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"sso", re.IGNORECASE),
    re.compile(r"cas/", re.IGNORECASE),
    re.compile(r"oauth", re.IGNORECASE),
]

_AUTH_BODY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"<form[^>]*>.*?(?:type=[\"']password[\"']|name=[\"']password[\"'])",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(r"Please\s+(?:log\s*in|sign\s*in)", re.IGNORECASE),
    re.compile(r"Authentication\s+required", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Baseline fingerprint
# ---------------------------------------------------------------------------

_CONTENT_LENGTH_TOLERANCE = 0.10  # 10 %


@dataclass
class _BaselineFingerprint:
    """Stores the response fingerprint of a baseline (e.g. a known-404)."""

    status_code: int = 0
    content_length: int = 0
    content_hash: str = ""
    body_sample: str = ""  # first 512 chars for debug logging


@dataclass
class _BaselineState:
    """Aggregated baseline state learned during ``set_baseline``."""

    target_status: int = 0
    not_found_fingerprints: list[_BaselineFingerprint] = field(default_factory=list)
    has_custom_404: bool = False


# ---------------------------------------------------------------------------
# ResponseClassifier
# ---------------------------------------------------------------------------

_NUM_BASELINE_PROBES = 3
_EMPTY_BODY_THRESHOLD = 64  # bytes


class ResponseClassifier:
    """Classifies HTTP responses by pattern to filter false positives and identify page types.

    Supports per-domain baselines: each domain (netloc) gets its own
    soft-404 fingerprints, learned on first use via ``set_baseline``.
    """

    def __init__(self) -> None:
        self._baseline: _BaselineState = _BaselineState()
        self._baseline_ready: bool = False
        self._seen_hashes: set[str] = set()
        # Per-domain baselines: netloc -> _BaselineState
        self._domain_baselines: dict[str, _BaselineState] = {}
        self._domain_baseline_pending: set[str] = set()
        self._backend: Any = None

    # ------------------------------------------------------------------
    # Baseline learning
    # ------------------------------------------------------------------

    async def set_baseline(self, target_url: str, backend: Any) -> None:
        """Learn baseline response patterns by probing known-good and known-bad paths.

        1. Request *target_url* (known-good page) and record its status.
        2. Request several random-UUID paths (known-bad, should be 404).
        3. Store content hashes, lengths, and status codes of 404 patterns.
        4. Detect custom 404 pages (200 status but same content for non-existent paths).
        """
        self._backend = backend

        # --- known-good -------------------------------------------------
        good_req = CrawlRequest(
            url=target_url,
            method=HttpMethod.GET,
            source_module="response_classifier",
        )
        try:
            good_resp: CrawlResponse = await backend.execute(good_req)
            self._baseline.target_status = good_resp.status_code
            logger.debug(
                "Baseline good page %s -> %d (%d bytes)",
                target_url,
                good_resp.status_code,
                len(good_resp.body),
            )
        except Exception:
            logger.warning(
                "Failed to fetch baseline good page %s; classifier will rely on heuristics",
                target_url,
                exc_info=True,
            )

        baseline = await self._learn_domain_baseline(target_url, backend)
        self._baseline = baseline
        self._baseline_ready = True

        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc
        self._domain_baselines[domain] = baseline

        logger.info(
            "Baseline learning complete: custom_404=%s, %d probe fingerprints stored",
            self._baseline.has_custom_404,
            len(baseline.not_found_fingerprints),
        )

    async def _learn_domain_baseline(self, base_url: str, backend: Any) -> _BaselineState:
        """Learn 404 baseline for a specific domain by probing random UUID paths."""
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        domain_root = f"{parsed.scheme}://{parsed.netloc}/"

        state = _BaselineState()
        probe_fingerprints: list[_BaselineFingerprint] = []

        for _ in range(_NUM_BASELINE_PROBES):
            random_path = uuid.uuid4().hex
            probe_url = urljoin(domain_root, random_path)
            probe_req = CrawlRequest(
                url=probe_url,
                method=HttpMethod.GET,
                source_module="response_classifier",
            )
            try:
                probe_resp: CrawlResponse = await backend.execute(probe_req)
                fp = _BaselineFingerprint(
                    status_code=probe_resp.status_code,
                    content_length=len(probe_resp.body),
                    content_hash=probe_resp.content_hash,
                    body_sample=probe_resp.body[:512].decode("utf-8", errors="replace"),
                )
                probe_fingerprints.append(fp)
                logger.debug(
                    "Baseline probe %s -> %d (%d bytes, hash=%s)",
                    probe_url,
                    fp.status_code,
                    fp.content_length,
                    fp.content_hash[:12],
                )
            except Exception:
                logger.warning(
                    "Baseline probe %s failed; skipping",
                    probe_url,
                    exc_info=True,
                )

        state.not_found_fingerprints = probe_fingerprints

        if len(probe_fingerprints) >= 2:
            all_200 = all(fp.status_code == 200 for fp in probe_fingerprints)
            hashes = {fp.content_hash for fp in probe_fingerprints}
            lengths = [fp.content_length for fp in probe_fingerprints]
            avg_len = sum(lengths) / len(lengths) if lengths else 0
            lengths_similar = avg_len > 0 and all(
                abs(ln - avg_len) / avg_len <= _CONTENT_LENGTH_TOLERANCE for ln in lengths
            )

            if all_200 and (len(hashes) == 1 and lengths_similar):
                state.has_custom_404 = True
                logger.info(
                    "Custom 404 detected for %s: status=200, avg_length=%d",
                    parsed.netloc,
                    int(avg_len),
                )

        return state

    async def ensure_domain_baseline(self, url: str) -> None:
        """Learn baseline for the domain of *url* if not already known."""
        if self._backend is None:
            return
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        if not domain or domain in self._domain_baselines or domain in self._domain_baseline_pending:
            return
        self._domain_baseline_pending.add(domain)
        try:
            baseline = await self._learn_domain_baseline(url, self._backend)
            self._domain_baselines[domain] = baseline
            logger.info(
                "Learned baseline for %s: custom_404=%s, %d fingerprints",
                domain, baseline.has_custom_404, len(baseline.not_found_fingerprints),
            )
        except Exception:
            logger.warning("Failed to learn baseline for %s", domain, exc_info=True)
        finally:
            self._domain_baseline_pending.discard(domain)

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def classify(self, response: CrawlResponse) -> str:
        """Classify a response into a page-type category.

        Uses the per-domain baseline matching the response URL when available,
        falling back to the primary baseline.

        Returns one of:
            ``"real_content"`` -- genuine, unique page content
            ``"custom_404"``  -- looks like 200 but matches the 404 baseline pattern
            ``"waf_block"``   -- WAF / IDS block page
            ``"error"``       -- server error page (5xx, stack traces)
            ``"redirect"``    -- 3xx redirect (to login, homepage, etc.)
            ``"auth_required"`` -- 401/403 or redirect to a login page
            ``"empty"``       -- no meaningful content
        """
        status = response.status_code
        body_text = self._decode_body(response.body)
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        # --- empty -------------------------------------------------------
        if len(response.body) < _EMPTY_BODY_THRESHOLD and status not in (301, 302, 303, 307, 308):
            return "empty"

        # --- redirect ----------------------------------------------------
        if 300 <= status <= 399:
            location = headers_lower.get("location", "")
            if self._matches_auth_redirect(location):
                return "auth_required"
            return "redirect"

        # --- auth required -----------------------------------------------
        if status in (401, 403):
            # 403 can also be a WAF block; check WAF signatures first
            if self._is_waf_block(status, body_text, headers_lower):
                return "waf_block"
            return "auth_required"

        if self._matches_auth_body(body_text):
            return "auth_required"

        # --- WAF block ---------------------------------------------------
        if self._is_waf_block(status, body_text, headers_lower):
            return "waf_block"

        # --- server error ------------------------------------------------
        if status >= 500:
            return "error"
        if self._matches_error_body(body_text):
            return "error"

        # --- custom 404 (per-domain baseline) ----------------------------
        baseline = self._get_baseline_for_response(response)
        if baseline and self._matches_custom_404_with_baseline(response, baseline):
            return "custom_404"

        # --- explicit 404 treated the same as custom 404 -----------------
        if status == 404:
            return "custom_404"

        # --- default: real content ---------------------------------------
        return "real_content"

    def _get_baseline_for_response(self, response: CrawlResponse) -> _BaselineState | None:
        """Return the baseline for the response's domain, falling back to primary."""
        from urllib.parse import urlparse
        url = response.url_final or (response.request.url if response.request else "")
        domain = urlparse(url).netloc
        if domain and domain in self._domain_baselines:
            return self._domain_baselines[domain]
        if self._baseline_ready:
            return self._baseline
        return None

    # ------------------------------------------------------------------
    # Content uniqueness
    # ------------------------------------------------------------------

    def is_unique_content(self, response: CrawlResponse) -> bool:
        """Check if response content is meaningfully different from seen patterns.

        Returns ``True`` if the body hash has not been seen before (and records it).
        """
        h = response.content_hash
        if h in self._seen_hashes:
            return False
        self._seen_hashes.add(h)
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_body(body: bytes, max_chars: int = 65_536) -> str:
        """Best-effort decode of the response body for pattern matching."""
        try:
            return body[:max_chars].decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover
            return ""

    # --- WAF ---

    @staticmethod
    def _is_waf_block(status: int, body_text: str, headers_lower: dict[str, str]) -> bool:
        """Return ``True`` if the response looks like a WAF block page."""
        # Header-based signatures
        for _waf_name, hdr_key, pattern in _WAF_HEADER_SIGNATURES:
            value = headers_lower.get(hdr_key, "")
            if value and pattern.search(value):
                # Header presence alone isn't proof; need a blocking status too
                if status in (403, 406, 429, 503):
                    return True

        # Body-based signatures
        if status in (403, 406, 429, 503):
            for pattern in _WAF_BODY_PATTERNS:
                if pattern.search(body_text):
                    return True

        # Generic heuristic: 403 with a substantial HTML body (WAFs tend to inject
        # branded block pages; a bare 403 from the origin is usually tiny).
        if status == 403 and len(body_text) > 1000 and "<html" in body_text.lower():
            return True

        return False

    # --- Auth ---

    @staticmethod
    def _matches_auth_redirect(location: str) -> bool:
        """Return ``True`` if the redirect Location header points to a login page."""
        if not location:
            return False
        for pattern in _AUTH_REDIRECT_PATTERNS:
            if pattern.search(location):
                return True
        return False

    @staticmethod
    def _matches_auth_body(body_text: str) -> bool:
        """Return ``True`` if the response body contains login-form indicators."""
        for pattern in _AUTH_BODY_PATTERNS:
            if pattern.search(body_text):
                return True
        return False

    # --- Error ---

    @staticmethod
    def _matches_error_body(body_text: str) -> bool:
        """Return ``True`` if the body contains stack-trace or framework-error patterns."""
        for pattern in _ERROR_BODY_PATTERNS:
            if pattern.search(body_text):
                return True
        return False

    # --- Custom 404 ---

    def _matches_custom_404(self, response: CrawlResponse) -> bool:
        """Return ``True`` if *response* looks like a custom 404 based on primary baseline."""
        return self._matches_custom_404_with_baseline(response, self._baseline)

    @staticmethod
    def _matches_custom_404_with_baseline(
        response: CrawlResponse, baseline: _BaselineState
    ) -> bool:
        """Return ``True`` if *response* matches a custom 404 in *baseline*."""
        if not baseline.not_found_fingerprints:
            return False

        # Exact content hash match with any baseline probe
        resp_hash = response.content_hash
        for fp in baseline.not_found_fingerprints:
            if resp_hash == fp.content_hash:
                return True

        # Fuzzy match: same status code + similar content length
        resp_len = len(response.body)
        for fp in baseline.not_found_fingerprints:
            if response.status_code != fp.status_code:
                continue
            if fp.content_length == 0:
                continue
            ratio = abs(resp_len - fp.content_length) / fp.content_length
            if ratio <= _CONTENT_LENGTH_TOLERANCE:
                return True

        return False
