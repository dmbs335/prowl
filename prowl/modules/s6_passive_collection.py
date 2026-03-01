"""§6 Passive & Historical Collection module.

Collects historical URLs from Wayback Machine, CommonCrawl, and AlienVault OTX.

Two-pass structural dedup to avoid junk flooding:
  Pass 1 — Junk filter: length, percent-encoding density, static-asset extension,
           control chars.  Query strings are stripped (passive cares about path
           structure, not parameters).
  Pass 2 — Path-tree collapsing: build a tree of path segments; any node whose
           children exceed COLLAPSE_THRESHOLD is treated as parametric and
           collapsed to one representative URL.  This handles /users/alice,
           /users/bob, /blog/post-1, /blog/post-2, … without hard-coded regex.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import httpx

from prowl.core.signals import Signal
from prowl.models.target import Endpoint, InputVector, Parameter, ParameterLocation
from prowl.modules.base import BaseModule

logger = logging.getLogger(__name__)

# ── Pass-1 constants ──────────────────────────────────────────────────
_MAX_URL_LEN = 250
_MAX_PERCENT_RATIO = 0.15
_SKIP_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".less", ".scss",
    ".mp4", ".mp3", ".avi", ".mov", ".flv", ".wmv",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".map", ".wasm",
})

# ── Pass-2 constants ──────────────────────────────────────────────────
# If a directory has more unique children than this, collapse to one.
COLLAPSE_THRESHOLD = 5
# Quick regex for obviously-numeric / hex / uuid segments (normalised
# *before* tree insertion so /user/1 and /user/2 always collapse).
_ID_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I,
)
_HEX_RE = re.compile(r"^[0-9a-f]{8,}$", re.I)


# ======================================================================
# Path-tree implementation
# ======================================================================

class _PathNode:
    """Single node in the path tree.  Leaf nodes store a representative URL."""

    __slots__ = ("children", "url")

    def __init__(self) -> None:
        self.children: dict[str, _PathNode] = {}
        self.url: str | None = None          # set only on leaf nodes


def _build_path_tree(entries: list[tuple[str, list[str]]]) -> dict[str, _PathNode]:
    """Build {host → root _PathNode} from (url, normalised_segments) pairs."""
    roots: dict[str, _PathNode] = {}
    for url, segments in entries:
        host = urlparse(url).hostname or ""
        node = roots.setdefault(host, _PathNode())
        for seg in segments:
            node = node.children.setdefault(seg, _PathNode())
        if node.url is None:
            node.url = url
    return roots


def _collect_unique(node: _PathNode, results: list[str]) -> None:
    """Walk tree; when a node has > COLLAPSE_THRESHOLD children, keep only one
    representative from the entire subtree (the rest are parametric duplicates)."""
    if node.url is not None and not node.children:
        results.append(node.url)
        return

    if len(node.children) > COLLAPSE_THRESHOLD:
        # Parametric node → pick first representative from subtree
        rep = _first_leaf(node)
        if rep:
            results.append(rep)
    else:
        for child in node.children.values():
            _collect_unique(child, results)


def _first_leaf(node: _PathNode) -> str | None:
    """DFS to find the first representative URL in a subtree."""
    if node.url is not None:
        return node.url
    for child in node.children.values():
        found = _first_leaf(child)
        if found:
            return found
    return None


# ======================================================================
# Module
# ======================================================================

class PassiveCollectionModule(BaseModule):
    """§6: Collect URLs from passive/historical sources without touching the target."""

    name = "s6_passive"
    description = "Passive & Historical Collection (Wayback, CommonCrawl, OTX)"

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        target = self.engine.config.target_url
        parsed = urlparse(target)
        domain = parsed.hostname or ""

        await self.engine.signals.emit(
            Signal.MODULE_STARTED, module=self.name,
        )

        # Accumulate all raw URLs across sources, then dedup once
        # Each entry: (url, tag, meta) where meta is optional dict
        # with keys like 'status', 'mime', 'timestamp'
        self._raw_urls: list[tuple[str, str, dict[str, str]]] = []

        try:
            if self.engine.config.use_wayback:
                await self._fetch_wayback(domain)
            if self.engine.config.use_commoncrawl:
                await self._fetch_commoncrawl(domain)
            await self._fetch_otx(domain)

            # ── Two-pass dedup & register ─────────────────────────────
            unique = self._structural_dedup(self._raw_urls)
            param_count = 0
            for url, tag, params, source_meta in unique:
                # Build Parameter list from accumulated query params
                ep_params: list[Parameter] = []
                for pname, sample_vals in params.items():
                    ep_params.append(Parameter(
                        name=pname,
                        location=ParameterLocation.QUERY,
                        param_type=self._infer_type(sample_vals),
                        sample_values=sorted(sample_vals)[:3],
                        source_module=self.name,
                    ))

                # Attach passive source metadata (status, mime)
                passive_status: int | None = None
                if source_meta.get("status"):
                    try:
                        passive_status = int(source_meta["status"])
                    except ValueError:
                        pass

                ep = Endpoint(
                    url=url, source_module=self.name,
                    tags=[tag], parameters=ep_params,
                    status_code=passive_status,
                    content_type=source_meta.get("mime", ""),
                )
                await self.engine.register_endpoint(ep)
                self.endpoints_found += 1

                # Register each param as an InputVector for attack surface
                for p in ep_params:
                    iv = InputVector(
                        endpoint_url=url,
                        name=p.name,
                        location=ParameterLocation.QUERY,
                        input_type=p.param_type,
                        sample_values=p.sample_values,
                        source_module=self.name,
                    )
                    self.engine.attack_surface.register_input_vector(iv)
                    param_count += 1

            self.logger.info(
                "Passive total: %d raw → %d unique endpoints, %d params extracted",
                len(self._raw_urls), len(unique), param_count,
            )
        except Exception as e:
            self.errors += 1
            logger.error("Passive collection error: %s", e)
        finally:
            self._raw_urls = []
            self._running = False
            await self.engine.signals.emit(
                Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats(),
            )

    # ------------------------------------------------------------------
    # Pass 1 — junk filter
    # ------------------------------------------------------------------

    @staticmethod
    def _is_useful_url(raw_url: str) -> bool:
        if len(raw_url) > _MAX_URL_LEN:
            return False
        pct_count = raw_url.count("%")
        if pct_count > 3 and pct_count / len(raw_url) > _MAX_PERCENT_RATIO:
            return False
        parsed = urlparse(raw_url)
        path_lower = parsed.path.lower().rstrip("/")
        for ext in _SKIP_EXTENSIONS:
            if path_lower.endswith(ext):
                return False
        decoded = unquote(parsed.path)
        if not decoded or decoded == "/":
            return True
        if re.search(r"[\x00-\x1f]", decoded):
            return False
        if "  " in decoded:
            return False
        return True

    # ------------------------------------------------------------------
    # Pass 2 — structural dedup
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_type(sample_vals: set[str]) -> str:
        """Infer parameter type from sample values."""
        if not sample_vals:
            return "string"
        if all(v.isdigit() for v in sample_vals if v):
            return "integer"
        if all(
            re.match(r"^(true|false|0|1)$", v, re.I)
            for v in sample_vals if v
        ):
            return "boolean"
        return "string"

    @staticmethod
    def _normalise_segment(seg: str) -> str:
        """Normalise obviously-dynamic segments before tree insertion."""
        if _ID_RE.match(seg):
            return "{id}"
        if _UUID_RE.match(seg):
            return "{uuid}"
        if _HEX_RE.match(seg):
            return "{hex}"
        return seg

    def _structural_dedup(
        self, raw: list[tuple[str, str, dict[str, str]]],
    ) -> list[tuple[str, str, dict[str, set[str]], dict[str, str]]]:
        """Filter → strip query → normalise → path-tree collapse.

        Returns list of (representative_url, tag, param_map, source_meta) where
        param_map is {param_name → set of sample values} and source_meta is
        {status, mime} from the passive source (first non-empty wins).
        """

        # Step 1: filter + normalise + accumulate params per path template
        seen_paths: dict[str, tuple[str, str]] = {}  # norm_key → (url, tag)
        # Accumulate query params across all URLs sharing a norm_key
        params_by_key: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: defaultdict(set),
        )
        # Keep first non-empty source metadata per norm_key
        meta_by_key: dict[str, dict[str, str]] = {}
        entries: list[tuple[str, list[str]]] = []

        for url, tag, meta in raw:
            if not self._is_useful_url(url):
                continue
            if not self.engine.scope.is_in_scope(url):
                continue

            parsed = urlparse(url)
            path = parsed.path.rstrip("/") or "/"
            segments = [self._normalise_segment(s) for s in path.split("/") if s]

            host = parsed.hostname or ""
            norm_key = f"{host}/{'/'.join(segments)}"

            # Extract query params from every URL (even if path is duplicate)
            if parsed.query:
                qs = parse_qs(parsed.query, keep_blank_values=True)
                for pname, pvals in qs.items():
                    for v in pvals:
                        params_by_key[norm_key][pname].add(v)

            # Merge source metadata (first non-empty status/mime wins)
            if norm_key not in meta_by_key:
                meta_by_key[norm_key] = {}
            stored = meta_by_key[norm_key]
            for k in ("status", "mime"):
                if k not in stored and meta.get(k):
                    stored[k] = meta[k]

            if norm_key in seen_paths:
                continue
            seen_paths[norm_key] = (url, tag)
            entries.append((url, segments))

        # Step 2: build path tree and collapse
        roots = _build_path_tree(entries)
        unique_urls: list[str] = []
        for root in roots.values():
            _collect_unique(root, unique_urls)

        # Map back to (url, tag, params, meta)
        url_to_info: dict[str, tuple[str, dict[str, set[str]], dict[str, str]]] = {}
        for norm_key, (u, t) in seen_paths.items():
            url_to_info[u] = (
                t,
                dict(params_by_key.get(norm_key, {})),
                meta_by_key.get(norm_key, {}),
            )

        results: list[tuple[str, str, dict[str, set[str]], dict[str, str]]] = []
        for u in unique_urls:
            tag, params, meta = url_to_info.get(u, ("passive", {}, {}))
            results.append((u, tag, params, meta))
        return results

    # ------------------------------------------------------------------
    # Data sources
    # ------------------------------------------------------------------

    async def _fetch_wayback(self, domain: str) -> None:
        # Request original URL + statuscode + mimetype from CDX API
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=text"
            f"&fl=original,statuscode,mimetype"
            f"&collapse=urlkey&limit=2000"
        )
        self.logger.info("Fetching Wayback URLs for %s", domain)
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    count = 0
                    for line in resp.text.strip().split("\n"):
                        line = line.strip()
                        if not line:
                            continue
                        # CDX returns space-separated: original statuscode mimetype
                        parts = line.split(" ", 2)
                        raw_url = parts[0]
                        meta: dict[str, str] = {}
                        if len(parts) >= 2 and parts[1] != "-":
                            meta["status"] = parts[1]
                        if len(parts) >= 3 and parts[2] != "-":
                            meta["mime"] = parts[2]
                        self._raw_urls.append((raw_url, "wayback", meta))
                        count += 1
                    self.requests_made += 1
                    self.logger.info("Wayback: fetched %d raw URLs", count)
            except Exception as e:
                self.errors += 1
                self.logger.warning("Wayback fetch failed: %s", e)

    async def _fetch_commoncrawl(self, domain: str) -> None:
        import json as _json

        index_url = (
            f"https://index.commoncrawl.org/CC-MAIN-2024-51-index"
            f"?url=*.{domain}&output=json&limit=2000"
        )
        self.logger.info("Fetching CommonCrawl URLs for %s", domain)
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.get(index_url)
                if resp.status_code == 200:
                    count = 0
                    for line in resp.text.strip().split("\n"):
                        if not line.strip():
                            continue
                        try:
                            data = _json.loads(line)
                            raw_url = data.get("url", "")
                            if raw_url:
                                meta: dict[str, str] = {}
                                if data.get("status"):
                                    meta["status"] = str(data["status"])
                                if data.get("mime"):
                                    meta["mime"] = data["mime"]
                                self._raw_urls.append((raw_url, "commoncrawl", meta))
                                count += 1
                        except Exception:
                            continue
                    self.requests_made += 1
                    self.logger.info("CommonCrawl: fetched %d raw URLs", count)
            except Exception as e:
                self.errors += 1
                self.logger.warning("CommonCrawl fetch failed: %s", e)

    async def _fetch_otx(self, domain: str) -> None:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
        self.logger.info("Fetching OTX URLs for %s", domain)
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    urls = data.get("url_list", [])
                    for entry in urls:
                        raw_url = entry.get("url", "")
                        if raw_url:
                            meta: dict[str, str] = {}
                            if entry.get("httpcode"):
                                meta["status"] = str(entry["httpcode"])
                            self._raw_urls.append((raw_url, "otx", meta))
                    self.requests_made += 1
                    self.logger.info("OTX: fetched %d raw URLs", len(urls))
            except Exception as e:
                self.errors += 1
                self.logger.warning("OTX fetch failed: %s", e)
