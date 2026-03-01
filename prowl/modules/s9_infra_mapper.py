"""Infrastructure Mapper — passive analysis of collected HTTP traffic to identify
CDN, WAF, reverse proxy, load balancer, and server components.

No additional requests are made.  All analysis is performed on data already
stored in the TransactionStore from prior crawl phases.
"""

from __future__ import annotations

import asyncio
import re
import socket
import logging
from collections import Counter
from typing import Any
from urllib.parse import urlparse

from prowl.core.infra_signatures import (
    CATEGORY_LAYER_ORDER,
    CNAME_PATTERNS,
    COOKIE_SIGNATURES,
    ERROR_PAGE_SIGNATURES,
    HEADER_SIGNATURES,
    InfraDetection,
)
from prowl.core.signals import Signal
from prowl.models.target import TechFingerprint
from prowl.modules.base import BaseModule

logger = logging.getLogger(__name__)


class InfraMapperModule(BaseModule):
    """Passive infrastructure topology mapper.

    Analyses response headers, cookies, and error pages from the
    TransactionStore to identify the network infrastructure stack
    between the client and the origin server.
    """

    name = "s9_infra"
    description = "Infrastructure topology mapper — CDN, WAF, proxy, LB detection"

    def __init__(self, engine: Any) -> None:
        super().__init__(engine)
        # component_key → InfraDetection
        self._detections: dict[str, InfraDetection] = {}
        self._server_values: Counter[str] = Counter()
        self._via_chains: list[list[str]] = []
        self._cache_hits = 0
        self._cache_misses = 0
        self._age_seen = False

    # ------------------------------------------------------------------
    # Main entry
    # ------------------------------------------------------------------

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        self.logger.info("Starting infrastructure mapping (passive analysis)")

        # Phase A-G: scan all transactions
        txn_count = 0
        async for txn in self.engine.transaction_store.get_all_transactions():
            if not self._running:
                break

            headers_lower = {k.lower(): v for k, v in txn.response_headers.items()}

            self._analyse_headers(headers_lower, txn.request_url)
            self._analyse_cookies(headers_lower)
            self._analyse_server_diversity(headers_lower)
            self._analyse_via_chain(headers_lower)
            self._analyse_cache_topology(headers_lower)

            # Error page analysis (only for error status)
            if txn.response_status >= 400:
                self._analyse_error_page(txn.response_body, txn.response_status)

            txn_count += 1

        self.logger.info("Analysed %d transactions", txn_count)

        # Phase D: server header diversity → LB inference
        self._infer_load_balancer()

        # Phase F: cache topology summary
        self._summarise_cache()

        # Phase H: DNS CNAME (optional)
        if getattr(self.engine.config, "infra_dns_lookup", True):
            await self._dns_cname_lookup()

        # Phase I: build topology and store results
        topology = self._build_topology()
        await self._store_results(topology)

        self.endpoints_found = len(self._detections)
        self._running = False
        self.logger.info(
            "Infrastructure mapping complete — %d components detected",
            len(self._detections),
        )

    # ------------------------------------------------------------------
    # Phase B: Header analysis
    # ------------------------------------------------------------------

    def _analyse_headers(self, headers: dict[str, str], url: str) -> None:
        for sig in HEADER_SIGNATURES:
            value = headers.get(sig.header, "")
            if not value:
                continue
            m = sig.pattern.search(value)
            if not m:
                continue

            key = f"{sig.component}:{sig.category}"
            det = self._detections.setdefault(
                key, InfraDetection(component=sig.component, category=sig.category)
            )
            # Extract version from regex group
            version = ""
            if sig.version_group and sig.version_group <= len(m.groups()):
                version = m.group(sig.version_group) or ""
            if version and not det.version:
                det.version = version

            det.add_evidence(
                "header", f"{sig.header}: {value[:80]}", sig.confidence
            )

    # ------------------------------------------------------------------
    # Phase C: Cookie analysis
    # ------------------------------------------------------------------

    def _analyse_cookies(self, headers: dict[str, str]) -> None:
        set_cookie = headers.get("set-cookie", "")
        if not set_cookie:
            return

        # Extract cookie names (Set-Cookie: name=value; ...)
        for part in set_cookie.split(","):
            part = part.strip()
            if "=" not in part:
                continue
            cookie_name = part.split("=", 1)[0].strip()

            for csig in COOKIE_SIGNATURES:
                matched = False
                if csig.is_prefix:
                    matched = cookie_name.startswith(csig.cookie_pattern)
                else:
                    matched = cookie_name == csig.cookie_pattern

                if matched:
                    key = f"{csig.component}:{csig.category}"
                    det = self._detections.setdefault(
                        key,
                        InfraDetection(
                            component=csig.component, category=csig.category
                        ),
                    )
                    det.add_evidence(
                        "cookie", f"Set-Cookie: {cookie_name}", csig.confidence
                    )

    # ------------------------------------------------------------------
    # Phase D: Server header diversity
    # ------------------------------------------------------------------

    def _analyse_server_diversity(self, headers: dict[str, str]) -> None:
        server = headers.get("server", "")
        if server:
            self._server_values[server] += 1

    def _infer_load_balancer(self) -> None:
        if len(self._server_values) > 1:
            key = "inferred_lb:load_balancer"
            det = self._detections.setdefault(
                key,
                InfraDetection(component="inferred_lb", category="load_balancer"),
            )
            variants = ", ".join(
                f"{v} ({c}x)" for v, c in self._server_values.most_common(5)
            )
            det.add_evidence(
                "server_diversity",
                f"Multiple Server headers detected: {variants}",
                0.70,
            )

    # ------------------------------------------------------------------
    # Phase E: Via chain parsing
    # ------------------------------------------------------------------

    def _analyse_via_chain(self, headers: dict[str, str]) -> None:
        via = headers.get("via", "")
        if not via:
            return

        # Via: 1.1 varnish, 1.1 cloudflare
        hops = [h.strip() for h in via.split(",")]
        if hops:
            self._via_chains.append(hops)

        # Each hop may reveal a proxy component
        for hop in hops:
            hop_lower = hop.lower()
            for name in ("varnish", "cloudflare", "akamai", "haproxy",
                         "envoy", "nginx", "apache", "squid", "traefik"):
                if name in hop_lower:
                    key = f"{name}:proxy"
                    det = self._detections.setdefault(
                        key,
                        InfraDetection(component=name, category="proxy"),
                    )
                    det.add_evidence("via_header", f"Via: {hop}", 0.80)

    # ------------------------------------------------------------------
    # Phase F: Cache topology
    # ------------------------------------------------------------------

    def _analyse_cache_topology(self, headers: dict[str, str]) -> None:
        x_cache = headers.get("x-cache", "").upper()
        if "HIT" in x_cache:
            self._cache_hits += 1
        elif "MISS" in x_cache:
            self._cache_misses += 1

        if headers.get("age", ""):
            self._age_seen = True

    def _summarise_cache(self) -> None:
        total = self._cache_hits + self._cache_misses
        if total > 0 or self._age_seen:
            key = "cache_layer:cdn"
            det = self._detections.setdefault(
                key,
                InfraDetection(component="cache_layer", category="cdn"),
            )
            if total > 0:
                ratio = self._cache_hits / total
                det.add_evidence(
                    "cache",
                    f"X-Cache: {self._cache_hits} HITs / {total} total "
                    f"({ratio:.0%} hit rate)",
                    0.60,
                )
            if self._age_seen:
                det.add_evidence("cache", "Age header present", 0.50)

    # ------------------------------------------------------------------
    # Phase G: Error page analysis
    # ------------------------------------------------------------------

    def _analyse_error_page(self, body: bytes, status: int) -> None:
        try:
            text = body[:65_536].decode("utf-8", errors="replace")
        except Exception:
            return

        for esig in ERROR_PAGE_SIGNATURES:
            lo, hi = esig.status_range
            if not (lo <= status <= hi):
                continue
            if esig.pattern.search(text):
                key = f"{esig.component}:{esig.category}"
                det = self._detections.setdefault(
                    key,
                    InfraDetection(
                        component=esig.component, category=esig.category
                    ),
                )
                det.add_evidence(
                    "error_page", f"HTTP {status} body matches {esig.component}",
                    esig.confidence,
                )

    # ------------------------------------------------------------------
    # Phase H: DNS CNAME lookup
    # ------------------------------------------------------------------

    async def _dns_cname_lookup(self) -> None:
        target = self.engine.config.target_url
        host = urlparse(target).hostname
        if not host:
            return

        try:
            loop = asyncio.get_running_loop()
            fqdn = await loop.run_in_executor(None, socket.getfqdn, host)

            if fqdn and fqdn != host:
                for comp, cat, pattern in CNAME_PATTERNS:
                    if pattern.search(fqdn):
                        key = f"{comp}:{cat}"
                        det = self._detections.setdefault(
                            key,
                            InfraDetection(component=comp, category=cat),
                        )
                        det.add_evidence(
                            "dns_cname", f"{host} → {fqdn}", 0.85
                        )
                        break

            # Also try getaddrinfo for canonical name
            infos = await loop.run_in_executor(
                None, lambda: socket.getaddrinfo(host, None, socket.AF_INET)
            )
            for _fam, _type, _proto, canonname, _addr in infos:
                if canonname and canonname != host:
                    for comp, cat, pattern in CNAME_PATTERNS:
                        if pattern.search(canonname):
                            key = f"{comp}:{cat}"
                            det = self._detections.setdefault(
                                key,
                                InfraDetection(component=comp, category=cat),
                            )
                            det.add_evidence(
                                "dns_canonical", f"{host} → {canonname}", 0.85
                            )
                            break
        except (socket.gaierror, OSError) as e:
            self.logger.debug("DNS lookup for %s failed: %s", host, e)

    # ------------------------------------------------------------------
    # Phase I: Topology inference
    # ------------------------------------------------------------------

    def _build_topology(self) -> list[InfraDetection]:
        """Order detected components by network layer (client → origin)."""
        components = list(self._detections.values())
        components.sort(
            key=lambda d: CATEGORY_LAYER_ORDER.get(d.category, 99)
        )
        return components

    # ------------------------------------------------------------------
    # Store results
    # ------------------------------------------------------------------

    async def _store_results(self, topology: list[InfraDetection]) -> None:
        for det in topology:
            if det.confidence < 0.30:
                continue  # skip very low confidence detections

            tech_fp = TechFingerprint(
                name=det.component,
                version=det.version,
                category=det.category,
                confidence=det.confidence,
                evidence=det.evidence,
            )
            self.engine.attack_surface.merge_tech(tech_fp)

            await self.engine.signals.emit(
                Signal.INFRA_DETECTED,
                component=tech_fp,
            )

        # Log topology summary
        if topology:
            layers = []
            for det in topology:
                if det.confidence >= 0.30:
                    label = det.component
                    if det.version:
                        label += f"/{det.version}"
                    label += f" ({det.category}, {det.confidence:.0%})"
                    layers.append(label)
            self.logger.info(
                "Infrastructure topology: Client → %s → Origin",
                " → ".join(layers),
            )
