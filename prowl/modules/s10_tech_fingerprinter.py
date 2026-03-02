"""Tech Fingerprinter - identifies application-layer technologies by
analysing response bodies, script tags, meta tags, and URL paths.

Complementary to s9_infra_mapper (network layer).  This module detects
CMS, JS frameworks, CSS frameworks, server-side frameworks, analytics,
and other application-level technologies.

No additional HTTP requests are made - purely passive analysis of
data already stored in the TransactionStore.
"""

from __future__ import annotations

import hashlib
import re
import logging
from typing import Any

from prowl.core.infra_signatures import InfraDetection
from prowl.core.signals import Signal
from prowl.core.tech_signatures import (
    BODY_SIGNATURES,
    META_SIGNATURES,
    SCRIPT_SRC_SIGNATURES,
    URL_PATH_SIGNATURES,
)
from prowl.models.target import TechFingerprint
from prowl.modules.base import BaseModule

logger = logging.getLogger(__name__)

# Pre-compiled extractors
_META_RE = re.compile(
    r'<meta\s[^>]*?name=["\']([^"\']+)["\'][^>]*?content=["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL,
)
_SCRIPT_SRC_RE = re.compile(
    r'<script\s[^>]*?src=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_LINK_HREF_RE = re.compile(
    r'<link\s[^>]*?href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


class TechFingerprinterModule(BaseModule):
    """Passive application-layer technology detection.

    Analyses HTML bodies from the TransactionStore to identify CMS,
    frameworks, JS libraries, CSS frameworks, analytics, and more.
    """

    name = "s10_tech"
    description = "Application technology fingerprinter"

    def __init__(self, engine: Any) -> None:
        super().__init__(engine)
        self._detections: dict[str, InfraDetection] = {}

    async def run(self, **kwargs: Any) -> None:
        self._running = True
        await self.engine.signals.emit(Signal.MODULE_STARTED, module=self.name)
        self.logger.info("Starting tech fingerprinting (passive analysis)")

        # Two-pass approach to filter soft-404 pages:
        # Pass 1: collect body hashes and count how many distinct URLs share them
        body_hash_counts: dict[str, int] = {}
        txn_count = 0

        async for txn in self.engine.transaction_store.get_all_transactions():
            if not self._running:
                break
            ct = txn.response_content_type.lower()
            if "html" not in ct:
                txn_count += 1
                continue
            body = txn.response_body
            if not body or len(body) < 32:
                txn_count += 1
                continue
            h = hashlib.md5(body[:8192]).hexdigest()
            body_hash_counts[h] = body_hash_counts.get(h, 0) + 1
            txn_count += 1

        # Body hashes appearing on 5+ distinct URLs are likely soft-404/default pages
        soft_404_hashes = {h for h, c in body_hash_counts.items() if c >= 5}
        if soft_404_hashes:
            self.logger.info(
                "Detected %d likely soft-404 body hashes (skipping for body analysis)",
                len(soft_404_hashes),
            )

        # Pass 2: actual analysis with deduplication
        seen_bodies: set[str] = set()
        txn_count = 0
        skipped_soft404 = 0
        async for txn in self.engine.transaction_store.get_all_transactions():
            if not self._running:
                break

            # Compute body hash early (needed for URL path + body filtering)
            body = txn.response_body
            body_hash = ""
            if body and len(body) >= 32:
                body_hash = hashlib.md5(body[:8192]).hexdigest()

            is_soft_404 = body_hash in soft_404_hashes

            # URL path analysis — only for real successful responses
            # (skip error status AND soft-404 pages)
            if 200 <= txn.response_status < 400 and not is_soft_404:
                self._analyse_url_paths(txn.request_url)

            # Body analysis (only HTML responses, skip error status)
            if txn.response_status >= 400:
                txn_count += 1
                continue

            ct = txn.response_content_type.lower()
            if "html" not in ct:
                txn_count += 1
                continue

            if not body_hash:
                txn_count += 1
                continue

            # Deduplicate: skip bodies we've already analysed
            if body_hash in seen_bodies:
                txn_count += 1
                continue
            seen_bodies.add(body_hash)

            # Skip soft-404 pages (same body served on many different URLs)
            if is_soft_404:
                skipped_soft404 += 1
                txn_count += 1
                continue

            text = body[:200_000].decode("utf-8", errors="replace")

            self._analyse_meta_tags(text)
            self._analyse_script_srcs(text)
            self._analyse_body_patterns(text)

            txn_count += 1

        self.logger.info(
            "Analysed %d transactions (%d unique bodies, %d soft-404 skipped)",
            txn_count, len(seen_bodies), skipped_soft404,
        )

        # Store results
        await self._store_results()

        self.endpoints_found = len(self._detections)
        self._running = False
        await self.engine.signals.emit(
            Signal.MODULE_COMPLETED, module=self.name, stats=self.get_stats()
        )
        self.logger.info(
            "Tech fingerprinting complete - %d technologies detected",
            len(self._detections),
        )

    def get_stats(self) -> dict[str, Any]:
        stats = super().get_stats()
        by_category: dict[str, int] = {}
        high_confidence = 0
        for det in self._detections.values():
            if det.confidence >= 0.30:
                by_category[det.category] = by_category.get(det.category, 0) + 1
                if det.confidence >= 0.80:
                    high_confidence += 1
        stats["by_category"] = by_category
        stats["high_confidence"] = high_confidence
        return stats

    # ------------------------------------------------------------------
    # Meta tag analysis  (<meta name="generator" content="WordPress 6.4">)
    # ------------------------------------------------------------------

    def _analyse_meta_tags(self, html: str) -> None:
        for name_attr, content_attr in _META_RE.findall(html):
            name_lower = name_attr.lower().strip()
            for msig in META_SIGNATURES:
                if name_lower != msig.meta_name:
                    continue
                m = msig.content_pattern.search(content_attr)
                if not m:
                    continue

                key = f"{msig.component}:{msig.category}"
                det = self._detections.setdefault(
                    key, InfraDetection(component=msig.component, category=msig.category)
                )
                version = ""
                if msig.version_group and msig.version_group <= len(m.groups()):
                    version = m.group(msig.version_group) or ""
                if version and not det.version:
                    det.version = version
                det.add_evidence("meta_tag", f'{name_attr}="{content_attr}"', msig.confidence)

    # ------------------------------------------------------------------
    # Script src analysis  (<script src="jquery-3.6.0.min.js">)
    # ------------------------------------------------------------------

    def _analyse_script_srcs(self, html: str) -> None:
        for src in _SCRIPT_SRC_RE.findall(html):
            for ssig in SCRIPT_SRC_SIGNATURES:
                m = ssig.pattern.search(src)
                if not m:
                    continue

                key = f"{ssig.component}:{ssig.category}"
                det = self._detections.setdefault(
                    key, InfraDetection(component=ssig.component, category=ssig.category)
                )
                version = ""
                if ssig.version_group and ssig.version_group <= len(m.groups()):
                    version = m.group(ssig.version_group) or ""
                if version and not det.version:
                    det.version = version
                det.add_evidence("script_src", src[:120], ssig.confidence)

        # Also check <link href="..."> for CSS frameworks
        for href in _LINK_HREF_RE.findall(html):
            for ssig in SCRIPT_SRC_SIGNATURES:
                m = ssig.pattern.search(href)
                if not m:
                    continue

                key = f"{ssig.component}:{ssig.category}"
                det = self._detections.setdefault(
                    key, InfraDetection(component=ssig.component, category=ssig.category)
                )
                version = ""
                if ssig.version_group and ssig.version_group <= len(m.groups()):
                    version = m.group(ssig.version_group) or ""
                if version and not det.version:
                    det.version = version
                det.add_evidence("link_href", href[:120], ssig.confidence)

    # ------------------------------------------------------------------
    # Body pattern analysis (inline markers in HTML)
    # ------------------------------------------------------------------

    def _analyse_body_patterns(self, html: str) -> None:
        for bsig in BODY_SIGNATURES:
            m = bsig.pattern.search(html)
            if not m:
                continue

            key = f"{bsig.component}:{bsig.category}"
            det = self._detections.setdefault(
                key, InfraDetection(component=bsig.component, category=bsig.category)
            )
            version = ""
            if bsig.version_group and bsig.version_group <= len(m.groups()):
                version = m.group(bsig.version_group) or ""
            if version and not det.version:
                det.version = version

            # Truncate match for evidence
            matched = m.group(0)[:80]
            det.add_evidence("body", matched, bsig.confidence)

    # ------------------------------------------------------------------
    # URL path analysis
    # ------------------------------------------------------------------

    def _analyse_url_paths(self, url: str) -> None:
        for usig in URL_PATH_SIGNATURES:
            if not usig.pattern.search(url):
                continue

            key = f"{usig.component}:{usig.category}"
            det = self._detections.setdefault(
                key, InfraDetection(component=usig.component, category=usig.category)
            )
            det.add_evidence("url_path", url[:120], usig.confidence)

    # ------------------------------------------------------------------
    # Store results
    # ------------------------------------------------------------------

    async def _store_results(self) -> None:
        for det in self._detections.values():
            if det.confidence < 0.30:
                continue

            tech_fp = TechFingerprint(
                name=det.component,
                version=det.version,
                category=det.category,
                confidence=det.confidence,
                evidence=det.evidence,
            )
            self.engine.attack_surface.merge_tech(tech_fp)

            await self.engine.signals.emit(
                Signal.TECH_DETECTED,
                tech=tech_fp,
            )

        # Log summary
        if self._detections:
            items = sorted(
                ((d.component, d.version, d.category, d.confidence)
                 for d in self._detections.values() if d.confidence >= 0.30),
                key=lambda x: -x[3],
            )
            for comp, ver, cat, conf in items:
                label = comp
                if ver:
                    label += f"/{ver}"
                self.logger.info("  [%s] %s (%.0f%%)", cat, label, conf * 100)
