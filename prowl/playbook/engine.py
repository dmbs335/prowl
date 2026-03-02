"""Phase-interleaved quality playbook.

Hooks into PHASE_COMPLETED signal and runs relevant plays against
live engine state between pipeline phases.  Findings with severity
``fail`` trigger automatic corrective actions before the next phase
starts.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import Counter
from typing import Any, Callable, Coroutine, TYPE_CHECKING

from prowl.api.schemas import NextCrawlHint, PlaybookFinding, PlaybookResult
from prowl.core.signals import Signal

if TYPE_CHECKING:
    from prowl.core.engine import CrawlEngine

logger = logging.getLogger(__name__)

# Type alias for a play function
PlayFn = Callable[["CrawlEngine", dict[str, Any]], Coroutine[Any, Any, list[PlaybookFinding]]]

# Error keywords for response body analysis
_LOGIN_FAIL_KEYWORDS = re.compile(
    r"login\s+fail|invalid\s+(credentials?|username|password)|"
    r"incorrect\s+(password|username|credentials?)|"
    r"authentication\s+fail|access\s+denied|wrong\s+password",
    re.IGNORECASE,
)

_ERROR_BODY_KEYWORDS = re.compile(
    r"not\s+found|page\s+not\s+found|does\s+not\s+exist|"
    r"error\s+404|no\s+such|cannot\s+find|"
    r"access\s+denied|forbidden|unauthorized",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Individual Plays
# ---------------------------------------------------------------------------


async def p1_completeness(engine: CrawlEngine, exploration: dict[str, Any]) -> list[PlaybookFinding]:
    """After active_crawl: did we discover enough?"""
    findings: list[PlaybookFinding] = []
    total = engine.requests_completed + engine.requests_failed

    if engine.endpoints_found < 5 and total > 20:
        findings.append(PlaybookFinding(
            play="P1_completeness",
            severity="fail",
            title="Very few endpoints discovered",
            detail=f"Only {engine.endpoints_found} endpoints found after {total} requests. "
                   "Target may be misconfigured, blocking requests, or requires authentication.",
            evidence={"endpoints_found": engine.endpoints_found, "requests_total": total},
        ))

    if total > 0 and engine.requests_failed / total > 0.5:
        findings.append(PlaybookFinding(
            play="P1_completeness",
            severity="warn",
            title="High error rate",
            detail=f"{engine.requests_failed}/{total} requests failed "
                   f"({engine.requests_failed / total:.0%}). "
                   "Check target availability or rate limiting.",
            evidence={
                "failed": engine.requests_failed,
                "total": total,
                "rate": round(engine.requests_failed / total, 3),
            },
        ))

    # Check 4xx/5xx distribution from transactions
    try:
        client_errors = await engine.transaction_store.query(status_range=(400, 499), limit=1)
        server_errors = await engine.transaction_store.query(status_range=(500, 599), limit=1)
        txn_count = await engine.transaction_store.count()
        if txn_count > 0:
            ce_txns = await engine.transaction_store.query(status_range=(400, 499), limit=10000)
            se_txns = await engine.transaction_store.query(status_range=(500, 599), limit=10000)
            ce_pct = len(ce_txns) / txn_count
            se_pct = len(se_txns) / txn_count
            if se_pct > 0.2:
                findings.append(PlaybookFinding(
                    play="P1_completeness",
                    severity="warn",
                    title="High server error rate",
                    detail=f"{len(se_txns)}/{txn_count} responses are 5xx ({se_pct:.0%}). "
                           "Server may be unstable or overloaded.",
                    evidence={"5xx_count": len(se_txns), "total": txn_count, "rate": round(se_pct, 3)},
                ))
    except Exception:
        pass  # Transaction store may not be initialized yet

    if not findings:
        findings.append(PlaybookFinding(
            play="P1_completeness",
            severity="info",
            title="Completeness check passed",
            detail=f"{engine.endpoints_found} endpoints discovered from {total} requests.",
            evidence={"endpoints_found": engine.endpoints_found, "requests_total": total},
        ))

    return findings


async def p2_auth_verify(engine: CrawlEngine, exploration: dict[str, Any]) -> list[PlaybookFinding]:
    """After auth_crawl: did login actually work?"""
    findings: list[PlaybookFinding] = []

    # Check if any auth roles were configured
    if not engine.sessions._roles:
        findings.append(PlaybookFinding(
            play="P2_auth",
            severity="info",
            title="No auth roles configured",
            detail="No authentication roles were registered. Skipping auth verification.",
        ))
        return findings

    # Check active sessions
    active_count = engine.sessions.active_session_count
    if active_count == 0:
        findings.append(PlaybookFinding(
            play="P2_auth",
            severity="fail",
            title="No active sessions after auth crawl",
            detail="Auth crawl completed but no valid sessions exist. "
                   "Login may have failed silently.",
            evidence={"roles": list(engine.sessions._roles.keys()), "active_sessions": 0},
            auto_action="Invalidated all sessions; credentials may be incorrect.",
        ))
        return findings

    # Analyze login transactions
    try:
        login_txns = await engine.transaction_store.query(url_pattern="login", limit=50)
        post_logins = [t for t in login_txns if t.request_method == "POST"]

        if not post_logins:
            findings.append(PlaybookFinding(
                play="P2_auth",
                severity="warn",
                title="No login POST requests found",
                detail="Could not find any POST requests to login URLs in transaction log. "
                       "Auth module may not have submitted login forms.",
                evidence={"login_url_txns": len(login_txns)},
            ))
            return findings

        for txn in post_logins[:5]:  # Check up to 5 login attempts
            resp_headers = txn.response_headers
            has_set_cookie = any(
                k.lower() == "set-cookie" for k in resp_headers
            )

            # Decode response body for keyword analysis
            body_text = ""
            if txn.response_body:
                try:
                    body_text = txn.response_body.decode("utf-8", errors="replace")[:4096]
                except Exception:
                    pass

            # Check for failure keywords in response body
            has_fail_keyword = bool(_LOGIN_FAIL_KEYWORDS.search(body_text)) if body_text else False

            # Check for redirect loop (302 back to login)
            is_redirect_loop = False
            if txn.response_status in (301, 302, 303, 307, 308):
                location = resp_headers.get("location", resp_headers.get("Location", ""))
                if "login" in location.lower():
                    is_redirect_loop = True

            if has_fail_keyword:
                findings.append(PlaybookFinding(
                    play="P2_auth",
                    severity="fail",
                    title="Login response contains failure keywords",
                    detail=f"POST {txn.request_url} returned {txn.response_status} "
                           f"with failure indicators in response body.",
                    evidence={
                        "url": txn.request_url,
                        "status": txn.response_status,
                        "has_set_cookie": has_set_cookie,
                    },
                    auto_action="Sessions invalidated due to likely authentication failure.",
                ))
                # Invalidate sessions for this role
                for role_name in list(engine.sessions._roles.keys()):
                    sessions = engine.sessions._sessions.get(role_name, [])
                    for s in sessions:
                        s.is_valid = False
                break

            if is_redirect_loop:
                findings.append(PlaybookFinding(
                    play="P2_auth",
                    severity="fail",
                    title="Login redirect loop detected",
                    detail=f"POST {txn.request_url} redirected back to login page. "
                           "Credentials are likely incorrect.",
                    evidence={
                        "url": txn.request_url,
                        "status": txn.response_status,
                        "location": resp_headers.get("location", resp_headers.get("Location", "")),
                    },
                    auto_action="Sessions invalidated due to redirect loop.",
                ))
                for role_name in list(engine.sessions._roles.keys()):
                    sessions = engine.sessions._sessions.get(role_name, [])
                    for s in sessions:
                        s.is_valid = False
                break

            if not has_set_cookie and txn.response_status == 200:
                findings.append(PlaybookFinding(
                    play="P2_auth",
                    severity="warn",
                    title="Login returned 200 but no Set-Cookie",
                    detail=f"POST {txn.request_url} returned 200 OK "
                           "without setting any cookies. Login may have failed silently "
                           "(server returns 200 for both success and failure).",
                    evidence={
                        "url": txn.request_url,
                        "status": txn.response_status,
                        "response_headers": list(resp_headers.keys()),
                    },
                ))
            elif has_set_cookie:
                findings.append(PlaybookFinding(
                    play="P2_auth",
                    severity="info",
                    title="Login appears successful",
                    detail=f"POST {txn.request_url} returned {txn.response_status} "
                           "with Set-Cookie headers.",
                    evidence={
                        "url": txn.request_url,
                        "status": txn.response_status,
                        "cookies_set": True,
                    },
                ))
                break  # Found a good login

    except Exception as exc:
        findings.append(PlaybookFinding(
            play="P2_auth",
            severity="warn",
            title="Could not analyze login transactions",
            detail=f"Error querying transaction store: {exc}",
        ))

    return findings


async def p3_response_semantics(engine: CrawlEngine, exploration: dict[str, Any]) -> list[PlaybookFinding]:
    """After active_crawl/deep_crawl: detect soft-404s and false positives."""
    findings: list[PlaybookFinding] = []

    try:
        # Sample 200 OK HTML responses
        ok_txns = await engine.transaction_store.query(
            status_range=(200, 200),
            content_type_contains="html",
            limit=200,
        )

        if len(ok_txns) < 5:
            return findings

        # Group by content_hash to find soft-404s
        hash_groups: dict[str, list[str]] = {}
        for txn in ok_txns:
            if txn.content_hash:
                hash_groups.setdefault(txn.content_hash, []).append(txn.request_url)

        # Soft-404 detection: same content hash for many different URLs
        soft_404_hashes = {h: urls for h, urls in hash_groups.items() if len(urls) >= 5}
        if soft_404_hashes:
            total_affected = sum(len(urls) for urls in soft_404_hashes.values())
            findings.append(PlaybookFinding(
                play="P3_semantics",
                severity="warn",
                title=f"Soft-404 detected: {len(soft_404_hashes)} duplicate response patterns",
                detail=f"{total_affected} URLs returned identical content (same content hash). "
                       "These are likely custom error pages returning 200 OK instead of 404.",
                evidence={
                    "duplicate_groups": len(soft_404_hashes),
                    "total_affected_urls": total_affected,
                    "sample_group": list(list(soft_404_hashes.values())[0][:5]),
                },
                auto_action=f"Registered {len(soft_404_hashes)} content hashes for dedup filtering.",
            ))
            # Register soft-404 hashes in dedup to filter future responses
            for h in soft_404_hashes:
                engine.dedup.mark_seen_content(h)

        # False positive detection: 200 OK with error keywords in body
        false_positive_count = 0
        false_positive_urls: list[str] = []
        for txn in ok_txns[:100]:  # Check up to 100
            if txn.response_body:
                try:
                    body = txn.response_body.decode("utf-8", errors="replace")[:2048]
                    if _ERROR_BODY_KEYWORDS.search(body):
                        false_positive_count += 1
                        if len(false_positive_urls) < 5:
                            false_positive_urls.append(txn.request_url)
                except Exception:
                    pass

        if false_positive_count > 3:
            findings.append(PlaybookFinding(
                play="P3_semantics",
                severity="warn",
                title=f"{false_positive_count} potential false positive endpoints",
                detail="These URLs returned 200 OK but contain error-like content "
                       "(not found, error, forbidden, etc.). They may be incorrectly "
                       "counted as valid endpoints.",
                evidence={
                    "count": false_positive_count,
                    "sample_urls": false_positive_urls,
                },
            ))

        # Empty body detection: 200 OK with tiny body
        empty_count = sum(1 for t in ok_txns if len(t.response_body or b"") < 100)
        if empty_count > 5:
            findings.append(PlaybookFinding(
                play="P3_semantics",
                severity="info",
                title=f"{empty_count} responses with near-empty bodies",
                detail="200 OK responses with less than 100 bytes. "
                       "May indicate placeholder pages or API endpoints without HTML.",
                evidence={"count": empty_count},
            ))

        # JSON error pattern detection
        json_txns = await engine.transaction_store.query(
            status_range=(200, 200),
            content_type_contains="json",
            limit=100,
        )
        json_error_count = 0
        for txn in json_txns:
            if txn.response_body:
                try:
                    body = txn.response_body.decode("utf-8", errors="replace")[:1024]
                    data = json.loads(body)
                    if isinstance(data, dict) and ("error" in data or "errors" in data):
                        json_error_count += 1
                except (json.JSONDecodeError, Exception):
                    pass
        if json_error_count > 2:
            findings.append(PlaybookFinding(
                play="P3_semantics",
                severity="warn",
                title=f"{json_error_count} JSON error responses with 200 OK",
                detail="API responses returning 200 OK with error payloads. "
                       "These are counted as successful but contain error data.",
                evidence={"count": json_error_count},
            ))

        if not findings:
            findings.append(PlaybookFinding(
                play="P3_semantics",
                severity="info",
                title="Response semantics check passed",
                detail=f"Analyzed {len(ok_txns)} responses. No significant anomalies.",
            ))

    except Exception as exc:
        findings.append(PlaybookFinding(
            play="P3_semantics",
            severity="warn",
            title="Could not analyze response semantics",
            detail=f"Error: {exc}",
        ))

    return findings


async def p4_input_vectors(engine: CrawlEngine, exploration: dict[str, Any]) -> list[PlaybookFinding]:
    """After param_discovery: assess input vector quality."""
    findings: list[PlaybookFinding] = []

    ep_count = engine.attack_surface.endpoint_count
    iv_count = engine.attack_surface.input_vector_count

    if ep_count == 0:
        return findings

    # Parameter coverage
    endpoints_with_params = sum(
        1 for ep in engine.attack_surface.endpoints if ep.parameters
    )
    paramless_ratio = 1.0 - (endpoints_with_params / ep_count) if ep_count > 0 else 0.0

    if paramless_ratio > 0.7 and ep_count > 10:
        findings.append(PlaybookFinding(
            play="P4_input_vectors",
            severity="warn",
            title="Low parameter coverage",
            detail=f"{paramless_ratio:.0%} of endpoints ({ep_count - endpoints_with_params}/{ep_count}) "
                   "have no parameters. Parameter discovery may be insufficient.",
            evidence={
                "endpoints_total": ep_count,
                "endpoints_with_params": endpoints_with_params,
                "paramless_ratio": round(paramless_ratio, 3),
            },
        ))

    # Risk indicator distribution
    high_risk = engine.attack_surface.get_high_risk_vectors()
    risk_types: Counter[str] = Counter()
    for iv in high_risk:
        for ri in iv.risk_indicators:
            risk_types[ri] += 1

    reflected_count = sum(1 for iv in engine.attack_surface.input_vectors if iv.is_reflected)

    findings.append(PlaybookFinding(
        play="P4_input_vectors",
        severity="info",
        title="Input vector summary",
        detail=f"{iv_count} input vectors across {ep_count} endpoints. "
               f"{len(high_risk)} high-risk, {reflected_count} reflected.",
        evidence={
            "total_vectors": iv_count,
            "high_risk": len(high_risk),
            "reflected": reflected_count,
            "risk_distribution": dict(risk_types),
        },
    ))

    return findings


async def p5_tech_coverage(engine: CrawlEngine, exploration: dict[str, Any]) -> list[PlaybookFinding]:
    """After fingerprinting: are the right modules enabled for detected tech?"""
    findings: list[PlaybookFinding] = []

    tech_stack = engine.attack_surface.tech_stack
    if not tech_stack:
        findings.append(PlaybookFinding(
            play="P5_tech_coverage",
            severity="info",
            title="No technologies detected",
            detail="Tech fingerprinting found no technologies. "
                   "This is normal for simple HTML sites.",
        ))
        return findings

    tech_names_lower = {t.name.lower() for t in tech_stack}
    tech_categories = {t.category.lower() for t in tech_stack if t.category}
    selected_modules = set(engine.config.modules) if engine.config.modules else set()

    # Tech → module recommendations
    recommendations: list[tuple[str, str, str]] = []  # (tech, module, reason)

    # PHP detection
    if any(t in tech_names_lower for t in ("php", "wordpress", "drupal", "joomla", "laravel")):
        if selected_modules and "s6_passive" not in selected_modules:
            recommendations.append(("PHP", "s6_passive", "PHP detected; passive collection can find PHP-specific paths"))

    # REST API detection
    if any(t in tech_names_lower for t in ("rest", "api", "swagger", "openapi")) or \
       any(c in tech_categories for c in ("api",)):
        if selected_modules and "s5_api" not in selected_modules:
            recommendations.append(("REST API", "s5_api", "API patterns detected; API discovery module recommended"))

    # JavaScript SPA detection
    if any(t in tech_names_lower for t in ("react", "vue", "angular", "next.js", "nuxt")):
        if selected_modules and "s4_js" not in selected_modules:
            recommendations.append(("JavaScript SPA", "s4_js", "SPA framework detected; JS analysis essential for route discovery"))

    for tech, module, reason in recommendations:
        findings.append(PlaybookFinding(
            play="P5_tech_coverage",
            severity="warn",
            title=f"Module {module} recommended for {tech}",
            detail=reason,
            evidence={"detected_tech": tech, "recommended_module": module},
        ))

    if not recommendations:
        tech_summary = ", ".join(t.name for t in tech_stack[:10])
        findings.append(PlaybookFinding(
            play="P5_tech_coverage",
            severity="info",
            title="Tech coverage adequate",
            detail=f"Detected: {tech_summary}. Module selection matches detected technologies.",
            evidence={"tech_count": len(tech_stack)},
        ))

    return findings


async def p6_scope_efficiency(engine: CrawlEngine, exploration: dict[str, Any]) -> list[PlaybookFinding]:
    """After active_crawl/deep_crawl: are we spending effort wisely?"""
    findings: list[PlaybookFinding] = []

    total_requests = engine.requests_completed + engine.requests_failed
    unique_eps = engine.endpoints_found

    if total_requests < 10:
        return findings

    efficiency = unique_eps / total_requests if total_requests > 0 else 0.0

    # Template over-sampling detection via coverage stats
    template_counts: Counter[str] = Counter()
    try:
        txns = await engine.transaction_store.query(limit=5000)
        for txn in txns:
            # Simple template normalization: replace numeric path segments
            path = txn.request_url.split("?")[0]
            template = re.sub(r"/\d+", "/{id}", path)
            template_counts[template] += 1

        oversampled = [(t, c) for t, c in template_counts.most_common(20) if c > 20]
        if oversampled:
            findings.append(PlaybookFinding(
                play="P6_scope",
                severity="warn",
                title=f"{len(oversampled)} over-sampled URL templates",
                detail="Some URL templates received significantly more requests than necessary. "
                       "Consider sample-based exploration for these templates.",
                evidence={
                    "oversampled": [{
                        "template": t,
                        "request_count": c,
                    } for t, c in oversampled[:10]],
                },
            ))
    except Exception:
        pass

    # Efficiency metric
    findings.append(PlaybookFinding(
        play="P6_scope",
        severity="info",
        title=f"Scope efficiency: {efficiency:.1%}",
        detail=f"{unique_eps} unique endpoints from {total_requests} requests.",
        evidence={
            "unique_endpoints": unique_eps,
            "total_requests": total_requests,
            "efficiency": round(efficiency, 4),
        },
    ))

    return findings


async def p7_secret_validation(engine: CrawlEngine, exploration: dict[str, Any]) -> list[PlaybookFinding]:
    """After classification: validate discovered secrets."""
    findings: list[PlaybookFinding] = []

    secrets = engine.attack_surface.secrets
    if not secrets:
        findings.append(PlaybookFinding(
            play="P7_secrets",
            severity="info",
            title="No secrets discovered",
            detail="No secrets or credentials found in responses.",
        ))
        return findings

    false_positive_keywords = {"test", "example", "placeholder", "xxx", "dummy", "sample", "demo", "todo"}
    low_confidence: list[dict[str, str]] = []
    short_tokens: list[dict[str, str]] = []

    for secret in secrets:
        val_lower = secret.value.lower()
        if any(kw in val_lower for kw in false_positive_keywords):
            low_confidence.append({"kind": secret.kind, "source": secret.source_url})
        if len(secret.value) < 10 and secret.kind in ("api_key", "token"):
            short_tokens.append({"kind": secret.kind, "value_length": str(len(secret.value))})

    if low_confidence:
        findings.append(PlaybookFinding(
            play="P7_secrets",
            severity="warn",
            title=f"{len(low_confidence)} likely false positive secrets",
            detail="Secrets containing test/example/placeholder values "
                   "are probably not real credentials.",
            evidence={"count": len(low_confidence), "samples": low_confidence[:5]},
        ))

    if short_tokens:
        findings.append(PlaybookFinding(
            play="P7_secrets",
            severity="warn",
            title=f"{len(short_tokens)} suspiciously short tokens",
            detail="API keys or tokens shorter than 10 characters are likely false positives.",
            evidence={"count": len(short_tokens), "samples": short_tokens[:5]},
        ))

    real_count = len(secrets) - len(low_confidence) - len(short_tokens)
    if real_count > 0:
        findings.append(PlaybookFinding(
            play="P7_secrets",
            severity="info",
            title=f"{real_count} potentially valid secrets found",
            detail=f"Total secrets: {len(secrets)}, after filtering likely false positives: {real_count}.",
            evidence={"total": len(secrets), "filtered_valid": real_count},
        ))

    return findings


async def p8_discovery_momentum(engine: CrawlEngine, exploration: dict[str, Any]) -> list[PlaybookFinding]:
    """After active_crawl/deep_crawl: is exploration still productive?"""
    findings: list[PlaybookFinding] = []

    stats = engine.coverage.get_stats()
    discovery_rate = stats.get("discovery_rate", 0.0)
    saturated = stats.get("saturated", False)
    total_checked = stats.get("total_checked", 0)
    unique_coverage = stats.get("unique_coverage", 0)

    new_coverage = exploration.get("new_coverage", 0)
    phase_requests = exploration.get("requests", 0)

    if saturated:
        findings.append(PlaybookFinding(
            play="P8_momentum",
            severity="info",
            title="Coverage saturated",
            detail=f"Discovery rate {discovery_rate:.1%} (below threshold). "
                   f"{unique_coverage} unique coverage tuples from {total_checked} checks. "
                   "Further crawling has diminishing returns.",
            evidence={
                "discovery_rate": discovery_rate,
                "unique_coverage": unique_coverage,
                "total_checked": total_checked,
            },
        ))
    elif phase_requests > 50 and new_coverage == 0:
        findings.append(PlaybookFinding(
            play="P8_momentum",
            severity="warn",
            title="No new coverage from this phase",
            detail=f"Phase made {phase_requests} requests but discovered 0 new coverage. "
                   "Exploration may be stuck or target is fully mapped.",
            evidence={
                "phase_requests": phase_requests,
                "new_coverage": new_coverage,
            },
        ))
    else:
        phase_rate = new_coverage / phase_requests if phase_requests > 0 else 0.0
        findings.append(PlaybookFinding(
            play="P8_momentum",
            severity="info",
            title=f"Discovery momentum: {phase_rate:.1%}",
            detail=f"Phase produced {new_coverage} new coverage from {phase_requests} requests.",
            evidence={
                "new_coverage": new_coverage,
                "phase_requests": phase_requests,
                "phase_discovery_rate": round(phase_rate, 4),
                "global_discovery_rate": discovery_rate,
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# PlaybookEngine
# ---------------------------------------------------------------------------


class PlaybookEngine:
    """Phase-interleaved quality playbook.

    Subscribes to ``Signal.PHASE_COMPLETED`` and runs relevant plays
    against the live ``CrawlEngine`` state between pipeline phases.
    """

    # Play registry: phase_name -> [play_functions]
    PLAY_TRIGGERS: dict[str, list[PlayFn]] = {
        "active_crawl": [p1_completeness, p3_response_semantics, p6_scope_efficiency, p8_discovery_momentum],
        "fingerprinting": [p5_tech_coverage],
        "auth_crawl": [p2_auth_verify],
        "deep_crawl": [p3_response_semantics, p6_scope_efficiency, p8_discovery_momentum],
        "param_discovery": [p4_input_vectors],
        "classification": [p7_secret_validation],
    }

    def __init__(self, engine: CrawlEngine) -> None:
        self.engine = engine
        self.findings: list[PlaybookFinding] = []
        self.phases_checked: list[str] = []
        self._plays_run = 0

    def connect(self) -> None:
        """Subscribe to PHASE_COMPLETED signal."""
        self.engine.signals.connect(Signal.PHASE_COMPLETED, self._on_phase_completed)
        logger.info("Playbook engine connected -- %d phase triggers registered",
                     len(self.PLAY_TRIGGERS))

    async def _on_phase_completed(self, **kwargs: Any) -> None:
        phase = kwargs.get("phase", "")
        exploration = kwargs.get("exploration", {})
        plays = self.PLAY_TRIGGERS.get(phase, [])

        if not plays:
            return

        self.phases_checked.append(phase)
        phase_findings: list[PlaybookFinding] = []

        for play_fn in plays:
            try:
                new_findings = await play_fn(self.engine, exploration)
                phase_findings.extend(new_findings)
                self._plays_run += 1
            except Exception as exc:
                logger.exception("Playbook play %s failed", play_fn.__name__)
                phase_findings.append(PlaybookFinding(
                    play=play_fn.__name__,
                    severity="warn",
                    title=f"Play {play_fn.__name__} error",
                    detail=str(exc),
                ))

        self.findings.extend(phase_findings)

        # Log summary for this phase checkpoint
        severity_counts = Counter(f.severity for f in phase_findings)
        parts = []
        if severity_counts.get("fail"):
            parts.append(f"{severity_counts['fail']} FAIL")
        if severity_counts.get("warn"):
            parts.append(f"{severity_counts['warn']} WARN")
        if severity_counts.get("info"):
            parts.append(f"{severity_counts['info']} INFO")
        summary = ", ".join(parts) if parts else "no findings"

        logger.info(
            "Playbook [%s]: %d plays, %s",
            phase, len(plays), summary,
        )
        for f in phase_findings:
            if f.severity == "fail":
                logger.warning("  FAIL: %s -- %s", f.title, f.detail[:120])
            elif f.severity == "warn":
                logger.warning("  WARN: %s", f.title)

    def _derive_hints(self) -> list[NextCrawlHint]:
        """Generate configuration hints from accumulated findings."""
        hints: list[NextCrawlHint] = []

        for f in self.findings:
            if f.play == "P2_auth" and f.severity == "fail":
                hints.append(NextCrawlHint(
                    action="fix_auth",
                    description="Authentication failed. Verify credentials and login URL.",
                    config_patch={"auth_roles": "check credentials"},
                ))
            elif f.play == "P5_tech_coverage" and f.severity == "warn":
                module = f.evidence.get("recommended_module", "")
                if module:
                    hints.append(NextCrawlHint(
                        action="enable_module",
                        description=f"Enable {module} for better coverage of detected technology.",
                        config_patch={"modules": [module]},
                    ))
            elif f.play == "P1_completeness" and f.severity == "fail":
                hints.append(NextCrawlHint(
                    action="increase_depth",
                    description="Very few endpoints found. Consider increasing depth or checking target.",
                    config_patch={"max_depth": 15},
                ))
            elif f.play == "P6_scope" and "over-sampled" in f.title:
                oversampled = f.evidence.get("oversampled", [])
                if oversampled:
                    templates = [o["template"] for o in oversampled[:3]]
                    hints.append(NextCrawlHint(
                        action="focus_area",
                        description=f"Over-sampled templates: {', '.join(templates)}. "
                                    "Consider excluding or rate-limiting these paths.",
                    ))

        return hints

    def get_result(self) -> PlaybookResult:
        """Get accumulated results. Call after crawl completes."""
        hints = self._derive_hints()
        severity_counts = Counter(f.severity for f in self.findings)

        return PlaybookResult(
            target=self.engine.config.target_url,
            timestamp=time.time(),
            plays_run=self._plays_run,
            findings=self.findings,
            hints=hints,
            summary={
                "info": severity_counts.get("info", 0),
                "warn": severity_counts.get("warn", 0),
                "fail": severity_counts.get("fail", 0),
            },
            phases_checked=self.phases_checked,
        )
