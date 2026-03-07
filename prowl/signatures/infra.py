"""Infrastructure fingerprint signature database.

Maps HTTP response headers, cookies, and error page patterns to
infrastructure components (CDN, WAF, reverse proxy, load balancer, server).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class InfraSignature:
    """A single header-based infrastructure detection rule."""

    component: str         # e.g. "cloudflare", "nginx", "aws_alb"
    category: str          # "cdn" | "waf" | "proxy" | "load_balancer" | "server"
    header: str            # lowercase header name to check
    pattern: re.Pattern[str]
    confidence: float      # 0.0-1.0 base confidence when matched
    version_group: int = 0  # regex capture group index for version extraction


@dataclass(frozen=True)
class CookieSignature:
    """Cookie-name-based infrastructure detection."""

    cookie_pattern: str    # exact name or prefix
    component: str
    category: str
    confidence: float
    is_prefix: bool = False  # True = prefix match, False = exact match


@dataclass(frozen=True)
class ErrorPageSignature:
    """Response body pattern for error-page-based detection."""

    component: str
    category: str
    pattern: re.Pattern[str]
    confidence: float
    status_range: tuple[int, int] = (400, 599)  # status codes where this applies


@dataclass
class InfraDetection:
    """Accumulated detection result for one infrastructure component."""

    component: str
    category: str
    confidence: float = 0.0
    version: str = ""
    evidence: list[str] = field(default_factory=list)
    hit_count: int = 0
    _source_confs: dict[str, float] = field(default_factory=dict, repr=False)

    def add_evidence(self, source: str, detail: str, conf: float) -> None:
        """Add evidence and accumulate confidence via probabilistic OR.

        Each source type (header, cookie, body, meta_tag, script_src, etc.)
        contributes its *maximum* observed confidence.  The final score is
        computed as ``1 - product(1 - max_conf_i)`` across all source types,
        which is order-independent and naturally caps at 1.0.

        Repeated evidence from the same source type only upgrades the score
        if the new confidence exceeds the previous max for that source.
        """
        self.hit_count += 1
        entry = f"{source}: {detail}"
        if entry not in self.evidence:
            self.evidence.append(entry)

        prev = self._source_confs.get(source, 0.0)
        if conf <= prev:
            return  # same or weaker signal from this source — skip

        self._source_confs[source] = conf

        # Recalculate: probabilistic OR over per-source maxima
        product = 1.0
        for c in self._source_confs.values():
            product *= (1.0 - c)
        self.confidence = 1.0 - product


# ---------------------------------------------------------------------------
# Header-based signatures
# ---------------------------------------------------------------------------

def _sig(component: str, category: str, header: str,
         pattern: str, confidence: float, version_group: int = 0,
         flags: int = re.IGNORECASE) -> InfraSignature:
    return InfraSignature(
        component=component, category=category, header=header,
        pattern=re.compile(pattern, flags), confidence=confidence,
        version_group=version_group,
    )


HEADER_SIGNATURES: list[InfraSignature] = [
    # ---- CDN ----
    _sig("cloudflare", "cdn", "cf-ray", r".+", 0.95),
    _sig("cloudflare", "cdn", "cf-cache-status",
         r"(?:HIT|MISS|BYPASS|DYNAMIC|EXPIRED|STALE|UPDATING|REVALIDATED)", 0.90),
    _sig("cloudflare", "cdn", "cdn-loop", r"cloudflare", 0.90),
    _sig("akamai", "cdn", "x-akamai-transformed", r".+", 0.90),
    _sig("akamai", "cdn", "akamai-grn", r".+", 0.95),
    _sig("akamai", "cdn", "x-akamai-edgescape", r".+", 0.85),
    _sig("fastly", "cdn", "x-served-by", r"cache-", 0.90),
    _sig("fastly", "cdn", "fastly-ff", r".+", 0.95),
    _sig("fastly", "cdn", "x-fastly-request-id", r".+", 0.90),
    _sig("cloudfront", "cdn", "x-amz-cf-id", r".+", 0.95),
    _sig("cloudfront", "cdn", "x-amz-cf-pop", r"[A-Z]{3}\d+", 0.95),
    _sig("azure_cdn", "cdn", "x-azure-ref", r".+", 0.85),
    _sig("google_cdn", "cdn", "x-goog-hash", r".+", 0.80),

    # ---- WAF ----
    _sig("cloudflare_waf", "waf", "server", r"cloudflare", 0.80),
    _sig("aws_waf", "waf", "x-amzn-waf-action", r".+", 0.90),
    _sig("aws_waf", "waf", "x-amzn-waf-rule", r".+", 0.85),
    _sig("aws", "server", "x-amzn-requestid", r".+", 0.50),
    _sig("imperva", "waf", "x-cdn", r"(?:imperva|incapsula)", 0.90),
    _sig("sucuri", "waf", "x-sucuri-id", r".+", 0.90),
    _sig("sucuri", "waf", "x-sucuri-cache", r".+", 0.85),
    _sig("modsecurity", "waf", "server", r"mod_security", 0.85),
    _sig("f5_bigip", "waf", "server", r"BigIP|BIG-IP", 0.85),
    _sig("barracuda", "waf", "server", r"Barracuda", 0.85),

    # ---- Reverse Proxy ----
    _sig("nginx", "proxy", "server", r"nginx(?:/([\d.]+))?", 0.85, version_group=1),
    _sig("apache", "proxy", "server", r"Apache(?:/([\d.]+))?", 0.85, version_group=1),
    _sig("varnish", "proxy", "via", r"varnish", 0.85),
    _sig("varnish", "proxy", "x-varnish", r"\d+", 0.90),
    _sig("envoy", "proxy", "server", r"envoy", 0.90),
    _sig("envoy", "proxy", "x-envoy-upstream-service-time", r"\d+", 0.85),
    _sig("traefik", "proxy", "server", r"Traefik", 0.85),
    _sig("caddy", "proxy", "server", r"Caddy", 0.85),
    _sig("haproxy", "proxy", "via", r"haproxy", 0.80),
    _sig("openresty", "proxy", "server", r"openresty(?:/([\d.]+))?", 0.85, version_group=1),
    _sig("litespeed", "proxy", "server", r"LiteSpeed(?:/([\d.]+))?", 0.85, version_group=1),

    # ---- Load Balancer ----
    _sig("aws_alb", "load_balancer", "x-amzn-trace-id", r"Root=", 0.80),
    _sig("aws_elb", "load_balancer", "server", r"awselb", 0.90),

    # ---- Server / Framework ----
    _sig("iis", "server", "server",
         r"Microsoft-IIS(?:/([\d.]+))?", 0.90, version_group=1),
    _sig("tomcat", "server", "server",
         r"Apache-Coyote(?:/([\d.]+))?", 0.85, version_group=1),
    _sig("gunicorn", "server", "server",
         r"gunicorn(?:/([\d.]+))?", 0.85, version_group=1),
    _sig("waitress", "server", "server", r"waitress", 0.85),
    _sig("uvicorn", "server", "server", r"uvicorn", 0.85),
    _sig("express", "server", "x-powered-by", r"Express", 0.85),
    _sig("php", "server", "x-powered-by",
         r"PHP(?:/([\d.]+))?", 0.90, version_group=1),
    _sig("aspnet", "server", "x-powered-by", r"ASP\\.NET", 0.90),
    _sig("aspnet", "server", "x-aspnet-version",
         r"([\d.]+)", 0.90, version_group=1),
    _sig("rails", "server", "x-runtime", r"[\d.]+", 0.75),
    _sig("django", "server", "x-frame-options",
         r"SAMEORIGIN", 0.15),  # very weak signal; almost all servers send this
    _sig("kestrel", "server", "server", r"Kestrel", 0.85),
    _sig("jetty", "server", "server",
         r"Jetty(?:\(([\d.]+)\))?", 0.85, version_group=1),
    _sig("werkzeug", "server", "server",
         r"Werkzeug(?:/([\d.]+))?", 0.85, version_group=1),
    _sig("tornado", "server", "server",
         r"TornadoServer(?:/([\d.]+))?", 0.85, version_group=1),
    _sig("aiohttp", "server", "server",
         r"Python/aiohttp", 0.85),
    _sig("python_http", "server", "server",
         r"(?:BaseHTTP|CPython|Python)(?:/([\d.]+))?", 0.80, version_group=1),
    _sig("flask", "server", "x-powered-by", r"Flask", 0.85),
    _sig("django", "server", "x-powered-by", r"Django", 0.85),
    _sig("laravel", "server", "x-powered-by", r"Laravel", 0.85),
    _sig("spring_boot", "server", "x-powered-by", r"Spring", 0.80),
    _sig("next_js", "server", "x-powered-by", r"Next\\.js", 0.85),
    _sig("passenger", "server", "x-powered-by", r"Phusion\s+Passenger", 0.85),
    _sig("puma", "server", "x-powered-by", r"Puma", 0.85),
    _sig("fastapi", "server", "server", r"uvicorn|starlette", 0.80),

    # ---- Modern Hosting / PaaS ----
    _sig("vercel", "cdn", "x-vercel-id", r".+", 0.95),
    _sig("vercel", "cdn", "server", r"Vercel", 0.90),
    _sig("vercel", "cdn", "x-vercel-cache", r"(?:HIT|MISS|STALE|PRERENDER)", 0.90),
    _sig("netlify", "cdn", "x-nf-request-id", r".+", 0.95),
    _sig("netlify", "cdn", "server", r"Netlify", 0.90),
    _sig("fly_io", "server", "fly-request-id", r".+", 0.90),
    _sig("fly_io", "server", "server", r"Fly/", 0.85),
    _sig("render", "server", "server", r"Render", 0.85),
    _sig("railway", "server", "server", r"Railway", 0.85),
    _sig("heroku", "server", "via", r"vegur", 0.85),
    _sig("github_pages", "cdn", "server", r"GitHub\.com", 0.90),
    _sig("cloudflare_pages", "cdn", "cf-ray", r".+", 0.50),  # weak: cf-ray is generic CF
    _sig("firebase", "cdn", "x-firebase-hosting-version", r".+", 0.95),
    _sig("aws_amplify", "cdn", "x-amz-apigw-id", r".+", 0.70),
    _sig("deno_deploy", "server", "server", r"deno/", 0.90),

    # ---- WAF (additional) ----
    _sig("fortiweb", "waf", "server", r"FortiWeb", 0.90),
    _sig("netscaler", "waf", "via", r"NS-CACHE", 0.80),
    _sig("netscaler", "waf", "cneonction", r".+", 0.85),
    _sig("datadome", "waf", "x-datadome", r".+", 0.90),
    _sig("datadome", "waf", "server", r"DataDome", 0.90),
]


# ---------------------------------------------------------------------------
# Header-prefix signatures (for WAFs that use header families like x-px-*)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HeaderPrefixSignature:
    """Matches any header whose name starts with a given prefix."""

    component: str
    category: str
    header_prefix: str   # lowercase prefix to match against header names
    confidence: float


HEADER_PREFIX_SIGNATURES: list[HeaderPrefixSignature] = [
    HeaderPrefixSignature("perimeterx", "waf", "x-px-", 0.85),
    HeaderPrefixSignature("aws", "server", "x-amz-", 0.40),
]


# ---------------------------------------------------------------------------
# Header-order fingerprints
# ---------------------------------------------------------------------------
# Servers have characteristic header orderings.  Pattern = ordered tuple of
# the *first N* standard headers (lowercased) in the response.  We compare
# the leading subsequence of well-known headers against these patterns.

@dataclass(frozen=True)
class HeaderOrderSignature:
    """Server identification from response header ordering."""

    component: str
    category: str
    # Ordered tuple of lowercase header names that should appear in this order.
    # Only standard/common headers are used; custom x-* headers are ignored
    # during comparison.
    order: tuple[str, ...]
    confidence: float


# Canonical ordering observed from default configurations.
# Only the relative order of the listed headers matters -- extra headers
# between them are ignored during matching.
HEADER_ORDER_SIGNATURES: list[HeaderOrderSignature] = [
    # nginx: server before date
    HeaderOrderSignature("nginx", "proxy",
                         ("server", "date", "content-type"), 0.45),
    # Apache: date before server
    HeaderOrderSignature("apache", "proxy",
                         ("date", "server", "content-type"), 0.45),
    # IIS: content-type very early, server later
    HeaderOrderSignature("iis", "server",
                         ("content-type", "server", "x-powered-by"), 0.40),
    # Gunicorn: server, date, content-type, content-length
    HeaderOrderSignature("gunicorn", "server",
                         ("server", "date", "content-type", "content-length"), 0.35),
    # Caddy: server first, alt-svc early
    HeaderOrderSignature("caddy", "proxy",
                         ("server", "alt-svc", "content-type"), 0.40),
    # Express (Node): x-powered-by before content-type, no server
    HeaderOrderSignature("express", "server",
                         ("x-powered-by", "content-type"), 0.35),
]


# ---------------------------------------------------------------------------
# Header presence/absence fingerprints
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HeaderPresenceSignature:
    """Identifies servers by which standard headers are present or absent.

    ``present`` headers must all exist; ``absent`` headers must all be missing.
    This catches servers that omit ``Server`` (Go, Deno) or always include
    certain non-standard headers.
    """

    component: str
    category: str
    present: tuple[str, ...]   # lowercase headers that MUST be present
    absent: tuple[str, ...]    # lowercase headers that MUST be absent
    confidence: float


HEADER_PRESENCE_SIGNATURES: list[HeaderPresenceSignature] = [
    # Go net/http: no Server header, has Content-Type and Date
    HeaderPresenceSignature(
        "go_http", "server",
        present=("content-type", "date"),
        absent=("server", "x-powered-by"),
        confidence=0.30,
    ),
    # Deno: no Server header, has content-type
    HeaderPresenceSignature(
        "deno", "server",
        present=("content-type",),
        absent=("server", "x-powered-by"),
        confidence=0.25,
    ),
    # Express: x-powered-by present, no Server header
    HeaderPresenceSignature(
        "express", "server",
        present=("x-powered-by",),
        absent=("server",),
        confidence=0.30,
    ),
    # LiteSpeed: x-litespeed-cache or x-turbo-charged-by present
    HeaderPresenceSignature(
        "litespeed", "proxy",
        present=("x-litespeed-cache",),
        absent=(),
        confidence=0.85,
    ),
    HeaderPresenceSignature(
        "litespeed", "proxy",
        present=("x-turbo-charged-by",),
        absent=(),
        confidence=0.80,
    ),
    # Drupal-specific header
    HeaderPresenceSignature(
        "drupal", "cms",
        present=("x-drupal-cache",),
        absent=(),
        confidence=0.90,
    ),
    # FastAPI / Starlette: x-process-time
    HeaderPresenceSignature(
        "fastapi", "server",
        present=("x-process-time",),
        absent=(),
        confidence=0.75,
    ),
]


# ---------------------------------------------------------------------------
# Cookie-based signatures
# ---------------------------------------------------------------------------

COOKIE_SIGNATURES: list[CookieSignature] = [
    # Load balancers
    CookieSignature("AWSALB", "aws_alb", "load_balancer", 0.90),
    CookieSignature("AWSALBCORS", "aws_alb", "load_balancer", 0.85),
    CookieSignature("SERVERID", "haproxy", "load_balancer", 0.70),

    # CDN
    CookieSignature("cf_clearance", "cloudflare", "cdn", 0.85),
    CookieSignature("__cfduid", "cloudflare", "cdn", 0.80),

    # WAF / Bot protection
    CookieSignature("__cf_bm", "cloudflare_bot", "waf", 0.85),
    CookieSignature("incap_ses_", "imperva", "waf", 0.90, is_prefix=True),
    CookieSignature("visid_incap_", "imperva", "waf", 0.90, is_prefix=True),
    CookieSignature("reese84", "shape_security", "waf", 0.80),
    CookieSignature("datadome", "datadome", "waf", 0.85),
    CookieSignature("FORTIWAFSID", "fortiweb", "waf", 0.90),
    CookieSignature("_px", "perimeterx", "waf", 0.80, is_prefix=True),

    # Server / runtime
    CookieSignature("JSESSIONID", "java", "server", 0.70),
    CookieSignature("PHPSESSID", "php", "server", 0.80),
    CookieSignature("ASP.NET_SessionId", "aspnet", "server", 0.85),
    CookieSignature("rack.session", "ruby_rack", "server", 0.80),
    CookieSignature("_rails_session", "rails", "server", 0.85, is_prefix=True),
    CookieSignature("connect.sid", "express", "server", 0.75),
    CookieSignature("laravel_session", "laravel", "server", 0.85),

    # CMS
    CookieSignature("wp-settings-", "wordpress", "cms", 0.85, is_prefix=True),
    CookieSignature("wordpress_logged_in_", "wordpress", "cms", 0.90, is_prefix=True),
    CookieSignature("Drupal.visitor.", "drupal", "cms", 0.85, is_prefix=True),
    CookieSignature("CONCRETE5", "concrete5", "cms", 0.85),

    # Hosting / PaaS
    CookieSignature("__vercel_live_token", "vercel", "cdn", 0.90),
    CookieSignature("nf_jwt", "netlify", "cdn", 0.80),
]


# ---------------------------------------------------------------------------
# Error page body signatures
# ---------------------------------------------------------------------------

ERROR_PAGE_SIGNATURES: list[ErrorPageSignature] = [
    ErrorPageSignature(
        "nginx", "proxy",
        re.compile(r"<center>\s*nginx(?:/([\d.]+))?\s*</center>", re.IGNORECASE),
        0.85, (400, 599),
    ),
    ErrorPageSignature(
        "apache", "proxy",
        re.compile(r"Apache(?:/([\d.]+))?\s+Server\s+at\s+\S+\s+Port\s+\d+", re.IGNORECASE),
        0.85, (400, 599),
    ),
    ErrorPageSignature(
        "iis", "server",
        re.compile(r"Internet\s+Information\s+Services", re.IGNORECASE),
        0.85, (400, 599),
    ),
    ErrorPageSignature(
        "cloudflare", "cdn",
        re.compile(r"Cloudflare\s+Ray\s+ID|Error\s+10[0-2]\d", re.IGNORECASE),
        0.80, (400, 599),
    ),
    ErrorPageSignature(
        "varnish", "proxy",
        re.compile(r"Guru\s+Meditation|Varnish\s+cache\s+server", re.IGNORECASE),
        0.85, (500, 599),
    ),
    ErrorPageSignature(
        "tomcat", "server",
        re.compile(r"Apache\s+Tomcat(?:/([\d.]+))?", re.IGNORECASE),
        0.85, (400, 599),
    ),
    ErrorPageSignature(
        "spring_boot", "server",
        re.compile(r"Whitelabel\s+Error\s+Page", re.IGNORECASE),
        0.80, (400, 599),
    ),
    ErrorPageSignature(
        "django", "server",
        re.compile(r"Django\s+Debug|You\'re\s+seeing\s+this\s+error\s+because", re.IGNORECASE),
        0.85, (400, 599),
    ),
    ErrorPageSignature(
        "flask", "server",
        re.compile(r"Werkzeug\s+Debugger|Traceback\s+\(most\s+recent\s+call\s+last\)", re.IGNORECASE),
        0.70, (400, 599),
    ),
    ErrorPageSignature(
        "aspnet", "server",
        re.compile(r"Server\s+Error\s+in\s+'/|ASP\.NET\s+is\s+configured", re.IGNORECASE),
        0.85, (400, 599),
    ),
]


# ---------------------------------------------------------------------------
# DNS CNAME patterns for CDN detection
# ---------------------------------------------------------------------------

CNAME_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # (component, category, pattern)
    ("cloudflare", "cdn", re.compile(r"\.cloudflare\.net$", re.IGNORECASE)),
    ("cloudfront", "cdn", re.compile(r"\.cloudfront\.net$", re.IGNORECASE)),
    ("akamai", "cdn", re.compile(r"\.akamai(?:edge|tech|ized)?\.net$", re.IGNORECASE)),
    ("fastly", "cdn", re.compile(r"\.fastly\.net$", re.IGNORECASE)),
    ("azure_cdn", "cdn", re.compile(r"\.azureedge\.net$", re.IGNORECASE)),
    ("incapsula", "waf", re.compile(r"\.incapdns\.net$", re.IGNORECASE)),
    ("sucuri", "waf", re.compile(r"\.sucuri\.net$", re.IGNORECASE)),
    ("stackpath", "cdn", re.compile(r"\.stackpathdns\.com$", re.IGNORECASE)),
    ("edgecast", "cdn", re.compile(r"\.edgecastcdn\.net$", re.IGNORECASE)),
    ("vercel", "cdn", re.compile(r"\.vercel-dns\.com$", re.IGNORECASE)),
    ("netlify", "cdn", re.compile(r"\.netlify\.app$|\.netlify\.com$", re.IGNORECASE)),
    ("fly_io", "cdn", re.compile(r"\.fly\.dev$|\.fly\.io$", re.IGNORECASE)),
    ("heroku", "server", re.compile(r"\.herokuapp\.com$|\.herokussl\.com$", re.IGNORECASE)),
    ("render", "server", re.compile(r"\.onrender\.com$", re.IGNORECASE)),
]


# ---------------------------------------------------------------------------
# Topology layer ordering
# ---------------------------------------------------------------------------

# Lower number = closer to client, higher = closer to origin
CATEGORY_LAYER_ORDER: dict[str, int] = {
    "cdn": 0,
    "waf": 1,
    "load_balancer": 2,
    "proxy": 3,
    "server": 4,
    "cms": 5,
}
