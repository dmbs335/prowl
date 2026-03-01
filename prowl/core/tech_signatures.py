"""Application-layer technology fingerprint signatures.

Detects frameworks, CMS, JS libraries, and server-side languages by
analysing response bodies (HTML meta/script/link tags, inline patterns),
URL paths, and response headers not covered by infra_signatures.

Follows the Wappalyzer categorisation model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class BodySignature:
    """Regex matched against decoded response body."""

    component: str
    category: str       # "cms" | "framework" | "js_library" | "analytics" | "font" | "lang"
    pattern: re.Pattern[str]
    confidence: float
    version_group: int = 0  # capture group for version


@dataclass(frozen=True)
class MetaSignature:
    """Matches <meta name="..." content="..."> tags."""

    component: str
    category: str
    meta_name: str          # lowercase meta name attribute
    content_pattern: re.Pattern[str]
    confidence: float
    version_group: int = 0


@dataclass(frozen=True)
class ScriptSrcSignature:
    """Matches <script src="..."> paths."""

    component: str
    category: str
    pattern: re.Pattern[str]
    confidence: float
    version_group: int = 0


@dataclass(frozen=True)
class URLPathSignature:
    """Matches request URL paths to infer technology."""

    component: str
    category: str
    pattern: re.Pattern[str]
    confidence: float


# ---------------------------------------------------------------------------
# Meta tag signatures
# ---------------------------------------------------------------------------

META_SIGNATURES: list[MetaSignature] = [
    MetaSignature("wordpress", "cms", "generator",
                  re.compile(r"WordPress\s*([\d.]+)?", re.I), 0.95, 1),
    MetaSignature("drupal", "cms", "generator",
                  re.compile(r"Drupal\s*([\d.]+)?", re.I), 0.95, 1),
    MetaSignature("joomla", "cms", "generator",
                  re.compile(r"Joomla", re.I), 0.95),
    MetaSignature("hugo", "cms", "generator",
                  re.compile(r"Hugo\s*([\d.]+)?", re.I), 0.90, 1),
    MetaSignature("ghost", "cms", "generator",
                  re.compile(r"Ghost\s*([\d.]+)?", re.I), 0.90, 1),
    MetaSignature("shopify", "cms", "generator",
                  re.compile(r"Shopify", re.I), 0.95),
    MetaSignature("wix", "cms", "generator",
                  re.compile(r"Wix\.com", re.I), 0.95),
    MetaSignature("squarespace", "cms", "generator",
                  re.compile(r"Squarespace", re.I), 0.95),
    MetaSignature("gatsby", "framework", "generator",
                  re.compile(r"Gatsby\s*([\d.]+)?", re.I), 0.90, 1),
    MetaSignature("next_js", "framework", "generator",
                  re.compile(r"Next\.js", re.I), 0.90),
    MetaSignature("nuxt", "framework", "generator",
                  re.compile(r"Nuxt", re.I), 0.90),
]


# ---------------------------------------------------------------------------
# Script src signatures  (<script src="...">)
# ---------------------------------------------------------------------------

SCRIPT_SRC_SIGNATURES: list[ScriptSrcSignature] = [
    # JS frameworks / libraries
    ScriptSrcSignature("jquery", "js_library",
                       re.compile(r"jquery[.-]?([\d.]+)?(?:\.min)?\.js", re.I), 0.90, 1),
    ScriptSrcSignature("react", "js_library",
                       re.compile(r"react(?:\.production|\.development)?[.-]?([\d.]+)?(?:\.min)?\.js", re.I), 0.85, 1),
    ScriptSrcSignature("vue", "js_library",
                       re.compile(r"vue(?:\.global|\.runtime)?[.-]?([\d.]+)?(?:\.min)?\.js", re.I), 0.85, 1),
    ScriptSrcSignature("angular", "js_library",
                       re.compile(r"angular(?:\.min)?\.js", re.I), 0.85),
    ScriptSrcSignature("angular", "js_library",
                       re.compile(r"(?:main|polyfills|runtime)\.[a-f0-9]+\.js", re.I), 0.40),
    ScriptSrcSignature("bootstrap", "js_library",
                       re.compile(r"bootstrap[.-]?([\d.]+)?(?:\.bundle)?(?:\.min)?\.js", re.I), 0.85, 1),
    ScriptSrcSignature("lodash", "js_library",
                       re.compile(r"lodash(?:\.min)?\.js", re.I), 0.85),
    ScriptSrcSignature("moment", "js_library",
                       re.compile(r"moment(?:\.min)?\.js", re.I), 0.80),
    ScriptSrcSignature("axios", "js_library",
                       re.compile(r"axios(?:\.min)?\.js", re.I), 0.80),
    ScriptSrcSignature("underscore", "js_library",
                       re.compile(r"underscore(?:\.min)?\.js", re.I), 0.80),
    ScriptSrcSignature("backbone", "js_library",
                       re.compile(r"backbone(?:\.min)?\.js", re.I), 0.80),
    ScriptSrcSignature("ember", "js_library",
                       re.compile(r"ember(?:\.min)?\.js", re.I), 0.85),
    ScriptSrcSignature("svelte", "js_library",
                       re.compile(r"svelte", re.I), 0.70),
    ScriptSrcSignature("htmx", "js_library",
                       re.compile(r"htmx(?:\.min)?\.js", re.I), 0.85),
    ScriptSrcSignature("alpine", "js_library",
                       re.compile(r"alpine(?:\.min)?\.js|cdn\.jsdelivr\.net/npm/alpinejs", re.I), 0.85),

    # Analytics / tracking
    ScriptSrcSignature("google_analytics", "analytics",
                       re.compile(r"google-analytics\.com/(?:analytics|ga)\.js|googletagmanager\.com/gtag", re.I), 0.90),
    ScriptSrcSignature("google_tag_manager", "analytics",
                       re.compile(r"googletagmanager\.com/gtm\.js", re.I), 0.90),
    ScriptSrcSignature("hotjar", "analytics",
                       re.compile(r"static\.hotjar\.com", re.I), 0.90),
    ScriptSrcSignature("segment", "analytics",
                       re.compile(r"cdn\.segment\.com/analytics\.js", re.I), 0.90),
    ScriptSrcSignature("facebook_pixel", "analytics",
                       re.compile(r"connect\.facebook\.net/.*/fbevents\.js", re.I), 0.90),

    # CMS
    ScriptSrcSignature("wordpress", "cms",
                       re.compile(r"/wp-(?:includes|content)/", re.I), 0.90),
    ScriptSrcSignature("drupal", "cms",
                       re.compile(r"/(?:modules|sites/all)/.*\.js|drupal\.js", re.I), 0.80),
    ScriptSrcSignature("shopify", "cms",
                       re.compile(r"cdn\.shopify\.com", re.I), 0.90),
]


# ---------------------------------------------------------------------------
# Body pattern signatures (HTML content)
# ---------------------------------------------------------------------------

BODY_SIGNATURES: list[BodySignature] = [
    # ---- CMS ----
    BodySignature("wordpress", "cms",
                  re.compile(r"/wp-content/|/wp-includes/|wp-json", re.I), 0.85),
    BodySignature("drupal", "cms",
                  re.compile(r'jQuery\.extend\(Drupal\.settings|drupal\.org', re.I), 0.85),
    BodySignature("joomla", "cms",
                  re.compile(r"/media/jui/|/components/com_", re.I), 0.80),
    BodySignature("magento", "cms",
                  re.compile(r"(?:Mage\.Cookies|/skin/frontend/|mage/cookies)", re.I), 0.80),
    BodySignature("shopify", "cms",
                  re.compile(r"Shopify\.theme|cdn\.shopify\.com", re.I), 0.85),
    BodySignature("wix", "cms",
                  re.compile(r"_wixCIDX|wix-code-sdk|X-Wix-", re.I), 0.85),

    # ---- Frameworks (server-side clues in HTML) ----
    BodySignature("django", "framework",
                  re.compile(r'csrfmiddlewaretoken|__admin_media_prefix__', re.I), 0.80),
    BodySignature("rails", "framework",
                  re.compile(r'name="csrf-token"|name="authenticity_token"', re.I), 0.80),
    BodySignature("laravel", "framework",
                  re.compile(r'name="_token"|laravel_session', re.I), 0.75),
    BodySignature("spring", "framework",
                  re.compile(r'name="_csrf"|org\.springframework', re.I), 0.75),
    BodySignature("aspnet_webforms", "framework",
                  re.compile(r'__VIEWSTATE|__EVENTVALIDATION|aspnetForm', re.I), 0.90),
    BodySignature("aspnet_blazor", "framework",
                  re.compile(r'_blazor|blazor\.webassembly\.js|blazor\.server\.js', re.I), 0.90),
    BodySignature("next_js", "framework",
                  re.compile(r'__NEXT_DATA__|/_next/static/', re.I), 0.90),
    BodySignature("nuxt", "framework",
                  re.compile(r'__NUXT__|/_nuxt/', re.I), 0.90),
    BodySignature("gatsby", "framework",
                  re.compile(r'___gatsby|gatsby-', re.I), 0.85),
    BodySignature("remix", "framework",
                  re.compile(r'__remixContext|__remix', re.I), 0.85),
    BodySignature("svelte_kit", "framework",
                  re.compile(r'__sveltekit|__data\.json', re.I), 0.85),

    # ---- JS frameworks (runtime markers) ----
    BodySignature("react", "js_library",
                  re.compile(r'data-reactroot|_reactRootContainer|__REACT_DEVTOOLS', re.I), 0.80),
    BodySignature("angular", "js_library",
                  re.compile(r'ng-version=|ng-app=|ng-controller=|\[ngClass\]', re.I), 0.85),
    BodySignature("vue", "js_library",
                  re.compile(r'data-v-[a-f0-9]|v-cloak|v-bind:|Vue\.component', re.I), 0.80),
    BodySignature("svelte", "js_library",
                  re.compile(r'svelte-[a-z0-9]|__svelte', re.I), 0.80),
    BodySignature("ember", "js_library",
                  re.compile(r'data-ember-|ember-view|EmberENV', re.I), 0.85),
    BodySignature("backbone", "js_library",
                  re.compile(r'Backbone\.Model|Backbone\.View', re.I), 0.80),
    BodySignature("htmx", "js_library",
                  re.compile(r'hx-get=|hx-post=|hx-trigger=|hx-swap=', re.I), 0.85),
    BodySignature("alpine", "js_library",
                  re.compile(r'x-data=|x-bind:|x-on:|@click=', re.I), 0.70),

    # ---- CSS frameworks (via class names / link tags) ----
    BodySignature("bootstrap", "css_framework",
                  re.compile(r'class="[^"]*\b(?:container-fluid|col-(?:xs|sm|md|lg|xl)-\d+|navbar-toggler)\b', re.I), 0.70),
    BodySignature("tailwind", "css_framework",
                  re.compile(r'class="[^"]*\b(?:flex|grid|text-(?:sm|lg|xl)|bg-(?:blue|red|green)-\d{3}|p-\d|mt-\d)\b', re.I), 0.50),
    BodySignature("materialize", "css_framework",
                  re.compile(r'materialize(?:\.min)?\.css|class="[^"]*materialize', re.I), 0.80),
    BodySignature("bulma", "css_framework",
                  re.compile(r'bulma(?:\.min)?\.css', re.I), 0.85),
    BodySignature("foundation", "css_framework",
                  re.compile(r'foundation(?:\.min)?\.css', re.I), 0.85),

    # ---- Font / CDN services ----
    BodySignature("google_fonts", "font",
                  re.compile(r'fonts\.googleapis\.com', re.I), 0.90),
    BodySignature("font_awesome", "font",
                  re.compile(r'font-awesome|fontawesome', re.I), 0.85),

    # ---- Security tokens (framework inference) ----
    BodySignature("recaptcha", "security",
                  re.compile(r'google\.com/recaptcha|g-recaptcha|grecaptcha', re.I), 0.90),
    BodySignature("hcaptcha", "security",
                  re.compile(r'hcaptcha\.com|h-captcha', re.I), 0.90),
    BodySignature("turnstile", "security",
                  re.compile(r'challenges\.cloudflare\.com/turnstile', re.I), 0.90),
]


# ---------------------------------------------------------------------------
# URL path signatures  (matched against request URLs)
# ---------------------------------------------------------------------------

URL_PATH_SIGNATURES: list[URLPathSignature] = [
    URLPathSignature("wordpress", "cms",
                     re.compile(r"/wp-(?:admin|login|content|includes|json)/", re.I), 0.90),
    URLPathSignature("drupal", "cms",
                     re.compile(r"/(?:node/\d+|admin/structure|sites/default/files)", re.I), 0.80),
    URLPathSignature("joomla", "cms",
                     re.compile(r"/administrator/|/components/com_", re.I), 0.80),
    URLPathSignature("magento", "cms",
                     re.compile(r"/(?:checkout/cart|customer/account|catalog/product)", re.I), 0.60),
    URLPathSignature("spring_actuator", "framework",
                     re.compile(r"/actuator(?:/health|/info|/env|/beans)?$", re.I), 0.85),
    URLPathSignature("laravel", "framework",
                     re.compile(r"/telescope|/horizon|/_debugbar", re.I), 0.80),
    URLPathSignature("rails", "framework",
                     re.compile(r"/rails/info/routes|/rails/mailers", re.I), 0.85),
    URLPathSignature("django", "framework",
                     re.compile(r"/__debug__/|/admin/login/", re.I), 0.70),
    URLPathSignature("graphql", "api",
                     re.compile(r"/graphql|/graphiql|/playground", re.I), 0.80),
    URLPathSignature("swagger", "api",
                     re.compile(r"/swagger-ui|/api-docs|/openapi\.json", re.I), 0.85),
    URLPathSignature("elmah", "framework",
                     re.compile(r"/elmah\.axd", re.I), 0.90),
    URLPathSignature("phpmyadmin", "tool",
                     re.compile(r"/phpmyadmin|/pma", re.I), 0.90),
]
