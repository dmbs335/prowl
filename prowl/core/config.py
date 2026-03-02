"""Crawl configuration using Pydantic Settings."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings

# Common noise URL patterns: marketing, static assets, tracking params.
# Applied automatically when noise_filter=True.
BUILTIN_NOISE_PATTERNS: list[str] = [
    r".*/blog/.*",
    r".*/careers/.*",
    r".*/press/.*",
    r".*/customer-stories/.*",
    r".*/events/.*",
    r".*/newsletter/.*",
    r".*/podcast/.*",
    r".*/webinar/.*",
    r".*/cdn-cgi/.*",
    r".*/static/.*",
    r".*/assets/.*",
    r".*/_next/static/.*",
    r".*/_next/image/.*",
    r".*/wp-content/uploads/.*",
    r".*\?utm_.*",
    r".*\?fbclid=.*",
    r".*\?gclid=.*",
]


class CrawlConfig(BaseSettings):
    """Main configuration for a crawl session."""

    model_config = {"env_prefix": "PROWL_"}

    # Target
    target_url: str = ""
    scope_patterns: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(
        default_factory=lambda: [
            r".*\.(jpg|jpeg|png|gif|svg|ico|woff2?|ttf|eot|css)(\?.*)?$",
            r".*\.(mp4|mp3|avi|mov|pdf|zip|tar|gz)(\?.*)?$",
        ]
    )

    # Crawl behavior
    max_depth: int = 10
    max_requests: int = 10000
    concurrency: int = 10
    request_delay: float = 0.0
    request_timeout: float = 30.0
    user_agent: str = "Prowl/0.1"
    follow_redirects: bool = True

    # Backend
    backend: str = "hybrid"
    headless: bool = True

    # Modules to run (empty = all)
    modules: list[str] = Field(default_factory=list)

    # Auth
    auth_roles: list[dict] = Field(default_factory=list)

    # Output
    output_dir: str = "./prowl-output"
    output_formats: list[str] = Field(default_factory=lambda: ["json", "markdown"])

    # Dashboard
    dashboard: bool = False
    dashboard_port: int = 8484

    # LLM (optional)
    llm_model: str = ""
    llm_api_key: str = ""

    # Bruteforce
    wordlist_dirs: str = ""
    wordlist_params: str = ""
    bruteforce_extensions: list[str] = Field(
        default_factory=lambda: [".php", ".asp", ".aspx", ".jsp", ".html", ".js", ".json"]
    )
    bruteforce_threads: int = 20

    # JS Analysis
    js_max_file_size: int = 5_000_000
    js_ast_enabled: bool = True
    js_analyze_inline: bool = True

    # Parameter Discovery
    param_probe_methods: bool = True
    param_probe_content_types: bool = True
    param_probe_locations: list[str] = Field(
        default_factory=lambda: ["query", "body_form", "body_json", "header", "cookie"]
    )
    param_max_endpoints: int = 100

    # GraphQL
    graphql_introspection_depth: int = 3
    graphql_extract_input_types: bool = True

    # Approval guardrail
    approve_unsafe: bool = True  # require user approval for POST/PUT/DELETE/PATCH

    # Exploration strategy
    coverage_guided: bool = True
    seed_scheduling: bool = True
    url_template_inference: bool = True
    hindsight_feedback: bool = True
    saturation_detection: bool = True
    saturation_threshold: float = 0.02
    saturation_window: int = 200
    smart_form_submission: bool = True
    adaptive_rate_limit: bool = True

    # Infrastructure mapping
    infra_mapping_enabled: bool = True
    infra_dns_lookup: bool = True

    # Noise filter
    noise_filter: bool = True
    noise_patterns: list[str] = Field(default_factory=list)

    # Auto-merge rules: template_pattern -> max_per_template
    auto_merge_rules: dict[str, int] = Field(default_factory=dict)

    # Focus patterns: URL substrings to boost priority
    focus_patterns: list[str] = Field(default_factory=list)
    focus_boost: int = 10

    # Passive
    use_wayback: bool = True
    use_commoncrawl: bool = False
