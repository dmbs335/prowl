# Prowl

Coverage-guided web attack surface discovery engine.

Prowl treats web crawling as **state space exploration**, not URL graph traversal.
It combines AFL-style coverage tracking, Thompson Sampling frontier selection,
and hindsight feedback to systematically map an application's attack surface
across authentication states, parameter spaces, and API boundaries.

## Architecture

```
                          CrawlConfig
                              |
                    PipelineOrchestrator
                     /        |        \
               Phase 1    Phase 2    Phase 3 ...
              (passive)   (active)   (fingerprint)
                 |          |   \        |    \
               [s6]      [s1] [s2]    [s9] [s10]  ...
                 \         |   /        \    /
                  \        |  /          \  /
                   CrawlEngine ─── SignalBus
                  /    |    \         |
            Queue  Coverage  Dedup  Signals → modules
              |      |         |
           Backend  Bitmap   Fingerprint
           /  |  \
        HTTP BRW HYBRID
              |
        TransactionStore (SQLite)
```

### Core Loop

```
Queue → Worker → Execute → Coverage Update → Frontier Priority Update → Queue
                                  |                     |
                           Saturation? → Stop    Thompson Sampling
                                                   (Beta posterior)
```

Each request produces a **5-dimensional coverage tuple**:

```
(url_template, method, status_bucket, structural_hash, auth_role)
```

New tuples = new coverage = worth exploring further.
When the discovery rate drops below threshold (default 2% over 200 requests),
crawling stops automatically.

## Quick Start

```bash
# Install
pip install -e ".[all]"

# Basic crawl
prowl crawl https://target.example.com

# With options
prowl crawl https://target.example.com \
  -d 5 \                    # max depth
  -c 20 \                   # concurrency
  -o ./output \             # output directory
  -f json,markdown,html \   # output formats
  --dashboard               # enable web UI at :8484
```

## Modules

13 discovery modules execute in a dependency-ordered pipeline:

| Phase | Module | Description |
|-------|--------|-------------|
| Passive | **s6** Passive Collection | Wayback Machine, CommonCrawl, OTX harvesting with path-tree dedup |
| Active | **s1** Active Spider | BFS link-following with POR, smart form submission, saturation stop |
| Active | **s2** Dir Bruteforce | Wordlist-based hidden path discovery |
| Fingerprint | **s9** Infra Mapper | CDN, WAF, reverse proxy detection (zero extra requests) |
| Fingerprint | **s10** Tech Fingerprinter | CMS, framework, JS library detection |
| Analysis | **s4** JS Analysis | Tree-sitter AST endpoint/secret extraction |
| API | **s5** API Discovery | OpenAPI, GraphQL introspection, WSDL |
| State | **s7** Auth Crawl | Multi-role session management |
| State | **s8** State Transitions | Application state machine mapping, auth re-crawl |
| Params | **s3** Param Discovery | Multi-location parameter probing (query, body, header, cookie) |
| Classify | **s11** Input Classifier | Reflection detection, type inference, risk scoring |
| Auth | **s12** Auth Boundary | Access control boundary detection, access matrix |
| Report | **s13** Report Generator | JSON, Markdown, HTML, Burp XML output |

## Exploration Strategy

Prowl's exploration is built on three algorithms from the formal CS state space exploration literature:

### Thompson Sampling (Frontier Selection)

Each URL template is a multi-armed bandit arm with a Beta(alpha, beta) posterior.
Templates that produce new coverage get sampled more often.
Heuristic scoring (security-relevant patterns, rare-edge bonus) dominates during
cold-start; Thompson takes over as data accumulates.

```
arm    = URL template (/api/users/{id})
reward = 1 if new coverage, 0 otherwise
select = argmax(sample(Beta(alpha_i, beta_i)))
```

### AFLFast Power Schedule (Energy Allocation)

Productive templates (those generating new coverage) receive more mutation budget.
Exhausted templates get fewer mutations, saving request budget for exploration.

### Partial Order Reduction (Redundant Exploration Pruning)

Independent GET requests at the same depth sharing a path prefix are collapsed:
only one representative gets full priority, the rest are deprioritized.

### Coverage Features

| Feature | Description |
|---------|-------------|
| **5D coverage tuple** | (template, method, status_bucket, struct_hash, auth_role) |
| **State-aware dedup** | Same URL + different auth_role = different request |
| **Parameter-aware templates** | `/api/users?role=` vs `/api/users?sort=` are distinct |
| **Saturation detection** | Sliding window; stops when discovery rate < threshold |
| **Hindsight feedback** | 403 = auth boundary, 405 = method hint, 500 = server processing |
| **Smart form submission** | Auto-fills search/filter forms with safe values |

## Backends

| Backend | Engine | Use Case |
|---------|--------|----------|
| `http` | httpx (HTTP/2) | Fast, lightweight |
| `browser` | Playwright | JS-rendered pages |
| `hybrid` | Both | HTTP default, browser fallback for dynamic content |

```bash
prowl crawl https://target.example.com -b hybrid --headless
```

## Authentication

```bash
# Via config or CLI
prowl crawl https://target.example.com \
  --auth-role '{"name": "admin", "username": "admin@test.com", "password": "pass"}'
```

Prowl handles login form detection, CSRF token extraction, session management,
and coverage-guided auth re-crawl (auth boundaries from HindsightFeedback are
re-crawled first).

## Output

```
prowl-output/
  endpoints.jsonl      # streaming endpoint data
  secrets.jsonl        # discovered secrets
  report.json          # full attack surface report
  report.md            # human-readable summary
  report.html          # self-contained HTML report
  transactions.db      # full HTTP traffic (SQLite)
```

## Dashboard

```bash
prowl crawl https://target.example.com --dashboard --dashboard-port 8484
```

Real-time web UI at `http://127.0.0.1:8484` with:
- Engine stats (requests, coverage, saturation)
- Module states
- Sitemap tree
- Endpoint browser
- WebSocket event stream

## Configuration

All options can be set via CLI flags, environment variables (`PROWL_` prefix),
or a config file.

### Key Options

| Option | Default | Description |
|--------|---------|-------------|
| `max_depth` | 10 | Maximum crawl depth |
| `max_requests` | 10000 | Maximum total requests |
| `concurrency` | 10 | Concurrent workers |
| `request_delay` | 0.0 | Delay between requests (seconds) |
| `coverage_guided` | true | Enable AFL-style coverage tracking |
| `seed_scheduling` | true | Enable Thompson Sampling priority |
| `saturation_detection` | true | Auto-stop on coverage plateau |
| `saturation_threshold` | 0.02 | Discovery rate threshold (2%) |
| `saturation_window` | 200 | Sliding window size |
| `smart_form_submission` | true | Auto-fill search/filter forms |
| `hindsight_feedback` | true | Learn from non-2xx responses |
| `url_template_inference` | true | Concolic URL mutation |

## LLM Integration (Optional)

```bash
pip install -e ".[llm]"
prowl crawl https://target.example.com --llm-model gpt-4o-mini --llm-api-key sk-...
```

5 pluggable strategies: API schema inference, content classification,
form filling, link prioritization, parameter generation.

## Dependencies

- **httpx[http2]** -- async HTTP client
- **beautifulsoup4** -- HTML parsing
- **pydantic** / **pydantic-settings** -- data models & config
- **typer** / **rich** -- CLI
- **aiosqlite** -- transaction persistence
- **tree-sitter** / **tree-sitter-javascript** -- JS AST analysis

Optional: `playwright` (browser), `litellm` (LLM), `fastapi`/`uvicorn` (dashboard).

## License

MIT
