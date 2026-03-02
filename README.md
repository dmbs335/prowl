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

## Pipeline

The orchestrator runs **11 phases** in dependency order, parallelizing where possible:

```
passive (s6)
    └──► active_crawl (s1, s2)
              └──► fingerprinting (s9, s10)
              │         └──► auth_crawl (s7)
              └──► js_analysis (s4)
                        └──► api_discovery (s5)
                        └──► state_transitions (s8)
                                  └──► deep_crawl (s1 re-run)
                                            └──► param_discovery (s3)
                                                      └──► classification (s11, s12)
                                                                └──► reporting (s13)
```

Between phases, the **quality playbook** hooks into `PHASE_COMPLETED` signals,
validates engine state (coverage growth, auth success, error rates),
and triggers corrective actions on failures before the next phase starts.

## Modules

13 discovery modules:

| Phase | Module | Description |
|-------|--------|-------------|
| Passive | **s6** Passive Collection | Wayback Machine, CommonCrawl, OTX harvesting with path-tree dedup |
| Active | **s1** Active Spider | BFS link-following with POR, smart form submission, saturation stop |
| Active | **s2** Dir Bruteforce | Wordlist-based hidden path discovery, backup file suffix probing |
| Fingerprint | **s9** Infra Mapper | CDN, WAF, reverse proxy detection (zero extra requests) |
| Fingerprint | **s10** Tech Fingerprinter | CMS, framework, JS library detection (signature-based) |
| Analysis | **s4** JS Analysis | Tree-sitter AST endpoint/secret extraction (regex fallback) |
| API | **s5** API Discovery | OpenAPI, GraphQL introspection, WSDL |
| State | **s7** Auth Crawl | Multi-role session management, coverage-guided auth re-crawl |
| State | **s8** State Transitions | Application state machine mapping, auth boundary detection |
| Params | **s3** Param Discovery | 4-phase parameter probing (query, body-form, body-json, header, cookie) + method/content-type probing |
| Classify | **s11** Input Classifier | Reflection detection, type inference, risk scoring |
| Auth | **s12** Auth Boundary | Access control boundary detection, access matrix |
| Report | **s13** Report Generator | JSON, Markdown, HTML, Burp XML, Postman, OpenAPI output |

## Exploration Strategy

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

### Adaptive Rate Limiter (AIAD)

Server rate limits are a fixed wall, not variable like network congestion.
Prowl uses Additive-Increase / Additive-Decrease instead of TCP AIMD:

```
429 hit  →  delay += 0.05s   (slow down a little)
10 OK    →  delay -= 0.01s   (speed up a little)
```

Converges to just below the server limit with minimal oscillation.
A global leaky bucket ensures inter-request pacing across all workers.

### Coverage Features

| Feature | Description |
|---------|-------------|
| **5D coverage tuple** | (template, method, status_bucket, struct_hash, auth_role) |
| **State-aware dedup** | Same URL + different auth_role = different request |
| **Parameter-aware templates** | `/api/users?role=` vs `/api/users?sort=` are distinct |
| **Saturation detection** | Sliding window (deque); stops when discovery rate < threshold |
| **Hindsight feedback** | 403 = auth boundary, 405 = method hint, 500 = server processing |
| **Smart form submission** | Auto-fills search/filter forms with safe values |
| **Adaptive rate limiting** | AIAD leaky-bucket; auto-converges to server limit |

## Intervention & Approval

Prowl includes a human-in-the-loop safety layer:

- **Approval gates** -- POST, PUT, DELETE, PATCH requests require explicit approval by default (`--approve-unsafe` to auto-approve)
- **Intervention types** -- LOGIN, CAPTCHA, TWO_FA, MANUAL with state machine (PENDING → IN_PROGRESS → RESOLVED/EXPIRED)
- **Interactive mode** -- `-i` flag enables terminal-based intervention for login flows and CAPTCHAs
- **Browser bridge** -- Playwright-based browser interaction during intervention

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
# Username/password login
prowl crawl https://target.example.com \
  --auth-user admin@test.com --auth-pass secret \
  --login-url https://target.example.com/login

# Raw HTTP request file (Burp/devtools export)
prowl crawl https://target.example.com \
  --auth-request ./login-request.txt
```

Prowl handles login form detection, CSRF token extraction, session management,
and coverage-guided auth re-crawl (auth boundaries from HindsightFeedback are
re-crawled first).

## CLI

```
prowl crawl <TARGET>     Main crawl command
prowl playbook <DIR>     Post-hoc quality analysis on saved crawl output
prowl version            Version info
```

### Key Options

| Option | Default | Description |
|--------|---------|-------------|
| `-d` / `--depth` | 10 | Maximum crawl depth |
| `-c` / `--concurrency` | 10 | Concurrent workers |
| `--max-requests` | 10000 | Maximum total requests |
| `--request-delay` | 0.0 | Delay between requests (seconds) |
| `-b` / `--backend` | http | Backend engine (http, browser, hybrid) |
| `-o` / `--output` | prowl-output/ | Output directory |
| `-f` / `--format` | json | Output formats (json, markdown, html, burp, postman, openapi) |
| `-m` / `--module` | all | Comma-separated module filter |
| `-i` / `--interactive` | false | Interactive intervention mode |
| `--approve-unsafe` | false | Auto-approve unsafe HTTP methods |
| `--dashboard` | false | Enable real-time web UI |
| `--dashboard-port` | 8484 | Dashboard port |
| `--headless` | true | Headless browser mode |
| `--llm-model` | - | LLM model for smart strategies |
| `--llm-api-key` | - | LLM API key |
| `--wordlist-dirs` | built-in | Directory bruteforce wordlist |
| `--wordlist-params` | built-in | Parameter discovery wordlist |

### Coverage & Exploration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--coverage-guided` | true | AFL-style coverage tracking |
| `--seed-scheduling` | true | Thompson Sampling priority |
| `--saturation-detection` | true | Auto-stop on coverage plateau |
| `--saturation-threshold` | 0.02 | Discovery rate threshold (2%) |
| `--saturation-window` | 200 | Sliding window size |
| `--smart-form-submission` | true | Auto-fill search/filter forms |
| `--hindsight-feedback` | true | Learn from non-2xx responses |
| `--url-template-inference` | true | Concolic URL mutation |

## REST API

When the dashboard is enabled, a full REST API is available for programmatic control:

```
POST   /api/crawl/start          Start a new crawl
GET    /api/crawl/status          Current crawl status
POST   /api/crawl/pause           Pause crawl
POST   /api/crawl/resume          Resume crawl
POST   /api/crawl/stop            Stop crawl
GET    /api/endpoints             List discovered endpoints
GET    /api/parameters            List discovered parameters
GET    /api/secrets               List discovered secrets
GET    /api/modules               Module states
GET    /api/sitemap               Sitemap tree
GET    /api/reports               Generated reports
WS     /ws                        Real-time event stream
```

## Output

```
prowl-output/
  endpoints.jsonl      # streaming endpoint data
  secrets.jsonl        # discovered secrets
  report.json          # full attack surface report
  report.md            # human-readable summary
  report.html          # self-contained HTML report
  report.xml           # Burp Suite import format
  postman.json         # Postman collection export
  openapi.json         # OpenAPI/Swagger schema
  transactions.db      # full HTTP traffic (SQLite)
```

Select formats with `-f`:

```bash
prowl crawl https://target.example.com -f json,markdown,html,burp,postman,openapi
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
- Approval queue for unsafe requests
- WebSocket event stream

## LLM Integration (Optional)

```bash
pip install -e ".[llm]"
prowl crawl https://target.example.com --llm-model gpt-4o-mini --llm-api-key sk-...
```

5 pluggable strategies:

| Strategy | Description |
|----------|-------------|
| API Schema Inferrer | Infers API structure from partial observations |
| Content Classifier | Classifies response content for security relevance |
| Form Filler | Generates context-aware form input values |
| Link Prioritizer | Prioritizes links by security interest |
| Param Generator | Generates parameter names and values for probing |

## Dependencies

**Core:**
- **httpx[http2]** -- async HTTP/2 client
- **lxml** -- HTML parsing (XPath-based link/form extraction)
- **pydantic** / **pydantic-settings** -- data models & config
- **typer** / **rich** -- CLI
- **aiofiles** / **aiosqlite** -- async file & transaction persistence
- **tree-sitter** / **tree-sitter-javascript** -- JS AST analysis

**Optional:**
- `playwright` -- browser backend (`pip install -e ".[browser]"`)
- `litellm` -- LLM strategies (`pip install -e ".[llm]"`)
- `fastapi` / `uvicorn` -- dashboard & REST API (`pip install -e ".[dashboard]"`)

## License

MIT
