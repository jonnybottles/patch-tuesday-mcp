# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**patch-tuesday-mcp** is a Python MCP server exposing a single tool, `msrc_search`, that queries the public MSRC CVRF v3 API (Microsoft Patch Tuesday security updates), enriched with FIRST.org EPSS scores and the CISA KEV catalog. No API keys anywhere. Ships two ways: a PyPI package (stdio transport for local MCP clients) and a Docker image running HTTP transport on Azure Container Apps.

## Commands

```bash
pip install -e ".[dev]"       # or: uv pip install -e ".[dev]" (repo .venv is uv-managed, has no pip)
pytest                        # offline suite — mocked feeds, fast, no network
pytest --run-live             # additionally runs tests/test_live_smoke.py against real MSRC/EPSS/KEV APIs
pytest -m endpoint --endpoint-url=http://localhost:8000 --endpoint-burst   # endpoint suite vs a running local container
pytest -m "endpoint and not endpoint_burst" --endpoint-url=<hosted URL>    # endpoint suite vs the hosted ACA endpoint (never --endpoint-burst: shared rate-limit bucket)
pytest tests/test_tools.py    # single file
pytest --cov=patch_tuesday_mcp  # coverage; CI gates at >= 90%
ruff check .                  # lint (line-length 100, rules E/F/I/W)
uv lock                       # refresh uv.lock after changing dependencies OR the project version
```

On Windows in this repo use `.venv/Scripts/python -m pytest` etc. — the venv was created by uv and `pip` is not installed in it.

## Architecture

- `src/patch_tuesday_mcp/server.py` — FastMCP app + `main()`. stdio by default; `MCP_TRANSPORT=http` serves `/mcp` + `/health` with the ASGI app from `build_http_app()` (middleware innermost→outermost: client-cleanup lifespan wrapper → body limit → rate limit → CORS; the factory exists so tests can exercise the exact production composition). uvicorn runs with `MCP_LIMIT_CONCURRENCY` (default 40) and `timeout_keep_alive=15`; `MCP_LOG_LEVEL` controls root logging (stderr). The startup settings log reports pinned trusted proxies as a count only — never echo `MCP_TRUSTED_PROXIES` values (CodeQL flags clear-text logging of them; issue #10, pinned by a test).
- `tools/search.py` — the single `msrc_search` tool and all its routing: CVE fast path (cross-month lookup), KB fast path (single KB or a batched `kb=[...]` list capped at `MAX_KB_BATCH = 30` returning grouped per-KB results, with optional supersedence chain walk and optional `include_known_issues=True` known-issues decoration — attached even to `not_found`/`upstream` KB results since preview-only updates aren't in MSRC data, but never to `invalid_input`), `list_months=True` catalog fast path, single-month filtered search, and historical trend search (`months_back` / `start_month`+`end_month`, capped at `MAX_TREND_MONTHS = 12`). A top-level catch-all converts unexpected exceptions to `error_kind="internal"` — `msrc_search` never raises.
- `tools/formatters.py` — optional `format="markdown"|"csv"` triage renderings; JSON is always included and unchanged.
- `tools/profiles.py` — named product watchlists for `msrc_search` (`product_profile=`, plus ad-hoc `products=[...]`/`product_families=[...]`). Built-ins (`identity-core`, `endpoint`, `server-infrastructure`) merged under a `MSRC_PROFILES_PATH` JSON override with strict validation; unknown/invalid → `invalid_input`, never an unscoped fallback. Matching is local substring (union: any product OR family); profile contents are never sent upstream or to telemetry.
- `tools/prompts.py` — the `monthly_triage` MCP prompt (registered in `server.py` via `mcp.prompt`), a guided analyst workflow built entirely on `msrc_search`; optional `product_profile`/`month` args. Portable copies live in `prompts/` (plain-text prompt) and `skills/patch-tuesday-triage/` (agent skill) — keep them in sync with `tools/prompts.py` when the workflow changes.
- `feeds/http_client.py` — shared httpx client: `follow_redirects=False` (hardcoded hosts; redirects are never followed automatically), `get_bounded()` which streams responses with a byte cap instead of buffering unbounded bodies, and `get_location()` which returns a redirect's status+Location without reading the body so a caller can follow one hop manually after validating the target.
- `feeds/msrc_api.py` — MSRC index + monthly CVRF fetch with in-process TTL caches (`MAX_FULL_MONTHS_CACHED = 12` — matches `MAX_TREND_MONTHS` so a max trend doesn't evict its own months; 40 slim), LRU eviction (hits refresh recency), per-month asyncio locks, `FETCH_CONCURRENCY = 3` semaphore, `force_refresh` bypass, freshness metadata. Response bodies capped via `MCP_MSRC_MAX_RESPONSE_BYTES` (64 MiB default).
- `feeds/enrichment.py` — KEV catalog + EPSS fetches (batches of 100, fetched concurrently with `EPSS_FETCH_CONCURRENCY = 3`), cached; EPSS cache capped at `MAX_EPSS_CACHE_ENTRIES = 50_000`; failures return empty ({}) — enrichment must never break a search. Bodies capped via `MCP_ENRICHMENT_MAX_RESPONSE_BYTES` (32 MiB default).
- `feeds/known_issues.py` — Microsoft-confirmed known issues per KB (`include_known_issues=True`), scraped best-effort from the public support.microsoft.com KB page (no keyless API exists; the Graph windowsupdates API needs AAD). Honest three-way status: `published` / `none_published` / `unavailable` — a fetch/parse failure is never reported as "none". Coverage boundary: known-issues sections exist mainly for Windows OS cumulative/preview updates; Office/SharePoint/SQL/.NET pages usually have none → `none_published`. Source quirks handled: `/help/{kb}` answers one same-host redirect (followed manually via `get_location()` after validating the target host), and bogus KB numbers redirect to *unrelated* articles that still echo the requested id in an analytics meta tag, so a landing page is only trusted if its URL slug or title names the requested KB (pages that never self-reference, like some .NET update pages, conservatively report no per-KB page). TTL cache 6 h (`MAX_CACHE_ENTRIES = 500`, LRU; failures aren't cached), `FETCH_CONCURRENCY = 3` semaphore shared by batch prefetch, bodies capped via `MCP_KNOWN_ISSUES_MAX_RESPONSE_BYTES` (4 MiB default). Parser is stdlib-only (regex slicing + `html.parser`); on layout drift it degrades to `unavailable` with the source URL — the `--run-live` smoke test is the drift canary.
- `models/vulnerability.py` — CVRF parsing into `Vulnerability`; numeric CVRF enums are documented constants (remediation types: 0=workaround, 1=mitigation, 2=vendor fix/KB, 4=will-not-fix). `to_summary_dict()` vs `to_detail_dict()` control output size; new fields are opt-in flags (`include_references`, `include_kb_details`, `include_kev_details`, `include_temporal`, filter-triggered `cwe`/`exploitation_assessment`).
- `models/cvss.py` — lenient CVSS v3.x vector parser; fails open to `None`, never raises.
- `middleware/` — per-IP token-bucket rate limit and request body cap, both with telemetry callbacks (`on_request`/`on_throttled`, `on_rejected`). X-Forwarded-For is honored only from private/loopback peers or `MCP_TRUSTED_PROXIES` members — a public direct peer can never forge it.
- `telemetry.py` — optional App Insights events (tool_call, msrc_fetch with `cache_hit`, enrichment_fetch, http_request, http_throttled, http_rejected_body); no-op unless `APPLICATIONINSIGHTS_CONNECTION_STRING` is set.

## Session-start check: pending third-party listings

**At the start of every session, run these checks and report the results to the user before other work.** When an item is resolved (merged/listed/confirmed), remove it from this list in a follow-up commit so the list stays current. All listings were submitted 2026-07-11.

1. **awesome-mcp-servers PR** — merged yet? `gh pr view 9879 --repo punkpeye/awesome-mcp-servers --json state,mergedAt` (all bot requirements met: Glama listing, badge, score A 4.8/5.0).
2. **Docker MCP Catalog PR** — CI green / review status? `gh pr view 4400 --repo docker/mcp-registry --json state,statusCheckRollup` (their CI builds the image itself; `server.yaml` pins `MCP_TRANSPORT=stdio` via config.env — if CI fails, fix in the fork branch `jonnybottles/mcp-registry:add-patch-tuesday`).
3. **PulseMCP auto-listing** — expected ~1 week after the 2026-07-11 registry publish: check https://www.pulsemcp.com/servers?q=patch-tuesday (they ingest the official MCP Registry; if absent after 2026-07-20, email hello@pulsemcp.com).
4. **Smithery deployment** — healthy and listed? https://smithery.ai/servers/xxbutler86xx/patch-tuesday (first deployment was still processing at submission time).
5. **Monthly draft routine** (only in the week after a Patch Tuesday) — did the Wednesday run open a `briefing/YYYY-MM` PR and email drafts to the user? Routine: https://claude.ai/code/routines/trig_01X24fvnRGhC6Lop3NRjVaJh

Standing follow-ups (no check needed, do when convenient): upload a social-preview image (repo Settings → Social preview); bump the PyPI classifier to `Development Status :: 4 - Beta` with the next release (requires version bump + `uv lock` + full deploy verification).

## Key Constraints

- **Single tool by design.** New capabilities hang off `msrc_search` parameters, never new tools — keeps client tool selection lean. MCP prompts (e.g. `monthly_triage`) are fine as long as they only orchestrate `msrc_search` calls.
- **Default output shape is a compatibility contract.** All new response fields/behaviors must be opt-in (parameter-gated); default JSON must not change. This extends to nested dicts: e.g. `restart_required` and the extra KEV catalog fields exist on the models but are stripped from default output (`KbArticle.to_dict(include_restart=)`, `Vulnerability._kev_view(full=)`).
- **Fail open on data quality.** Bad CVSS vectors, missing enrichment, malformed CVRF fragments must degrade gracefully (skip/None), never raise into a search. Unexpected exceptions become structured `error_kind="internal"` responses, never raw tracebacks.
- **Honest failure reporting.** KB month scans and chain walks distinguish "document not found" from fetch failures — upstream errors must not masquerade as definitive `not_found`.
- **Slim vs full parses.** `fetch_month(slim=True)` skips descriptions/FAQs/guidance (used for supersedence chain walking). The `query` filter matches description text, so filtered searches and trend search need **full** parses.
- **Memory envelope.** The hosted container is 0.25 vCPU / 0.5 GiB. A cold 12-month trend query measured ~81 MB traced peak / ~8 s (2026-07, after concurrent EPSS + 12-month cache) — fine, but keep this budget in mind when growing caches or ranges. Upstream reads are size-capped while streaming; keep it that way.
- **Live tests are opt-in.** Anything hitting real APIs belongs in `tests/test_live_smoke.py` behind the `--run-live` flag, or in the HTTP endpoint suite `tests/test_endpoint.py` behind `--endpoint-url` (markers `endpoint` / `endpoint_upstream` / `endpoint_burst`; see `tests/conftest.py`). The burst test drains the per-IP rate bucket — local containers only, and restart the container between back-to-back runs.

## CI & Supply Chain

- `.github/workflows/ci.yml` — pytest (3.11/3.12/3.14) + ruff + `--cov-fail-under=90`, then a container build with a Trivy CRITICAL/HIGH scan, an upstream-free endpoint smoke against the running image (MCP over HTTP + middleware; no secrets, fork-safe), and an SPDX SBOM artifact, on every push/PR.
- `.github/workflows/canary.yml` — daily (+ manual) run of the endpoint suite against the hosted ACA endpoint; on failure it files/updates a `canary`-labeled issue. Its `/health` version check doubles as a "merged a version bump but forgot to deploy" alarm.
- `.github/workflows/codeql.yml` — CodeQL (python) on push/PR + weekly.
- `.github/dependabot.yml` — weekly pip/actions/docker update PRs.
- All GitHub Actions are pinned to commit SHAs (Dependabot keeps them fresh); keep new workflow steps SHA-pinned too.
- `uv.lock` is committed and embeds the project version — **run `uv lock` after any dependency or version change**, or the Docker build (`uv sync --locked`) fails.
- The Dockerfile is multi-stage on a digest-pinned `python:3.14-slim`, runs non-root, and has a HEALTHCHECK against `/health`.

## Release & Deployment

- **Hosted endpoint** (public, no auth — owner's explicit choice): `https://patch-tuesday-mcp.happyrock-b60185ec.eastus.azurecontainerapps.io/mcp` (+ `/health`, which reports the running version).
- **Deploy flow**: bump `version` in **both** `pyproject.toml` and `src/patch_tuesday_mcp/__init__.py` → `uv lock` → `docker build -t docker.io/xxbutler21xx/patch-tuesday-mcp:<version> .` → push → `az containerapp update -n patch-tuesday-mcp -g patch-tuesday-rg --image docker.io/xxbutler21xx/patch-tuesday-mcp:<version>`. An unchanged image ref does not roll a new revision; ACA may briefly serve the draining old revision after update.
- **Post-deploy verification (every deployment, local container AND remote ACA)**: run the endpoint suite — `pytest -m endpoint --endpoint-url=http://localhost:8000 --endpoint-burst` against the local container, then `pytest -m "endpoint and not endpoint_burst" --endpoint-url=<hosted URL>` against ACA. It covers `/health` version match (override with `PT_EXPECTED_VERSION`), MCP tool round-trip over `/mcp`, prompt round-trip with and without `product_profile`/`month` args, middleware behavior, and real searches through the wire.
- **PyPI**: publishing is automated — creating a GitHub release triggers `.github/workflows/publish.yml` (trusted publishing + build-provenance attestation). `workflow_dispatch` publishes to TestPyPI instead.
- **MCP Registry**: the server is listed as `io.github.jonnybottles/patch-tuesday` (registry.modelcontextprotocol.io) via `server.json` in the repo root. After a version bump, update the two `version` fields in `server.json` and re-run `mcp-publisher publish` (login: `mcp-publisher login github`), or the registry serves a stale version.
- `SECURITY.md` documents the private-disclosure process and hosted-endpoint scope.
- Pushing directly to `main` on origin is permission-gated for automated sessions.
