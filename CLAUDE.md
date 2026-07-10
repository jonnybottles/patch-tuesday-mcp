# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**patch-tuesday-mcp** is a Python MCP server exposing a single tool, `msrc_search`, that queries the public MSRC CVRF v3 API (Microsoft Patch Tuesday security updates), enriched with FIRST.org EPSS scores and the CISA KEV catalog. No API keys anywhere. Ships two ways: a PyPI package (stdio transport for local MCP clients) and a Docker image running HTTP transport on Azure Container Apps.

## Commands

```bash
pip install -e ".[dev]"       # or: uv pip install -e ".[dev]" (repo .venv is uv-managed, has no pip)
pytest                        # offline suite — mocked feeds, fast, no network
pytest --run-live             # additionally runs tests/test_live_smoke.py against real MSRC/EPSS/KEV APIs
pytest tests/test_tools.py    # single file
pytest --cov=patch_tuesday_mcp  # coverage; CI gates at >= 90%
ruff check .                  # lint (line-length 100, rules E/F/I/W)
uv lock                       # refresh uv.lock after changing dependencies OR the project version
```

On Windows in this repo use `.venv/Scripts/python -m pytest` etc. — the venv was created by uv and `pip` is not installed in it.

## Architecture

- `src/patch_tuesday_mcp/server.py` — FastMCP app + `main()`. stdio by default; `MCP_TRANSPORT=http` wraps the ASGI app in middleware (innermost→outermost: client-cleanup lifespan wrapper → body limit → rate limit → CORS) and serves `/mcp` + `/health`. uvicorn runs with `MCP_LIMIT_CONCURRENCY` (default 40) and `timeout_keep_alive=15`; `MCP_LOG_LEVEL` controls root logging (stderr).
- `tools/search.py` — the single `msrc_search` tool and all its routing: CVE fast path (cross-month lookup), KB fast path (with optional supersedence chain walk), `list_months=True` catalog fast path, single-month filtered search, and historical trend search (`months_back` / `start_month`+`end_month`, capped at `MAX_TREND_MONTHS = 12`). A top-level catch-all converts unexpected exceptions to `error_kind="internal"` — `msrc_search` never raises.
- `tools/formatters.py` — optional `format="markdown"|"csv"` triage renderings; JSON is always included and unchanged.
- `tools/profiles.py` — named product watchlists for `msrc_search` (`product_profile=`, plus ad-hoc `products=[...]`/`product_families=[...]`). Built-ins (`identity-core`, `endpoint`, `server-infrastructure`) merged under a `MSRC_PROFILES_PATH` JSON override with strict validation; unknown/invalid → `invalid_input`, never an unscoped fallback. Matching is local substring (union: any product OR family); profile contents are never sent upstream or to telemetry.
- `tools/prompts.py` — the `monthly_triage` MCP prompt (registered in `server.py` via `mcp.prompt`), a guided analyst workflow built entirely on `msrc_search`; optional `product_profile`/`month` args. Portable copies live in `prompts/` (plain-text prompt) and `skills/patch-tuesday-triage/` (agent skill) — keep them in sync with `tools/prompts.py` when the workflow changes.
- `feeds/http_client.py` — shared httpx client: `follow_redirects=False` (hardcoded hosts; redirects are never followed) and `get_bounded()` which streams responses with a byte cap instead of buffering unbounded bodies.
- `feeds/msrc_api.py` — MSRC index + monthly CVRF fetch with in-process TTL caches (`MAX_FULL_MONTHS_CACHED = 12` — matches `MAX_TREND_MONTHS` so a max trend doesn't evict its own months; 40 slim), LRU eviction (hits refresh recency), per-month asyncio locks, `FETCH_CONCURRENCY = 3` semaphore, `force_refresh` bypass, freshness metadata. Response bodies capped via `MCP_MSRC_MAX_RESPONSE_BYTES` (64 MiB default).
- `feeds/enrichment.py` — KEV catalog + EPSS fetches (batches of 100, fetched concurrently with `EPSS_FETCH_CONCURRENCY = 3`), cached; EPSS cache capped at `MAX_EPSS_CACHE_ENTRIES = 50_000`; failures return empty ({}) — enrichment must never break a search. Bodies capped via `MCP_ENRICHMENT_MAX_RESPONSE_BYTES` (32 MiB default).
- `models/vulnerability.py` — CVRF parsing into `Vulnerability`; numeric CVRF enums are documented constants (remediation types: 0=workaround, 1=mitigation, 2=vendor fix/KB, 4=will-not-fix). `to_summary_dict()` vs `to_detail_dict()` control output size; new fields are opt-in flags (`include_references`, `include_kb_details`, `include_kev_details`, `include_temporal`, filter-triggered `cwe`/`exploitation_assessment`).
- `models/cvss.py` — lenient CVSS v3.x vector parser; fails open to `None`, never raises.
- `middleware/` — per-IP token-bucket rate limit and request body cap, both with telemetry callbacks (`on_request`/`on_throttled`, `on_rejected`). X-Forwarded-For is honored only from private/loopback peers or `MCP_TRUSTED_PROXIES` members — a public direct peer can never forge it.
- `telemetry.py` — optional App Insights events (tool_call, msrc_fetch with `cache_hit`, enrichment_fetch, http_request, http_throttled, http_rejected_body); no-op unless `APPLICATIONINSIGHTS_CONNECTION_STRING` is set.

## Key Constraints

- **Single tool by design.** New capabilities hang off `msrc_search` parameters, never new tools — keeps client tool selection lean. MCP prompts (e.g. `monthly_triage`) are fine as long as they only orchestrate `msrc_search` calls.
- **Default output shape is a compatibility contract.** All new response fields/behaviors must be opt-in (parameter-gated); default JSON must not change. This extends to nested dicts: e.g. `restart_required` and the extra KEV catalog fields exist on the models but are stripped from default output (`KbArticle.to_dict(include_restart=)`, `Vulnerability._kev_view(full=)`).
- **Fail open on data quality.** Bad CVSS vectors, missing enrichment, malformed CVRF fragments must degrade gracefully (skip/None), never raise into a search. Unexpected exceptions become structured `error_kind="internal"` responses, never raw tracebacks.
- **Honest failure reporting.** KB month scans and chain walks distinguish "document not found" from fetch failures — upstream errors must not masquerade as definitive `not_found`.
- **Slim vs full parses.** `fetch_month(slim=True)` skips descriptions/FAQs/guidance (used for supersedence chain walking). The `query` filter matches description text, so filtered searches and trend search need **full** parses.
- **Memory envelope.** The hosted container is 0.25 vCPU / 0.5 GiB. A cold 12-month trend query measured ~81 MB traced peak / ~8 s (2026-07, after concurrent EPSS + 12-month cache) — fine, but keep this budget in mind when growing caches or ranges. Upstream reads are size-capped while streaming; keep it that way.
- **Live tests are opt-in.** Anything hitting real APIs belongs in `tests/test_live_smoke.py` behind the `--run-live` flag (see `tests/conftest.py`).

## CI & Supply Chain

- `.github/workflows/ci.yml` — pytest (3.11/3.12/3.14) + ruff + `--cov-fail-under=90`, then a container build with a Trivy CRITICAL/HIGH scan and an SPDX SBOM artifact, on every push/PR.
- `.github/workflows/codeql.yml` — CodeQL (python) on push/PR + weekly.
- `.github/dependabot.yml` — weekly pip/actions/docker update PRs.
- All GitHub Actions are pinned to commit SHAs (Dependabot keeps them fresh); keep new workflow steps SHA-pinned too.
- `uv.lock` is committed and embeds the project version — **run `uv lock` after any dependency or version change**, or the Docker build (`uv sync --locked`) fails.
- The Dockerfile is multi-stage on a digest-pinned `python:3.14-slim`, runs non-root, and has a HEALTHCHECK against `/health`.

## Release & Deployment

- **Hosted endpoint** (public, no auth — owner's explicit choice): `https://patch-tuesday-mcp.happyrock-b60185ec.eastus.azurecontainerapps.io/mcp` (+ `/health`, which reports the running version).
- **Deploy flow**: bump `version` in **both** `pyproject.toml` and `src/patch_tuesday_mcp/__init__.py` → `uv lock` → `docker build -t docker.io/xxbutler21xx/patch-tuesday-mcp:<version> .` → push → `az containerapp update -n patch-tuesday-mcp -g patch-tuesday-rg --image docker.io/xxbutler21xx/patch-tuesday-mcp:<version>`. An unchanged image ref does not roll a new revision; ACA may briefly serve the draining old revision after update.
- **PyPI**: publishing is automated — creating a GitHub release triggers `.github/workflows/publish.yml` (trusted publishing + build-provenance attestation). `workflow_dispatch` publishes to TestPyPI instead.
- `SECURITY.md` documents the private-disclosure process and hosted-endpoint scope.
- Pushing directly to `main` on origin is permission-gated for automated sessions.
