# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **⚠️ Keep the sibling instruction file in sync.** This repo is worked on from **both** Claude Code
> and GitHub Copilot, and the owner switches between them. `CLAUDE.md` and
> `.github/copilot-instructions.md` are intended to carry the **same** architecture, constraints,
> commands, and operational knowledge. **Whenever you change this file, apply the equivalent change
> to `.github/copilot-instructions.md` in the same commit** (and vice versa). If you learn something
> durable during a session — a corrected fact, a new command, a resolved checklist item — write it to
> *both* files before you finish. A change that lands in only one of them is a bug.

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

# Scale/infra suite (tests/test_scale.py) — opt-in, shells out to `az`, never runs in CI.
pytest -m "scale and not scale_load" --aca-scale --aca-subscription=<sub-id>   # ARM config assertions
pytest -m "scale and not scale_load" --aca-scale --aca-subscription=<sub-id> --endpoint-url=<hosted URL>  # + live cross-check
pytest -m scale_load --aca-scale --aca-scale-load --aca-subscription=<sub-id>  # real load-driven scale-out (~5 min, mutates live config)
```

On Windows in this repo use `.venv/Scripts/python -m pytest` etc. — the venv was created by uv and `pip` is not installed in it.

## Architecture

- `src/patch_tuesday_mcp/server.py` — FastMCP app + `main()`. stdio by default; `MCP_TRANSPORT=http` serves `/mcp` + `/health` with the ASGI app from `build_http_app()` (middleware innermost→outermost: client-cleanup lifespan wrapper → body limit → rate limit → deprecation headers → CORS; the factory exists so tests can exercise the exact production composition). uvicorn runs with `MCP_LIMIT_CONCURRENCY` (default 40; the hosted deployment sets **100**) and `timeout_keep_alive=15`; `MCP_LOG_LEVEL` controls root logging (stderr). The startup settings log reports pinned trusted proxies as a count only — never echo `MCP_TRUSTED_PROXIES` values (CodeQL flags clear-text logging of them; issue #10, pinned by a test).
- `deprecation.py` + `middleware/deprecation_headers.py` — **env-gated endpoint deprecation signalling**, used to retire a hosted URL without breaking clients. Active only when **both** `MCP_DEPRECATION_SUNSET` and `MCP_DEPRECATION_REPLACEMENT_URL` are set (optional `MCP_DEPRECATION_SINCE`, `MCP_DEPRECATION_DOCS_URL`); partial or malformed config logs a warning and stays **silent**. When active it adds a `deprecation` block to every `msrc_search` response (attached at the single return choke point, so even errors carry it), RFC 9745/8594/5829 `Deprecation`/`Sunset`/`Link` headers, a `deprecation` key on `/health`, a suffix on the FastMCP server `instructions`, and a suffix on the tool description. Server instructions and the tool description are computed at **import** time (correct for containers); the JSON block and headers read env **per request**. **All text is declarative fact — never an instruction aimed at the model.** `tests/test_deprecation.py::test_notice_never_instructs_the_model` fails the build if imperative phrasing ("you must", "your response", "prepend", …) creeps into any channel; do not weaken it. This endpoint is public, so model-directed text here would be indirect prompt injection into *other people's* agent sessions.
- `tools/search.py` — the single `msrc_search` tool and all its routing: CVE fast path (cross-month lookup), KB fast path (single KB or a batched `kb=[...]` list capped at `MAX_KB_BATCH = 30` returning grouped per-KB results, with optional supersedence chain walk and optional support-page decoration (`include_known_issues=True` known issues, `include_update_summary=True` what-the-update-changes summary; both served by one page fetch) — attached even to `not_found`/`upstream` KB results since preview-only updates aren't in MSRC data, but never to `invalid_input`), `list_months=True` catalog fast path, single-month filtered search, and historical trend search (`months_back` / `start_month`+`end_month`, capped at `MAX_TREND_MONTHS = 12`). A top-level catch-all converts unexpected exceptions to `error_kind="internal"` — `msrc_search` never raises.
- `tools/formatters.py` — optional `format="markdown"|"csv"` triage renderings; JSON is always included and unchanged.
- `tools/profiles.py` — named product watchlists for `msrc_search` (`product_profile=`, plus ad-hoc `products=[...]`/`product_families=[...]`). Built-ins (`identity-core`, `endpoint`, `server-infrastructure`) merged under a `MSRC_PROFILES_PATH` JSON override with strict validation; unknown/invalid → `invalid_input`, never an unscoped fallback. Matching is local substring (union: any product OR family); profile contents are never sent upstream or to telemetry.
- `tools/prompts.py` — the `monthly_triage` MCP prompt (registered in `server.py` via `mcp.prompt`), a guided analyst workflow built entirely on `msrc_search`; optional `product_profile`/`month` args. Portable copies live in `prompts/` (plain-text prompt) and `skills/patch-tuesday-triage/` (agent skill) — keep them in sync with `tools/prompts.py` when the workflow changes.
- `feeds/http_client.py` — shared httpx client: `follow_redirects=False` (hardcoded hosts; redirects are never followed automatically), `get_bounded()` which streams responses with a byte cap instead of buffering unbounded bodies, and `get_location()` which returns a redirect's status+Location without reading the body so a caller can follow hops manually after validating each target.
- `feeds/msrc_api.py` — MSRC index + monthly CVRF fetch with in-process TTL caches (`MAX_FULL_MONTHS_CACHED = 12` — matches `MAX_TREND_MONTHS` so a max trend doesn't evict its own months; 40 slim), LRU eviction (hits refresh recency), per-month asyncio locks, `FETCH_CONCURRENCY = 3` semaphore, `force_refresh` bypass, freshness metadata. Response bodies capped via `MCP_MSRC_MAX_RESPONSE_BYTES` (64 MiB default).
- `feeds/enrichment.py` — KEV catalog + EPSS fetches (batches of 100, fetched concurrently with `EPSS_FETCH_CONCURRENCY = 3`), cached; EPSS cache capped at `MAX_EPSS_CACHE_ENTRIES = 50_000`; failures return empty ({}) — enrichment must never break a search. Bodies capped via `MCP_ENRICHMENT_MAX_RESPONSE_BYTES` (32 MiB default).
- `feeds/known_issues.py` — per-KB support-page scraping serving two opt-in response blocks from one fetch and one combined cache record: Microsoft-confirmed known issues (`include_known_issues=True`) and the update summary (`include_update_summary=True` — the page's Summary/Highlights text + Improvements bullets, size-capped via `_SUMMARY_MAX_CHARS`/`_MAX_IMPROVEMENT_ITEMS`/`_IMPROVEMENT_ITEM_MAX_CHARS` with a `truncated` marker). Scraped best-effort from the public support.microsoft.com KB page (no keyless API exists; the Graph windowsupdates API needs AAD). Honest three-way status per block: `published` / `none_published` / `unavailable` — a fetch/parse failure is never reported as "none". A record is cached only when neither block is `unavailable` (partial layout drift refetches rather than pinning a failure). Coverage boundary: known-issues sections exist mainly for Windows OS cumulative/preview updates; Office/SharePoint/SQL/.NET pages usually have none → `none_published` (their Summary sections still yield an update summary). Source quirks handled: `/help/{kb}` answers a short same-host redirect chain (bounded at `MAX_REDIRECT_HOPS = 3`; each hop followed manually via `get_location()` after validating the target host — the 2026 site migration added a second hop to `/servicing/os/...`), two markup generations are parsed (legacy `ocpSection` divs with `<b class="ocpLegacyBold">` labels, and the newer `<details>/<summary>` blocks with `<strong>` labels under an `<h3>` heading), and bogus KB numbers redirect to *unrelated* articles that still echo the requested id in an analytics meta tag, so a landing page is only trusted if its URL slug or title names the requested KB (pages that never self-reference, like some .NET update pages, conservatively report no per-KB page). TTL cache 6 h (`MAX_CACHE_ENTRIES = 500`, LRU; failures aren't cached), `FETCH_CONCURRENCY = 3` semaphore shared by batch prefetch, bodies capped via `MCP_KNOWN_ISSUES_MAX_RESPONSE_BYTES` (4 MiB default). Parser is stdlib-only (regex slicing + `html.parser`); on layout drift it degrades to `unavailable` with the source URL — the `--run-live` smoke test is the drift canary.
- `models/vulnerability.py` — CVRF parsing into `Vulnerability`; numeric CVRF enums are documented constants (remediation types: 0=workaround, 1=mitigation, 2=vendor fix/KB, 4=will-not-fix). `to_summary_dict()` vs `to_detail_dict()` control output size; new fields are opt-in flags (`include_references`, `include_kb_details`, `include_kev_details`, `include_temporal`, filter-triggered `cwe`/`exploitation_assessment`).
- `models/cvss.py` — lenient CVSS v3.x vector parser; fails open to `None`, never raises.
- `middleware/` — per-IP token-bucket rate limit and request body cap, both with telemetry callbacks (`on_request`/`on_throttled`, `on_rejected`). X-Forwarded-For is honored only from private/loopback peers or `MCP_TRUSTED_PROXIES` members — a public direct peer can never forge it.
- `telemetry.py` — optional App Insights events (tool_call, msrc_fetch with `cache_hit`, enrichment_fetch, http_request, http_throttled, http_rejected_body); no-op unless `APPLICATIONINSIGHTS_CONNECTION_STRING` is set.

## Session-start check: pending items

**At the start of every session, run these checks and report the results to the user before other work.** When an item is resolved (merged/listed/confirmed/expired), remove it from this list in a follow-up commit so the list stays current — **and remove it from `.github/copilot-instructions.md` too**.

1. **Old hosted endpoint retirement (due 2026-08-11)** — is today on/after **August 11, 2026**? If so, the grace period is over: delete the old Container App and its RG (sub `d30bd909-9bf4-4edd-a991-f44677e7c07f`, `patch-tuesday-rg`, eastus), delete the "Legacy endpoint still serving" step in `.github/workflows/canary.yml` (it is marked `DELETE THIS STEP`), and drop the deprecation blockquote from `README.md` + the old-URL scope line in `SECURITY.md`. Until then, confirm the old endpoint still answers `/health` **and** still carries its `deprecation` block.
2. **Glama re-index** — Glama renders `README.md` directly, so it picks up doc changes with no PR, but on *its* schedule. Until it does, it advertises a stale endpoint. Check: `curl -sL https://glama.ai/mcp/servers/jonnybottles/patch-tuesday-mcp | grep -c agreeabledesert` should be non-zero (and `happyrock` should be gone). Still stale as of 2026-07-26, the day 0.9.1 merged. Drop this item once it flips.
3. **Docker MCP Catalog PR** — CI green / review status? `gh pr view 4400 --repo docker/mcp-registry --json state,statusCheckRollup` (their CI builds the image itself; `server.yaml` pins `MCP_TRANSPORT=stdio` via config.env — if CI fails, fix in the fork branch `jonnybottles/mcp-registry:add-patch-tuesday`). Unaffected by the hosted-URL change (stdio only). Open with **zero CI runs** since 2026-07-11; nudged 2026-07-26 with the pinned `source.commit` refreshed to the v0.9.1 tree.
4. **Monthly draft routine** (only in the week after a Patch Tuesday) — did the Wednesday run open a `briefing/YYYY-MM` PR and email drafts to the user? Routine: https://claude.ai/code/routines/trig_01X24fvnRGhC6Lop3NRjVaJh

Standing follow-ups (no check needed, do when convenient): upload a social-preview image (repo Settings → Social preview).

**Settled — do not re-litigate:** `modelcontextprotocol/servers` (the "official Anthropic repo") **no longer accepts third-party server listings**; its CONTRIBUTING.md retired that list in favor of the MCP Registry. Publishing to `registry.modelcontextprotocol.io` via `server.json` + `mcp-publisher` *is* the official-listing action. Glama renders `README.md` directly, so it picks up doc changes on re-index with no PR. The merged `punkpeye/awesome-mcp-servers` entry carries no endpoint URL, so URL changes never require a PR there.

## Key Constraints

- **Single tool by design.** New capabilities hang off `msrc_search` parameters, never new tools — keeps client tool selection lean. MCP prompts (e.g. `monthly_triage`) are fine as long as they only orchestrate `msrc_search` calls.
- **Default output shape is a compatibility contract.** All new response fields/behaviors must be opt-in (parameter-gated); default JSON must not change. This extends to nested dicts: e.g. `restart_required` and the extra KEV catalog fields exist on the models but are stripped from default output (`KbArticle.to_dict(include_restart=)`, `Vulnerability._kev_view(full=)`).
- **Fail open on data quality.** Bad CVSS vectors, missing enrichment, malformed CVRF fragments must degrade gracefully (skip/None), never raise into a search. Unexpected exceptions become structured `error_kind="internal"` responses, never raw tracebacks.
- **Honest failure reporting.** KB month scans and chain walks distinguish "document not found" from fetch failures — upstream errors must not masquerade as definitive `not_found`.
- **Slim vs full parses.** `fetch_month(slim=True)` skips descriptions/FAQs/guidance (used for supersedence chain walking). The `query` filter matches description text, so filtered searches and trend search need **full** parses.
- **Memory envelope.** The hosted container runs **0.5 vCPU / 1 GiB** per replica (resized 2026-07 during the subscription migration; it was 0.25/0.5 before). A cold 12-month trend query measured ~81 MB traced peak / ~8 s (2026-07, after concurrent EPSS + 12-month cache) — comfortable now, but keep the budget in mind when growing caches or ranges, and remember every replica pays it independently. Upstream reads are size-capped while streaming; keep it that way.
- **Never scale to zero.** The hosted app runs `minReplicas: 2` — cold starts are unacceptable for an interactive MCP tool, and 2 replicas also give zero-downtime revision rolls. `tests/test_scale.py` pins this (`minReplicas > 0` is an explicit assertion, not an implication of the floor).
- **The autoscale trigger must sit well below the connection cap.** uvicorn 503s past `MCP_LIMIT_CONCURRENCY`, so a `concurrentRequests` trigger at or above it means replicas start *refusing* traffic before ACA ever decides to add one. Current hosted values: cap **100**, trigger **20** (5x headroom). `tests/test_scale.py` reads the app's *configured* cap and enforces `cap / trigger >= 2.0`.
- **Live tests are opt-in.** Anything hitting real APIs belongs in `tests/test_live_smoke.py` behind the `--run-live` flag, or in the HTTP endpoint suite `tests/test_endpoint.py` behind `--endpoint-url` (markers `endpoint` / `endpoint_upstream` / `endpoint_burst`; see `tests/conftest.py`). Infra assertions live in `tests/test_scale.py` behind `--aca-scale` / `--aca-scale-load` (markers `scale` / `scale_load`). The burst test drains the per-IP rate bucket — local containers only, and restart the container between back-to-back runs.

## CI & Supply Chain

- `.github/workflows/ci.yml` — pytest (3.11/3.12/3.14) + ruff + `--cov-fail-under=90`, then a container build with a Trivy CRITICAL/HIGH scan, an upstream-free endpoint smoke against the running image (MCP over HTTP + middleware; no secrets, fork-safe), and an SPDX SBOM artifact, on every push/PR.
- `.github/workflows/canary.yml` — daily (+ manual) run of the endpoint suite against the hosted ACA endpoint; on failure it files/updates a `canary`-labeled issue. Its `/health` version check doubles as a "merged a version bump but forgot to deploy" alarm.
- `.github/workflows/codeql.yml` — CodeQL (python) on push/PR + weekly.
- `.github/dependabot.yml` — weekly pip/actions/docker update PRs.
- All GitHub Actions are pinned to commit SHAs (Dependabot keeps them fresh); keep new workflow steps SHA-pinned too.
- `uv.lock` is committed and embeds the project version — **run `uv lock` after any dependency or version change**, or the Docker build (`uv sync --locked`) fails.
- The Dockerfile is multi-stage on a digest-pinned `python:3.14-slim`, runs non-root, and has a HEALTHCHECK against `/health`.

## Release & Deployment

### Hosted endpoints (public, no auth — owner's explicit choice)

| | URL | Subscription | RG / region | Purpose |
|---|---|---|---|---|
| **Current** | `https://patch-tuesday-mcp.agreeabledesert-d0b8e491.eastus2.azurecontainerapps.io/mcp` | `737d1571-00f3-486b-866b-24399aa29ac5` (ME-MngEnvMCAP124320, VS sub, tenant `3697dc7c-…`) | `patch-tuesday-rg` / **eastus2** | The one to advertise everywhere |
| **Legacy** | `https://patch-tuesday-mcp.happyrock-b60185ec.eastus.azurecontainerapps.io/mcp` | `d30bd909-9bf4-4edd-a991-f44677e7c07f` (Platform Subscription, tenant `27793beb-…`) | `patch-tuesday-rg` / eastus | Grace period only — **retires 2026-08-11** |

Both serve `/mcp` + `/health` (`/health` reports the running version). The current app runs
0.5 vCPU / 1 GiB, min 2 / max 6, an `http-concurrency` scale rule at **20**, `MCP_LIMIT_CONCURRENCY=100`,
`RATE_LIMIT_RPM=60`. The legacy app keeps its original 0.25/0.5, min 1 sizing — it is only kept
image-current so `/health` versions agree, **plus** the deprecation env vars below.

**The legacy app is the only place the deprecation env vars are set** — that is what keeps the
notice off local stdio installs and off the current endpoint:
`MCP_DEPRECATION_SUNSET=2026-08-11`, `MCP_DEPRECATION_SINCE=2026-07-26`,
`MCP_DEPRECATION_REPLACEMENT_URL=<current /mcp URL>`. Same image everywhere; only env differs.

**Azure identity gotcha:** the two apps live in **different tenants**. `az` picks the right identity
automatically when you pass `--subscription`, but SDK code using `DefaultAzureCredential` (e.g.
`foundry-agent/`) uses the **default** `az` context — so `az account set --subscription 737d1571-…`
first, or Foundry calls fail with a confusing `agents/read` RBAC error naming the *other* tenant's user.

### Deploy flow

1. Bump `version` in **both** `pyproject.toml` and `src/patch_tuesday_mcp/__init__.py`.
2. `uv lock` (mandatory — `uv sync --locked` in the Dockerfile fails otherwise).
3. Update the two `version` fields in `server.json`.
4. `docker build -t docker.io/xxbutler21xx/patch-tuesday-mcp:<version> .` → `docker push`.
5. `az containerapp update -n patch-tuesday-mcp -g patch-tuesday-rg --subscription <sub> --image …:<version>`
   for **both** apps (current app keeps its resized spec; legacy app is image-only).

An unchanged image ref does not roll a new revision. ACA may briefly serve the draining old revision
after an update. `az containerapp update` **echoes stale state in its own output** (it printed
`concurrentRequests: ""` right after successfully setting it) — always read back with
`az containerapp show` instead of trusting the update response.

### Post-deploy verification (every deployment)

- Local container: `pytest -m endpoint --endpoint-url=http://localhost:8000 --endpoint-burst`.
- Current ACA: `pytest -m "endpoint and not endpoint_burst" --endpoint-url=<current URL>`.
- Legacy ACA (until 2026-08-11): same command against the legacy URL.
- Scale config assertions: `pytest -m "scale and not scale_load" --aca-scale --aca-subscription=737d1571-…`.

Covers `/health` version match (override with `PT_EXPECTED_VERSION`), MCP tool round-trip over
`/mcp`, prompt round-trip with and without `product_profile`/`month` args, middleware behavior, and
real searches through the wire.

**Give a freshly rolled revision a minute before judging results.** Caches start cold, and
enrichment fails *open* — a KEV/EPSS fetch that fails on a cold container makes `kev=True` return
**0 results**, which is indistinguishable from a genuine zero. A post-deploy Foundry eval failed
exactly this way once and passed on re-run with no code change. Suspect cold cache before suspecting
a regression.

### Publishing

- **PyPI**: automated — creating a GitHub release triggers `.github/workflows/publish.yml` (trusted publishing + build-provenance attestation). `workflow_dispatch` publishes to TestPyPI instead.
- **MCP Registry**: listed as `io.github.jonnybottles/patch-tuesday` (registry.modelcontextprotocol.io) via `server.json`. After a version bump, update the two `version` fields and re-run `mcp-publisher publish` (login: `mcp-publisher login github`), or the registry serves a stale version. **The registry refuses to re-publish an existing version** — changing anything in `server.json` (including the remote URL) therefore requires a *new* version number. `mcp-publisher` is not on PATH by default; install/locate it first.
- `SECURITY.md` documents the private-disclosure process and hosted-endpoint scope.
- Pushing directly to `main` on origin is permission-gated for automated sessions — branch + PR.
- `outreach/` holds post drafts (LinkedIn, Show HN, newsletter pitches); `foundry-agent/` is **local-only** and git-excluded (`.gitignore`), so never commit eval results.
