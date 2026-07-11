### Disclaimer: This is an independent, self-built project and is not an official Microsoft tool or service.

# Patch Tuesday MCP Server

[![patch-tuesday-mcp MCP server](https://glama.ai/mcp/servers/jonnybottles/patch-tuesday-mcp/badges/score.svg)](https://glama.ai/mcp/servers/jonnybottles/patch-tuesday-mcp)
[![PyPI](https://img.shields.io/pypi/v/patch-tuesday-mcp)](https://pypi.org/project/patch-tuesday-mcp/)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.jonnybottles%2Fpatch--tuesday-blue)](https://registry.modelcontextprotocol.io/v0/servers?search=patch-tuesday)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

mcp-name: io.github.jonnybottles/patch-tuesday

Ask your AI assistant about Microsoft security updates. This Python-based MCP (Model Context Protocol) server connects AI assistants like Claude, Copilot, and ChatGPT to the [MSRC Security Update Guide](https://msrc.microsoft.com/update-guide) — the authoritative source for every CVE Microsoft patches — enabling natural-language queries over Patch Tuesday releases: CVEs, KB articles, severity ratings, CVSS scores, affected products, and exploited-in-the-wild status.

## What It Does

Patch Tuesday MCP Server bridges Microsoft's official CVRF security update API and your AI assistant, allowing you to:

- **Get the monthly rollup** - "What did this month's Patch Tuesday fix?"
- **Find what's actively exploited** - "Which vulnerabilities are being exploited in the wild?"
- **Look up any CVE** - "Tell me about CVE-2026-41108" (KBs, affected products, CVSS, description)
- **Map KBs to CVEs** - "Which vulnerabilities does KB5094123 fix?"
- **Filter by product** - "What Critical CVEs affect Windows Server 2022 this month?"
- **Track zero-days** - "Were any publicly disclosed vulnerabilities patched in April?"
- **See what's confirmed exploited** - "Which of this month's CVEs are on the CISA KEV list?" — with federal remediation due dates
- **Rank by exploitation probability** - "Show me CVEs with EPSS above 50%" — daily FIRST.org exploit prediction scores
- **Find zero-click, internet-reachable criticals** - "Which Critical CVEs are network-reachable with no privileges and no user interaction?" — filter on the parsed CVSS attack vector, privileges, and user-interaction fields
- **Jump straight to authoritative sources** - every CVE detail carries ready-to-open MSRC, NVD, EPSS, and (when listed) CISA KEV reference links
- **Avoid stale patches** - "Is KB5087538 superseded by anything newer?" — walks Microsoft's supersedence links
- **Get mitigations when there's no patch yet** - "Are there mitigations or workarounds for CVE-2026-47291?" — surfaces Microsoft's mitigation, workaround, and will-not-fix guidance
- **Spot trends over time** - "How many HTTP.sys CVEs shipped over the last 6 months?" (`months_back=6`, or `start_month`/`end_month`) — aggregates matches across released months with per-month counts
- **Filter by Microsoft's own exploitation forecast** - "Which of this month's CVEs does Microsoft rate 'Exploitation More Likely'?" (`exploitation_likely=True`)
- **Spot ransomware-weaponized CVEs** - "Which CVEs this month are used in known ransomware campaigns?" (`ransomware=True`; add `include_kev_details=True` for the full CISA entry with required actions)
- **Plan the deployment, not just the priority** - "Does KB5094123 require a restart, and what build fixes it?" (`include_kb_details=True` adds per-KB URLs, fixed builds, supersedence, and restart requirements)
- **Know what Microsoft says an update breaks** - "Any known issues with KB5094126 before I roll it out?" (`include_known_issues=True` adds each KB's Microsoft-confirmed known issues — symptoms, workarounds, and the resolving update — best-effort from its public support page; published mainly for Windows updates, and the response says explicitly when Microsoft publishes none)
- **Slice a month by weakness class** - "Show me this month's use-after-free CVEs" (`cwe="CWE-416"` or `cwe="use after free"`)
- **Discover the release catalog** - "Which monthly releases are available, and when were they last revised?" (`list_months=True`)
- **Export a triage briefing** - "Give me this month's Critical CVEs as a Markdown report" or "…as CSV" — a prioritized executive summary and table, or a spreadsheet-ready export (`format="markdown"` / `format="csv"`)
- **Force-refresh & check data freshness** - "Re-pull this month's data fresh" (`force_refresh=True`) bypasses the in-process caches; `include_freshness=True` reports the cache age/TTL of the MSRC document and EPSS/KEV enrichment
- **Prioritize patching** - Results are sorted most-urgent-first: KEV/exploited, then EPSS, then severity, then CVSS

Perfect for security analysts, sysadmins, and IT professionals who triage Microsoft security updates every month — without clicking through the Security Update Guide portal.

Data comes from the official, public [MSRC CVRF v3 API](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API). No authentication or API key required.

## Why This Server?

**This is the only MCP server that models the Patch Tuesday release itself.** Plenty of MCP servers can look up a CVE — general-purpose vulnerability aggregators fan a known CVE ID out across NVD, OSV, and threat-intel feeds. They answer *"tell me about CVE-X"*. But they have no concept of a monthly Microsoft release, a KB article, or a product family — so they structurally cannot answer the questions a Microsoft shop actually asks on the second Tuesday of every month:

| The question you actually have | Generic CVE lookup servers | patch-tuesday-mcp |
|---|---|---|
| "Summarize this month's Patch Tuesday" | ❌ no concept of a release | ✅ rollup + stats in one call |
| "What Critical CVEs affect Windows Server 2022 this month?" | ❌ can't filter by Microsoft product | ✅ product & family filtering |
| "Which vulnerabilities does KB5094123 fix?" | ❌ no KB awareness | ✅ KB ↔ CVE mapping |
| "What's being exploited in the wild right now?" | ⚠️ per-CVE only, if you already know the CVE | ✅ filter the whole month |
| "What do I patch first?" | ❌ | ✅ urgency-sorted: exploited/KEV → EPSS → severity → CVSS |
| "Which criticals are zero-click and internet-reachable?" | ⚠️ per-CVE CVSS only | ✅ filter the month by parsed CVSS attack vector / privileges / user interaction |
| "Tell me about CVE-X" | ✅ (often with more ecosystem data) | ✅ MSRC detail: KBs, builds, supersedence, parsed CVSS, MSRC/NVD/EPSS/KEV links |

Under the hood, the difference is the data source: this server parses the full **MSRC CVRF monthly documents** — the ProductTree, per-product severity threats, exploitability assessments, and KB remediation chains that per-CVE APIs never expose. That's what makes release-centric questions possible.

Other things it deliberately gets right:

- **Zero API keys, zero accounts** — the MSRC API is public; setup is one `uvx` command
- **One tool, not thirty** — a single consolidated `msrc_search` keeps your AI client's context lean and tool selection reliable
- **Built for the monthly workflow** — triage a release, brief your team, prioritize patching, then get on with your life

## Try It Instantly — Hosted Endpoint (No Install)

A free remote instance is available at:

```
https://patch-tuesday-mcp.happyrock-b60185ec.eastus.azurecontainerapps.io/mcp
```
No account or API key needed. The endpoint serves the same public data as a local install — for heavy use or guaranteed availability, run it locally (below) or [self-host your own](#self-hosting-as-a-remote-mcp-server). Only minimal, anonymized usage data is recorded — see [Telemetry & Privacy](#telemetry--privacy).

## Requirements

### General

- **Python 3.11+**
- An MCP-compatible client (Claude Desktop, Cursor, Claude Code, GitHub Copilot CLI, etc.)

### Using `uvx` (Recommended)

If you are installing or running the server via **`uvx`**, you must have **uv** installed first.

- **uv** (includes `uvx`): https://github.com/astral-sh/uv

Install uv:

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
irm https://astral.sh/uv/install.ps1 | iex
```

> `uvx` allows you to run the MCP server without installing the package globally.

### Using pip (Alternative)

```bash
pip install patch-tuesday-mcp
```

## Installation

### Install from PyPI

```bash
uvx patch-tuesday-mcp
```

Or install with pip:

```bash
pip install patch-tuesday-mcp
```

### Upgrade to Latest Version

```bash
uvx patch-tuesday-mcp@latest
```

Or with pip:

```bash
pip install --upgrade patch-tuesday-mcp
```

## Quick Setup

[![Set up in VS Code](https://img.shields.io/badge/Set_up_in-VS_Code-0078d4?style=flat-square&logo=visualstudiocode)](https://vscode.dev/redirect/mcp/install?name=patch-tuesday-mcp&config=%7B%22type%22%3A%20%22stdio%22%2C%20%22command%22%3A%20%22uvx%22%2C%20%22args%22%3A%20%5B%22patch-tuesday-mcp%22%5D%7D)
[![Set up in Cursor](https://img.shields.io/badge/Set_up_in-Cursor-000000?style=flat-square&logo=cursor)](https://cursor.com/docs/context/mcp)
[![Set up in Claude Code](https://img.shields.io/badge/Set_up_in-Claude_Code-9b6bff?style=flat-square&logo=anthropic)](https://code.claude.com/docs/en/mcp)
[![Set up in Copilot CLI](https://img.shields.io/badge/Set_up_in-Copilot_CLI-28a745?style=flat-square&logo=github)](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/use-copilot-cli)

> **One-click setup:** Click the VS Code badge for automatic configuration (requires `uv` installed)
> **Manual setup:** See instructions below for VS Code, Cursor, Claude Code, Copilot CLI, or Claude Desktop

## Features

- **msrc_search** – Search and filter Microsoft security updates by keyword, CVE, KB number, month, product, severity, CVSS score, exploited-in-the-wild status, or public disclosure. When no month is given, results default to the most recent release whose Patch Tuesday has already occurred — the upcoming month's pre-release document (early Chromium/out-of-band entries only) is skipped by default and available explicitly via `month=`. Results are enriched with **EPSS scores** (FIRST.org 30-day exploitation probability, `min_epss=0.5` filter) and **CISA KEV** catalog status with federal remediation due dates (`kev=True` filter) — both public, keyless sources. Filter by the **parsed CVSS v3.x exposure fields** — `attack_vector` (N/A/L/P), `privileges_required` (N/L/H), `user_interaction` (N/R), and `scope` (U/C) — to isolate, for example, network-reachable zero-click criticals; matching results surface a structured `cvss` object broken out from the raw vector string. Every CVE detail also includes a **references** block of ready-to-open links (MSRC update guide, NVD, EPSS API, and the CISA KEV catalog when the CVE is listed). Add `include_chain=True` to a KB lookup to walk Microsoft-stated **supersedence chains** (which KBs it replaces, newest → oldest). Pass a **list of KB numbers** (`kb=["5094123", "KB5094127", ...]`, up to 30) to resolve them all in one call — e.g. a machine's installed-update list as context for a patch report — and get a grouped response with one per-KB entry (found or not-found, each with the same body as a single-KB lookup); every monthly document is still fetched upstream at most once for the whole batch. Add `include_known_issues=True` to any KB lookup (single or batched) for the **Microsoft-confirmed known issues** of each update — issue titles, symptoms, workarounds, and the resolving KB when Microsoft names one — scraped best-effort from the KB's public support page with an honest per-KB status: `published`, `none_published` (Microsoft publishes no known-issues data for that KB — the norm outside Windows OS updates), or `unavailable` (retrieval/parse failure, explicitly distinct from "no issues"); it reports what Microsoft has confirmed breaks, not a prediction for your environment. Add `include_guidance=True` to a CVE lookup to surface Microsoft-provided **mitigations, workarounds, and will-not-fix advisories** alongside the vendor-fix KBs. Pass `format="markdown"` or `format="csv"` to a monthly/filtered search to get an additive **triage briefing** — a prioritized executive summary and table (Markdown) or a spreadsheet-ready export with stable columns (CSV) — rendered from the same urgency ranking; the JSON `vulnerabilities` list is always included. Use `force_refresh=True` to bypass the in-process caches and re-fetch the MSRC document and EPSS/KEV enrichment for the request, and `include_freshness=True` to add a **freshness** block reporting the cache age and TTL of the MSRC document and enrichment data. Search a **historical range** instead of a single month with `months_back=N` (the N most recent released months) or `start_month`/`end_month` — the response aggregates matching CVEs across the range and adds per-month **trend** counts; ranges are capped at 12 months and reuse the existing cache/concurrency controls. Set `include_stats=True` for aggregate counts (by severity, impact, product family, exploited, KEV). Use `limit=0` with `include_stats=True` for a stats-only month overview. Filter on **Microsoft's exploitation-likelihood assessment** with `exploitation_likely=True` ("Exploitation More Likely"/"Exploitation Detected"; matches carry an `exploitation_assessment` field) and on **known ransomware campaign use** with `ransomware=True` (from the CISA KEV catalog). Opt into richer rows where you need them: `include_references=True` adds the MSRC/NVD/EPSS/KEV link block to month/KB/trend list results, `include_kev_details=True` replaces the boolean KEV flag with the full catalog entry (due date, required action, vendor/product, ransomware use), `include_kb_details=True` expands KB numbers into full objects with per-KB URL, fixed build, supersedence, sub-type, and **restart-required** status, and `include_temporal=True` adds Microsoft's **CVSS temporal score** to cvss blocks. Filter by **weakness class** with `cwe=` (ID or name substring, e.g. `cwe="CWE-416"`). Use `list_months=True` to fetch the **release catalog** (every available month with initial/current release dates — handy for valid `month=` values and spotting same-month revisions). All new fields are opt-in: the default JSON shape is unchanged.

## Product profiles (watchlists)

Scope any search to the products you actually run. Pass `product_profile="identity-core"` (built-in profiles: `identity-core`, `endpoint`, `server-infrastructure`) or supply ad-hoc `products=["Exchange Server", "Windows Server"]` / `product_families=["Windows", "Azure"]`. A vulnerability is kept if it matches **any** listed product or family. All matching is local — profile contents are never transmitted to MSRC, FIRST.org, CISA, or telemetry.

Override or extend the built-ins by pointing `MSRC_PROFILES_PATH` at a JSON file:

```json
{
  "my-estate": {
    "families": ["Windows", "Azure"],
    "products": ["Exchange Server", "Microsoft Entra"]
  }
}
```

Each entry may set `products` and/or `families` (case-insensitive partial matchers). A file entry with the same name as a built-in replaces it. An unknown `product_profile`, or a missing/invalid `MSRC_PROFILES_PATH`, returns a clear `invalid_input` error rather than falling back to a broad, unscoped result.

### Companion triage skill

A portable [agent skill](skills/README.md) — `patch-tuesday-triage` — teaches an AI agent how to drive `msrc_search` through the monthly workflow (which searches to run, in what order, how to prioritize). It's plain Markdown and can be **deployed independently of this server**: copy `skills/patch-tuesday-triage/` into your agent's skills directory. See [`skills/README.md`](skills/README.md) for deployment details.

## Guided triage prompt

The server registers an MCP **prompt** named `monthly_triage`. MCP clients that support prompts can select it to get a step-by-step analyst workflow built entirely on `msrc_search` — publicly disclosed zero-days, CISA KEV, exploited, network/no-auth/no-UI criticals, identity-adjacent products, endpoint/Intune, and a briefing. It accepts two optional arguments: `product_profile` (scope the whole workflow to a watchlist) and `month` (triage a specific release). No new tools are introduced — the prompt only orchestrates `msrc_search` calls.

A portable, plain-text copy of this prompt lives under [`prompts/`](prompts/README.md) so the workflow can be used **independently of the server**.

## Prompt Examples

Once connected to an MCP client, you can ask questions like:

1. **Monthly overview**: "Summarize this month's Patch Tuesday"
2. **Exploited vulnerabilities**: "Which Microsoft vulnerabilities are being actively exploited?"
3. **CVE lookup**: "What is CVE-2026-41108 and which KB fixes it?"
4. **KB lookup**: "What does KB5094123 patch?"
5. **Machine patch report**: "Here are the KBs installed on this server: KB5094123, KB5094127, KB5093998 — what do they fix and is anything superseded?"
6. **Product filter**: "Show me Critical vulnerabilities affecting Exchange Server this month"
7. **Patch prioritization**: "What should I patch first from the June 2026 updates?"
8. **CISA KEV**: "Which of this month's CVEs are on the CISA KEV list?"
9. **EPSS**: "Show me CVEs with EPSS above 50%"
10. **Exposure filtering**: "Which Critical CVEs are network-reachable with no privileges and no user interaction?"
11. **Reference links**: "Give me the MSRC, NVD, and EPSS links for CVE-2026-41108"
12. **Mitigations & workarounds**: "Are there any mitigations or workarounds for CVE-2026-41108?"
13. **Triage report**: "Give me this month's Critical CVEs as a Markdown briefing" (or "…export them as CSV")
14. **Fresh data on demand**: "Re-pull this month's updates fresh and tell me how current the data is" (`force_refresh=True`, `include_freshness=True`)
15. **Historical trends**: "How many HTTP.sys RCE CVEs shipped over the last 6 months?" (`query="HTTP.sys"`, `months_back=6`)
16. **Supersedence**: "Is KB5087538 superseded by anything newer?"
17. **Exploitation forecast**: "Which CVEs does Microsoft rate 'Exploitation More Likely' this month?"
18. **Ransomware**: "Which of this month's CVEs are used in known ransomware campaigns?"
19. **Deployment planning**: "Does KB5094123 require a restart, and which build fixes it?"
20. **Known issues before rollout**: "What has Microsoft confirmed breaks in KB5094126, and is there a fix or workaround?" (`include_known_issues=True`)
21. **Weakness class**: "Show me this month's use-after-free vulnerabilities" (`cwe="CWE-416"`)
22. **Release catalog**: "Which Patch Tuesday months are available to query?"
23. **Product watchlist**: "Show me this month's Critical CVEs across my estate" (`product_profile="identity-core"`, `severity="Critical"`)
24. **Guided triage**: "Walk me through this month's triage for my identity estate" (selects the `monthly_triage` prompt with `product_profile="identity-core"`)

## Usage

### Run the MCP Server

```bash
uvx patch-tuesday-mcp
```

Or if installed with pip:

```bash
patch-tuesday-mcp
```

### Connect from VS Code

**Option 1: One-Click Install (Recommended)**

Click the **[Set up in VS Code](#quick-setup)** badge at the top of this README for automatic configuration (requires `uv` installed).

**Option 2: Manual Configuration**

VS Code stores MCP servers in a **dedicated `mcp.json` file — not `settings.json`.** Open the Command Palette (`Ctrl+Shift+P` on Windows/Linux, `Cmd+Shift+P` on macOS) and run one of:

- **`MCP: Open User Configuration`** — edits your user-level `mcp.json` (available in every workspace)
- **`MCP: Open Workspace Folder Configuration`** — edits a project-local `.vscode/mcp.json`

Then add the server. Note that VS Code uses a top-level **`"servers"`** key (unlike the `"mcpServers"` key used by the other clients below):

```json
{
  "servers": {
    "patch-tuesday": {
      "type": "stdio",
      "command": "uvx",
      "args": ["patch-tuesday-mcp"]
    }
  }
}
```

### Connect from Claude Desktop

Add to your Claude Desktop MCP config:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

**Using uvx (recommended)**

```json
{
  "mcpServers": {
    "patch-tuesday": {
      "command": "uvx",
      "args": ["patch-tuesday-mcp"]
    }
  }
}
```

**Using installed package**

```json
{
  "mcpServers": {
    "patch-tuesday": {
      "command": "patch-tuesday-mcp"
    }
  }
}
```

### Connect from Cursor

**Option 1: One-Click Install (Recommended)**

```
cursor://anysphere.cursor-deeplink/mcp/install?name=patch-tuesday-mcp&config=eyJjb21tYW5kIjogInV2eCIsICJhcmdzIjogWyJwYXRjaC10dWVzZGF5LW1jcCJdfQ==
```

**Option 2: Manual Configuration**

Add to your Cursor MCP config (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "patch-tuesday": {
      "command": "uvx",
      "args": ["patch-tuesday-mcp"]
    }
  }
}
```

### Connect from Claude Code

```bash
claude mcp add --transport stdio patch-tuesday -- uvx patch-tuesday-mcp
```

### Connect from GitHub Copilot CLI

Add to `~/.copilot/mcp-config.json`:

```json
{
  "mcpServers": {
    "patch-tuesday": {
      "type": "stdio",
      "command": "uvx",
      "args": ["patch-tuesday-mcp"]
    }
  }
}
```

## Self-Hosting as a Remote MCP Server

The server also supports the HTTP transport for remote/shared deployments:

```bash
MCP_TRANSPORT=http MCP_PORT=8000 patch-tuesday-mcp
# MCP endpoint: http://localhost:8000/mcp
```

Or with Docker:

```bash
docker build -t patch-tuesday-mcp .
docker run -p 8000:8000 patch-tuesday-mcp
```

HTTP-mode environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_TRANSPORT` | `stdio` | Set to `http` for remote serving |
| `MCP_HOST` / `MCP_PORT` | `0.0.0.0` / `8000` | Bind address |
| `MCP_MAX_BODY_BYTES` | `262144` | Max request body size, returns 413 above it (`0` disables) |
| `MCP_CORS_ORIGINS` | `*` (all) | Comma-separated allowlist of browser origins. **Set an explicit list for public deployments** (e.g. `https://app.example.com`) |
| `MCP_LIMIT_CONCURRENCY` | `40` | Max concurrent in-flight connections; uvicorn responds 503 beyond it (`0` disables) |
| `MCP_TIMEOUT_KEEP_ALIVE` | `15` | Seconds before idle keep-alive connections are closed |
| `MCP_LOG_LEVEL` | `WARNING` | Root log level (`DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL`); logs go to stderr |
| `MCP_MSRC_MAX_RESPONSE_BYTES` | `67108864` (64 MiB) | Cap on a single MSRC upstream response body (read while streaming, never buffered past the cap) |
| `MCP_ENRICHMENT_MAX_RESPONSE_BYTES` | `33554432` (32 MiB) | Cap on a single EPSS/KEV upstream response body |
| `MCP_KNOWN_ISSUES_MAX_RESPONSE_BYTES` | `4194304` (4 MiB) | Cap on a single support.microsoft.com KB-page body (known-issues lookups) |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | unset | Opt-in usage telemetry (requires `pip install patch-tuesday-mcp[telemetry]`) |

HTTP mode also serves `GET /health` (liveness endpoint) and runs stateless,
so it can scale to multiple replicas behind a load balancer without session
affinity.

### Hardening a public HTTP deployment

The HTTP transport is **unauthenticated** — `msrc_search` only reads public
vulnerability data, but an open endpoint is still abusable. Before exposing it
to the internet:

- **Put it behind an authenticated front door.** Terminate TLS and require auth
  at a reverse proxy / API gateway (e.g. Azure API Management, an OAuth2/OIDC
  proxy such as `oauth2-proxy`, Cloudflare Access, or your ingress controller's
  auth). This server intentionally ships no built-in auth so you can layer your
  organization's standard access control in front of it.
- **Restrict CORS.** Set `MCP_CORS_ORIGINS` to the exact origins of your MCP
  clients instead of the permissive `*` default.
- **Keep the defaults on.** Leave `MCP_MAX_BODY_BYTES` and
  `MCP_LIMIT_CONCURRENCY` at their defaults (or tighten them) — they are your
  first line of defense against oversized payloads and connection exhaustion.
- **Upstream reads are bounded and redirect-free.** Responses from MSRC/EPSS/
  KEV are size-capped while streaming and HTTP redirects are never followed,
  so a misbehaving upstream can't exhaust container memory.

Local `stdio` usage is unaffected by all of the above; none of this middleware
runs for the default transport.

The container runs on any host that can serve HTTP — Azure Container Apps, Cloud Run, Fly.io, or a plain VM.

## Telemetry & Privacy

- **Local stdio (the default): no telemetry, ever** — there is no code path that sends anything.
- **The hosted endpoint** records minimal usage data to Azure Application Insights (90-day retention): a daily-salted hash of the client IP (raw IPs are never stored; they are only held briefly in memory for abuse protection), request path and timestamp, which tool parameters were used (parameter *names* only — never your query text or CVE/KB values; only the low-cardinality `month` and `severity` values are kept), result counts, latency, and error categories. No cookies, no accounts, no request/response bodies.
- **Self-hosted HTTP** collects nothing unless you set `APPLICATIONINSIGHTS_CONNECTION_STRING` to your own resource — then the same minimal set flows to your instance instead.

## Development

```bash
pip install -e ".[dev]"
pytest                  # offline suite (mocked feeds)
pytest --run-live       # also run live smoke tests against the real MSRC / EPSS / KEV APIs
pytest --cov=patch_tuesday_mcp   # coverage (CI enforces >= 90%)
ruff check src/ tests/
```

CI (GitHub Actions) runs the offline suite on Python 3.11/3.12/3.14 with a coverage
gate, lints with ruff, builds the container, scans it with Trivy, and produces
an SPDX SBOM on every push/PR. Release builds attest provenance for the
published wheel/sdist. Dependencies are locked in `uv.lock` (used by the Docker
build via `uv sync --locked`).

## Security

See [SECURITY.md](SECURITY.md) for the supported versions, scope, and how to
report a vulnerability privately.

## License

MIT
