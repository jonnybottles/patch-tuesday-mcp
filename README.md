### Disclaimer: This is an independent, self-built project and is not an official Microsoft tool or service.

# Patch Tuesday MCP Server

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

- **msrc_search** – Search and filter Microsoft security updates by keyword, CVE, KB number, month, product, severity, CVSS score, exploited-in-the-wild status, or public disclosure. When no month is given, results default to the most recent release whose Patch Tuesday has already occurred — the upcoming month's pre-release document (early Chromium/out-of-band entries only) is skipped by default and available explicitly via `month=`. Results are enriched with **EPSS scores** (FIRST.org 30-day exploitation probability, `min_epss=0.5` filter) and **CISA KEV** catalog status with federal remediation due dates (`kev=True` filter) — both public, keyless sources. Filter by the **parsed CVSS v3.x exposure fields** — `attack_vector` (N/A/L/P), `privileges_required` (N/L/H), `user_interaction` (N/R), and `scope` (U/C) — to isolate, for example, network-reachable zero-click criticals; matching results surface a structured `cvss` object broken out from the raw vector string. Every CVE detail also includes a **references** block of ready-to-open links (MSRC update guide, NVD, EPSS API, and the CISA KEV catalog when the CVE is listed). Add `include_chain=True` to a KB lookup to walk Microsoft-stated **supersedence chains** (which KBs it replaces, newest → oldest). Set `include_stats=True` for aggregate counts (by severity, impact, product family, exploited, KEV). Use `limit=0` with `include_stats=True` for a stats-only month overview.

## Prompt Examples

Once connected to an MCP client, you can ask questions like:

1. **Monthly overview**: "Summarize this month's Patch Tuesday"
2. **Exploited vulnerabilities**: "Which Microsoft vulnerabilities are being actively exploited?"
3. **CVE lookup**: "What is CVE-2026-41108 and which KB fixes it?"
4. **KB lookup**: "What does KB5094123 patch?"
5. **Product filter**: "Show me Critical vulnerabilities affecting Exchange Server this month"
6. **Patch prioritization**: "What should I patch first from the June 2026 updates?"
7. **CISA KEV**: "Which of this month's CVEs are on the CISA KEV list?"
8. **EPSS**: "Show me CVEs with EPSS above 50%"
9. **Exposure filtering**: "Which Critical CVEs are network-reachable with no privileges and no user interaction?"
10. **Reference links**: "Give me the MSRC, NVD, and EPSS links for CVE-2026-41108"
11. **Supersedence**: "Is KB5087538 superseded by anything newer?"

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
| `RATE_LIMIT_RPM` | `60` | Per-IP requests/minute (`0` disables) |
| `MCP_MAX_BODY_BYTES` | `262144` | Max request body size, returns 413 above it (`0` disables) |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | unset | Opt-in usage telemetry (requires `pip install patch-tuesday-mcp[telemetry]`) |

HTTP mode also serves `GET /health` (liveness endpoint, exempt from rate
limiting) and runs stateless, so it can scale to multiple replicas behind a
load balancer without session affinity.

The container runs on any host that can serve HTTP — Azure Container Apps, Cloud Run, Fly.io, or a plain VM.

## Telemetry & Privacy

- **Local stdio (the default): no telemetry, ever** — there is no code path that sends anything.
- **The hosted endpoint** records minimal usage data to Azure Application Insights (90-day retention): a daily-salted hash of the client IP (raw IPs are never stored; they are only held briefly in memory for abuse protection), request path and timestamp, which tool parameters were used (parameter *names* only — never your query text or CVE/KB values; only the low-cardinality `month` and `severity` values are kept), result counts, latency, and error categories. No cookies, no accounts, no request/response bodies.
- **Self-hosted HTTP** collects nothing unless you set `APPLICATIONINSIGHTS_CONNECTION_STRING` to your own resource — then the same minimal set flows to your instance instead.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/
```

## License

MIT
