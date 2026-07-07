### Disclaimer: This is an independent, self-built project and is not an official Microsoft tool or service.

# Patch Tuesday MCP Server

mcp-name: io.github.jonnybottles/patch-tuesday

Ask your AI assistant about Microsoft security updates. This Python-based MCP (Model Context Protocol) server connects AI assistants like Claude to the [MSRC Security Update Guide](https://msrc.microsoft.com/update-guide) — the authoritative source for every CVE Microsoft patches — enabling natural-language queries over Patch Tuesday releases: CVEs, KB articles, severity ratings, CVSS scores, affected products, and exploited-in-the-wild status.

## What It Does

Patch Tuesday MCP Server bridges Microsoft's official CVRF security update API and your AI assistant, allowing you to:

- **Get the monthly rollup** - "What did this month's Patch Tuesday fix?"
- **Find what's actively exploited** - "Which vulnerabilities are being exploited in the wild?"
- **Look up any CVE** - "Tell me about CVE-2026-41108" (KBs, affected products, CVSS, description)
- **Map KBs to CVEs** - "Which vulnerabilities does KB5094123 fix?"
- **Filter by product** - "What Critical CVEs affect Windows Server 2022 this month?"
- **Track zero-days** - "Were any publicly disclosed vulnerabilities patched in April?"
- **Prioritize patching** - Results are sorted most-urgent-first: exploited, then severity, then CVSS

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
| "What do I patch first?" | ❌ | ✅ urgency-sorted: exploited → severity → CVSS |
| "Tell me about CVE-X" | ✅ (often with more ecosystem data) | ✅ MSRC detail: KBs, builds, supersedence |

Under the hood, the difference is the data source: this server parses the full **MSRC CVRF monthly documents** — the ProductTree, per-product severity threats, exploitability assessments, and KB remediation chains that per-CVE APIs never expose. That's what makes release-centric questions possible.

Other things it deliberately gets right:

- **Zero API keys, zero accounts** — the MSRC API is public; setup is one `uvx` command
- **One tool, not thirty** — a single consolidated `msrc_search` keeps your AI client's context lean and tool selection reliable
- **Built for the monthly workflow** — triage a release, brief your team, prioritize patching, then get on with your life

### Roadmap

- **EPSS scores** (FIRST.org) — data-driven 30-day exploitation probability per CVE, for sharper "patch this first" ranking than severity alone
- **CISA KEV integration** — flag CVEs on the Known Exploited Vulnerabilities catalog, with federal remediation due dates (`kev=True` filter)
- Cross-month keyword search

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
> **Manual setup:** See instructions below for Cursor, Claude Code, Copilot CLI, or Claude Desktop

## Features

- **msrc_search** – Search and filter Microsoft security updates by keyword, CVE, KB number, month, product, severity, CVSS score, exploited-in-the-wild status, or public disclosure. Set `include_stats=True` for aggregate counts (by severity, impact, product family). Use `limit=0` with `include_stats=True` for a stats-only month overview.

## Prompt Examples

Once connected to an MCP client, you can ask questions like:

1. **Monthly overview**: "Summarize this month's Patch Tuesday"
2. **Exploited vulnerabilities**: "Which Microsoft vulnerabilities are being actively exploited?"
3. **CVE lookup**: "What is CVE-2026-41108 and which KB fixes it?"
4. **KB lookup**: "What does KB5094123 patch?"
5. **Product filter**: "Show me Critical vulnerabilities affecting Exchange Server this month"
6. **Patch prioritization**: "What should I patch first from the June 2026 updates?"

## Usage

### Run the MCP Server

```bash
uvx patch-tuesday-mcp
```

Or if installed with pip:

```bash
patch-tuesday-mcp
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
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | unset | Opt-in usage telemetry (requires `pip install patch-tuesday-mcp[telemetry]`) |

See [docs/deploy-azure.md](docs/deploy-azure.md) for a full Azure Container Apps deployment guide.

### Privacy

**Local stdio usage (the default) sends no telemetry — ever.** Telemetry only exists for self-hosted HTTP deployments, is off unless the operator sets their own Application Insights connection string, and never stores raw client IPs (they are hashed with a daily salt for unique-user counts).

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/
```

## License

MIT
