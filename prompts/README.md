# patch-tuesday-mcp prompt library

Portable, plain-text copies of the MCP **prompts** this server registers. The
canonical, parameterized prompts are generated in code
([`src/patch_tuesday_mcp/tools/prompts.py`](../src/patch_tuesday_mcp/tools/prompts.py))
and exposed to MCP clients at runtime. The Markdown files here mirror that
content so the workflows can be used **independently of the MCP server** — pasted
into any agent, chat client, or runbook that talks to a `msrc_search` deployment.

## Contents

| Prompt | MCP name | Purpose |
|--------|----------|---------|
| [`monthly_triage.md`](monthly_triage.md) | `monthly_triage` | Step-by-step monthly Patch Tuesday triage over `msrc_search`, optionally scoped by product watchlist and month. |

## Using a prompt with the server

If your MCP client supports prompts, select `monthly_triage` directly — the
server renders it with your `product_profile` / `month` arguments. Nothing here
needs to be copied.

## Using a prompt without the server (standalone)

Open the Markdown file, replace the `{PROFILE}` and `{MONTH}` placeholders (or
delete those fragments to use defaults), and hand the text to any agent that can
call `msrc_search`. The prompt only orchestrates `msrc_search` calls — it
introduces no new tools and hard-codes no organization-specific data.

## Keeping the copies in sync

`tools/prompts.py` is the source of truth for what the server serves. When you
change a prompt's wording there, update the matching Markdown file here (and vice
versa) so the standalone copy stays accurate.
