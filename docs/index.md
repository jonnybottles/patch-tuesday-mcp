---
layout: default
title: Patch Tuesday Briefings
---

# Patch Tuesday Briefings

Monthly triage briefings for Microsoft Patch Tuesday, generated from the official
[MSRC Security Update Guide](https://msrc.microsoft.com/update-guide) and enriched
with [EPSS](https://www.first.org/epss/) exploitation-probability scores and the
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog.
Every briefing is produced by **[patch-tuesday-mcp](https://github.com/jonnybottles/patch-tuesday-mcp)**,
an open-source MCP server that lets AI assistants (Claude, Copilot, Cursor, and any
MCP client) answer questions like *"what do I patch first this month?"*

## Briefings

- [July 2026]({{ site.baseurl }}/briefings/2026-07)
- [June 2026]({{ site.baseurl }}/briefings/2026-06)

## Ask these questions yourself

The same data behind these briefings is one command away:

```bash
uvx patch-tuesday-mcp
```

Then ask your AI assistant:

- "Summarize this month's Patch Tuesday"
- "Which CVEs are on the CISA KEV list?"
- "What Critical CVEs affect Windows Server 2022?"
- "Is KB5094123 superseded by anything newer?"

No API keys, no accounts — the MSRC, EPSS, and KEV feeds are all public.
[Get started on GitHub →](https://github.com/jonnybottles/patch-tuesday-mcp)
