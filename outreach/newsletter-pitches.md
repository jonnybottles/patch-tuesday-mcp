# Newsletter & media pitches

## Help Net Security (monthly "hottest open-source cybersecurity tools" roundup)

> Email via their contact page (helpnetsecurity.com/contact) or press@helpnetsecurity.com. Short pitch; they write the copy themselves.

**Subject:** Open-source tool submission: patch-tuesday-mcp — AI-assisted Patch Tuesday triage

Hi,

I'd like to submit an open-source tool for consideration in your monthly open-source tools roundup.

**patch-tuesday-mcp** (MIT, Python) connects AI assistants — Claude, Copilot, Cursor, any MCP client — to Microsoft's official MSRC Security Update Guide API, enriched with FIRST.org EPSS scores and the CISA KEV catalog. Security teams can ask "what do I patch first this month?", "which CVEs are on KEV?", or "is KB5094123 superseded?" in plain language and get urgency-ranked answers from authoritative public data. No API keys or accounts anywhere; there's also a free hosted endpoint for zero-install trial.

It's the only MCP server that models the Patch Tuesday release itself (KB articles, product trees, supersedence chains) rather than doing per-CVE lookups.

GitHub: https://github.com/jonnybottles/patch-tuesday-mcp
Monthly briefing samples: https://jonnybottles.github.io/patch-tuesday-mcp/

Happy to provide screenshots, a demo, or answer questions.

John Butler

---

## tl;dr sec (Clint Gibler) — tools section

> Submit via the link in any tl;dr sec issue footer or tldrsec.com contact; keep it to 2–3 sentences, they curate heavily.

**patch-tuesday-mcp** — Open-source MCP server that lets AI assistants triage Microsoft Patch Tuesday from the official MSRC API, enriched with EPSS + CISA KEV and sorted by real-world urgency. Models the release itself (KBs, supersedence chains, product filtering), not just per-CVE lookups. No API keys; free hosted endpoint available. https://github.com/jonnybottles/patch-tuesday-mcp

---

## patchmanagement.org mailing list (PatchManagement.org listserv)

> This is THE practitioner community for Microsoft patching (run by Susan Bradley). Plain-text email, no marketing tone, disclose you're the author. Subscribe first at patchmanagement.org, participate a little, then share.

**Subject:** Free open-source tool: AI-queryable MSRC data with EPSS/KEV enrichment

Hi all,

Long-time Patch Tuesday triager here. I built a free, open-source tool that might save some of you the monthly Security Update Guide clicking: it's an MCP server (the protocol AI assistants use for tools) that queries the official MSRC CVRF API and answers questions like:

- "Summarize this month's release" / "what do I patch first?"
- "Which of this month's CVEs are on the CISA KEV list?"
- "Here are the KBs on this server — what do they fix, is anything superseded?"
- "Which Criticals are network-reachable with no auth and no user interaction?"

Results are ranked by exploited/KEV status, then EPSS probability, severity, and CVSS. Works with Claude, Copilot, Cursor, or any MCP client; no API keys (MSRC/EPSS/KEV are all public feeds). MIT licensed.

https://github.com/jonnybottles/patch-tuesday-mcp

Full disclosure: I'm the author. Feedback from folks who live this workflow is exactly what I'm after.

John

---

## Docker MCP Catalog (submission is a PR, not email)

Repo: https://github.com/docker/mcp-registry — `task create` scaffolds a `servers/patch-tuesday/server.yaml`; requirements: Dockerfile in repo (✔ have one), MIT license (✔), working MCP server (✔). Their CI builds the image and Docker hosts it on the `mcp/` namespace. Do this after the current PR wave settles.

## Anthropic Claude connectors directory

The hosted endpoint qualifies as a remote server. Submission: https://docs.claude.com/en/docs/agents-and-tools/mcp-connectors (directory submission form linked from claude.ai/directory). Requires: OAuth or open access (open ✔), privacy policy (Telemetry section in README ✔ — may need a standalone page), support contact.
