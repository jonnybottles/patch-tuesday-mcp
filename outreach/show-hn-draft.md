# Show HN draft

> Post on a Patch Tuesday morning (US Eastern, ~9–11am works well) or the Wednesday after. Title must start with "Show HN:". Stay in the comments for the first 2–3 hours to answer questions — that's what keeps it alive. Never ask anyone to upvote (HN detects voting rings).

**Title:**
Show HN: MCP server for Microsoft Patch Tuesday triage (MSRC + EPSS + CISA KEV)

**URL:** https://github.com/jonnybottles/patch-tuesday-mcp

**First comment (post immediately after submitting):**

I triage Microsoft security updates every month, and clicking through the Security Update Guide portal to answer "what do I actually patch first?" was tedious. So I built an MCP server that lets any AI assistant (Claude, Copilot, Cursor…) query the official MSRC CVRF API directly.

What makes it different from generic CVE-lookup tools: it models the monthly release itself — KB articles, product trees, supersedence chains — so it can answer release-centric questions like "summarize this month," "which Critical CVEs affect Server 2022," "which KBs does this machine's update list map to, and is anything superseded?"

Results are enriched with FIRST.org EPSS scores (exploitation probability) and the CISA KEV catalog (confirmed exploited), and sorted most-urgent-first: KEV → EPSS → severity → CVSS.

Design decisions I care about:
- One consolidated tool, not thirty — keeps client tool-selection reliable
- Zero API keys anywhere (MSRC, EPSS, and KEV are all public feeds)
- Fail-open data handling — bad CVSS vectors or a down enrichment feed degrade gracefully instead of breaking a search
- There's a free hosted endpoint if you want to try it without installing anything

Python, MIT licensed. Feedback welcome — especially from anyone who does this workflow monthly.
