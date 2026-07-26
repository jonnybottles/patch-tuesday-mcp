# LinkedIn monthly post template

> Post Patch Tuesday evening or Wednesday morning. Attach a screenshot of an AI chat answering "what do I patch first this month?" via the tool. Put the repo link in the **first comment**, not the post body (LinkedIn suppresses posts with outbound links).

---

June 2026 Patch Tuesday, triaged in 5 minutes ⬇️

Microsoft shipped fixes for 89 Critical CVEs this month. Here's what actually matters:

🔴 CVE-2026-11645 (Chromium V8) — the only one confirmed exploited in the wild (CISA KEV, due 6/23). Update browsers first.

🔴 CVE-2026-47291 — CVSS 9.8 unauthenticated RCE in HTTP.sys. Its sibling DoS (CVE-2026-49160) was publicly disclosed and EPSS puts it at 48% exploitation probability — the highest of the month. If it serves HTTP on Windows, patch it.

🟠 Kernel RCE (CVE-2026-45657), DHCP client RCE (CVE-2026-44815), and an AD DS RCE (CVE-2026-45648) round out the criticals — all in the June cumulative.

I generated this triage by asking an AI assistant one question — "what do I patch first?" — through an open-source MCP server I built that queries Microsoft's MSRC API and enriches it with EPSS exploit-probability scores and the CISA KEV catalog. No API keys, works with Claude/Copilot/Cursor.

Link in the comments. Happy patching. 🛠️

#PatchTuesday #CyberSecurity #SysAdmin #VulnerabilityManagement #MCP

**First comment:**
🔗 https://github.com/jonnybottles/patch-tuesday-mcp — install is one command: `uvx patch-tuesday-mcp`. Monthly briefings archive: https://jonnybottles.github.io/patch-tuesday-mcp/
