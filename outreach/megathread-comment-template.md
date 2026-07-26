# r/sysadmin Patch Tuesday Megathread — comment template

> Post as a **comment in the monthly megathread** (search "Patch Tuesday Megathread" on r/sysadmin, pinned on the second Tuesday), within a few hours of release if possible. Helpful-first, attribution last. Don't post it as a standalone thread — that reads as self-promotion and gets removed.

---

**June 2026 quick triage** (example — regenerate each month)

The numbers: 1,281 entries in the CVRF doc (most are Chromium/OSS), 89 Critical, 4 publicly disclosed, 1 on CISA KEV.

What I'd actually patch first:

- **Edge/Chrome today** — CVE-2026-11645 (V8 OOB) is the month's only KEV entry, confirmed exploited, federal due date June 23.
- **The HTTP.sys pair** — CVE-2026-47291 is a 9.8 unauthenticated RCE in http.sys, and CVE-2026-49160 (DoS, same component) was publicly disclosed and is sitting at 48% EPSS. Anything that serves HTTP through http.sys (IIS, WinRM, WSUS…) is exposed. Both fixed in the June cumulatives.
- **Kernel RCE** CVE-2026-45657 (9.8) and **DHCP client RCE** CVE-2026-44815 (9.8) — in the same cumulative, so you get them for free.
- **DCs**: CVE-2026-45648 (AD DS RCE, Critical) — worth an early window for domain controllers.

BitLocker bypass (CVE-2026-50507), Defender EoP (CVE-2026-50656), and CTFMON EoP (CVE-2026-45586) were also publicly disclosed but are local/Important — normal cycle, assume PoCs exist.

*Pulled this together with an open-source MCP server I built that queries the MSRC API with EPSS/KEV enrichment — [patch-tuesday-mcp](https://github.com/jonnybottles/patch-tuesday-mcp) if anyone wants to ask their own questions ("what do I patch first?", "is KB____ superseded?"). Free, no API keys.*
