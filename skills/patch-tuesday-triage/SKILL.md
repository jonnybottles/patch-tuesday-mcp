---
name: "patch-tuesday-triage"
description: "Monthly Patch Tuesday identity/security triage using the single msrc_search tool with product watchlists"
domain: "vulnerability-triage"
confidence: "high"
source: "patch-tuesday-mcp triage workflow"
---

## Context

This project exposes **one** MCP tool, `msrc_search`, over the MSRC Patch
Tuesday feed (enriched with EPSS + CISA KEV). Do **not** look for other tools —
every workflow below is expressed as `msrc_search` calls with different
parameters. Product watchlists are applied locally; their contents never leave
the host.

## Product watchlists (profiles)

`msrc_search` accepts a `product_profile="<name>"` that expands locally into
product/family matchers, plus ad-hoc `products=[...]` and `product_families=[...]`
lists. A vulnerability matches if it hits **any** listed product OR family.

Built-in profiles:

| Profile | Covers |
|---------|--------|
| `identity-core` | Windows (family) + Azure (family) + Exchange Server, Entra, Intune, Defender, Edge |
| `endpoint` | Windows, Defender, Intune, Edge, Browser family |
| `server-infrastructure` | Windows/ESU families + Windows Server, Exchange, SharePoint, SQL Server |

Override or add profiles locally by pointing `MSRC_PROFILES_PATH` at a JSON file:

```json
{
  "my-estate": { "families": ["Windows", "Azure"], "products": ["Exchange Server"] }
}
```

Keep organization-specific profile names and product lists **local** — never
send them upstream or into shared prompts.

## Monthly triage workflow

Run these `msrc_search` calls in order and summarize the findings. Scope each to
your estate by adding `product_profile="identity-core"` (or your own profile).

1. **Publicly disclosed zero-days** — `msrc_search(publicly_disclosed=True, product_profile="identity-core")`.
2. **Known exploited (KEV)** — `msrc_search(kev=True, product_profile="identity-core")`. These carry CISA due dates; treat as top priority.
3. **Exploited per Microsoft** — `msrc_search(exploited=True, product_profile="identity-core")`.
4. **Network / no-auth / no-UI critical** — `msrc_search(severity="Critical", attack_vector="N", privileges_required="N", user_interaction="N", product_profile="identity-core")`.
5. **Identity-adjacent products** — `msrc_search(product_profile="identity-core", severity="Critical")` for Exchange/Entra/Intune/Defender/Edge exposure.
6. **Endpoint / Intune** — `msrc_search(product_profile="endpoint", min_cvss=7.0)`.

## Briefing output

Ask for a ready-to-share report with `format="markdown", report="triage"`, e.g.:

```
msrc_search(kev=True, product_profile="identity-core", format="markdown", report="triage")
```

Prioritize in this order: KEV/exploited → high EPSS → severity → CVSS exposure
(this is also how `msrc_search` sorts by default). Include the CVE, title,
severity, exploitation status, EPSS, and the fixing KB(s).

## Trends

To see how a class of issues has moved, add a range: `months_back=6` (or
`start_month`/`end_month`) returns a per-month `trend` block, e.g.
`msrc_search(query="HTTP.sys", months_back=6)`.
