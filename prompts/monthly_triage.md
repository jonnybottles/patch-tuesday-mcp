# Monthly Patch Tuesday triage

> Portable copy of the `monthly_triage` MCP prompt. This is the plain-text
> workflow the server renders when a client selects the prompt — reproduced here
> so it can be used **independently of the MCP server** (pasted into any agent,
> chat, or runbook). The server version accepts `product_profile` and `month`
> arguments; in this standalone copy, fill in the two placeholders below.
>
> - Replace `{PROFILE}` with a product watchlist name (e.g. `identity-core`) to
>   scope every step to your estate, or delete the `, product_profile="{PROFILE}"`
>   fragments to triage the whole release.
> - Replace `{MONTH}` with a release (e.g. `2026-Jun`) to triage a specific
>   month, or delete the `, month="{MONTH}"` fragments to use the latest release.

---

You have a single MCP tool, `msrc_search`. Do not look for other tools — every
step below is a `msrc_search` call with different parameters. Scope every search
to the **{PROFILE}** watchlist (omit `product_profile` to cover the whole
release, or pass `products=[...]` / `product_families=[...]`).

Work through these steps and summarize the findings, most urgent first.

1. **Publicly disclosed zero-days** — `msrc_search(publicly_disclosed=True, product_profile="{PROFILE}", month="{MONTH}")`.
2. **Known exploited (CISA KEV)** — `msrc_search(kev=True, product_profile="{PROFILE}", month="{MONTH}")`. These carry
   federal due dates; treat them as the top priority.
3. **Exploited per Microsoft** — `msrc_search(exploited=True, product_profile="{PROFILE}", month="{MONTH}")`.
4. **Network / no-auth / no-UI criticals** — `msrc_search(severity="Critical",
   attack_vector="N", privileges_required="N", user_interaction="N", product_profile="{PROFILE}", month="{MONTH}")`.
   These are the zero-click, internet-reachable criticals.
5. **Identity-adjacent products** — `msrc_search(severity="Critical", product_profile="{PROFILE}", month="{MONTH}")` and
   call out anything touching Exchange, Entra, Intune, Defender, or Edge.
6. **Endpoint / Intune exposure** — `msrc_search(min_cvss=7.0, product_profile="{PROFILE}", month="{MONTH}")`, focusing
   on client and management-plane products.

## Briefing output

Produce a shareable summary. For a ready-made report, add
`format="markdown", report="triage"` to any of the calls above, e.g.
`msrc_search(kev=True, product_profile="{PROFILE}", format="markdown", report="triage")`.

Prioritize KEV/exploited → high EPSS → severity → CVSS exposure (this is also
how `msrc_search` sorts by default). For each item include the CVE, title,
severity, exploitation status, EPSS score, and the fixing KB(s).
