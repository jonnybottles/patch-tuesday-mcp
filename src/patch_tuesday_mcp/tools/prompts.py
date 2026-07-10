"""MCP prompt templates for Patch Tuesday triage.

These guide a client through analyst workflows using the single ``msrc_search``
tool — they do not introduce new tools. Organization-specific watchlist names
are supplied by the caller (or a locally configured profile); nothing here
hard-codes a particular estate.
"""


def monthly_triage(product_profile: str = "", month: str = "") -> str:
    """Monthly Patch Tuesday identity/security triage workflow.

    Args:
        product_profile: Optional named product watchlist to scope every step to
            (e.g. "identity-core"). Leave blank to triage the whole release.
        month: Optional release to triage (e.g. "2026-Jun"). Defaults to the
            latest released month.
    """
    scope = f', product_profile="{product_profile}"' if product_profile.strip() else ""
    month_arg = f', month="{month}"' if month.strip() else ""
    args = f"{scope}{month_arg}"
    profile_note = (
        f"Scope every search to the **{product_profile}** watchlist."
        if product_profile.strip()
        else "No product watchlist is set, so this covers the whole release. To "
        'focus on your estate, re-run with a product_profile (e.g. "identity-core") '
        "or pass products=[...] / product_families=[...]."
    )

    return f"""\
# Monthly Patch Tuesday triage

You have a single MCP tool, `msrc_search`. Do not look for other tools — every
step below is a `msrc_search` call with different parameters. {profile_note}

Work through these steps and summarize the findings, most urgent first.

1. **Publicly disclosed zero-days** — `msrc_search(publicly_disclosed=True{args})`.
2. **Known exploited (CISA KEV)** — `msrc_search(kev=True{args})`. These carry
   federal due dates; treat them as the top priority.
3. **Exploited per Microsoft** — `msrc_search(exploited=True{args})`.
4. **Network / no-auth / no-UI criticals** — `msrc_search(severity="Critical",
   attack_vector="N", privileges_required="N", user_interaction="N"{args})`.
   These are the zero-click, internet-reachable criticals.
5. **Identity-adjacent products** — `msrc_search(severity="Critical"{args})` and
   call out anything touching Exchange, Entra, Intune, Defender, or Edge.
6. **Endpoint / Intune exposure** — `msrc_search(min_cvss=7.0{args})`, focusing
   on client and management-plane products.

## Briefing output

Produce a shareable summary. For a ready-made report, add
`format="markdown", report="triage"` to any of the calls above, e.g.
`msrc_search(kev=True{scope}, format="markdown", report="triage")`.

Prioritize KEV/exploited → high EPSS → severity → CVSS exposure (this is also
how `msrc_search` sorts by default). For each item include the CVE, title,
severity, exploitation status, EPSS score, and the fixing KB(s).
"""
