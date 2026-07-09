"""Rendering helpers for the msrc_search triage report mode.

The JSON response remains the default and most complete representation; these
helpers produce optional Markdown and CSV views for briefings and spreadsheets.
"""

import csv
import io

from ..models.vulnerability import Vulnerability

# Stable CSV column order. Clients can rely on these names and their ordering.
TRIAGE_COLUMNS = [
    "cve",
    "title",
    "severity",
    "impact",
    "max_cvss",
    "attack_vector",
    "privileges_required",
    "user_interaction",
    "epss_score",
    "kev",
    "kev_due_date",
    "exploited",
    "publicly_disclosed",
    "product_families",
    "affected_count",
    "kb_articles",
    "url",
    "rationale",
]


def prioritization_rationale(v: Vulnerability) -> str:
    """A short, human-readable reason a CVE ranks where it does.

    Mirrors the urgency ordering used for sorting: KEV/exploited first, then
    EPSS, then severity. Returns one or more compact tags joined by "; ".
    """
    reasons: list[str] = []
    if v.kev is not None:
        due = (v.kev or {}).get("due_date")
        reasons.append(f"On CISA KEV (due {due})" if due else "On CISA KEV")
    if v.exploited:
        reasons.append("Exploited in the wild")
    if v.publicly_disclosed:
        reasons.append("Publicly disclosed")
    if v.epss_score is not None and v.epss_score >= 0.10:
        reasons.append(f"EPSS {v.epss_score:.0%}")
    if v.severity in ("Critical", "Important"):
        reasons.append(f"{v.severity} severity")
    if not reasons:
        reasons.append(f"{v.severity or 'Low'} severity")
    return "; ".join(reasons)


def _kev_due_date(v: Vulnerability) -> str:
    return (v.kev or {}).get("due_date", "") if v.kev is not None else ""


def _row(v: Vulnerability) -> dict:
    """Flatten a Vulnerability into the stable triage column set."""
    cvss = v.cvss
    return {
        "cve": v.cve,
        "title": v.title,
        "severity": v.severity,
        "impact": v.impact,
        "max_cvss": v.max_cvss if v.max_cvss is not None else "",
        "attack_vector": cvss.attack_vector if cvss else "",
        "privileges_required": cvss.privileges_required if cvss else "",
        "user_interaction": cvss.user_interaction if cvss else "",
        "epss_score": v.epss_score if v.epss_score is not None else "",
        "kev": "yes" if v.kev is not None else "no",
        "kev_due_date": _kev_due_date(v),
        "exploited": "yes" if v.exploited else "no",
        "publicly_disclosed": "yes" if v.publicly_disclosed else "no",
        "product_families": "; ".join(v.product_families),
        "affected_count": len(v.affected_products),
        "kb_articles": "; ".join(sorted({k.kb for k in v.kb_articles})),
        "url": v.url,
        "rationale": prioritization_rationale(v),
    }


def render_csv(vulns: list[Vulnerability]) -> str:
    """Render a triage table as a CSV string with stable column names."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=TRIAGE_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for v in vulns:
        writer.writerow(_row(v))
    return buffer.getvalue()


def _md_cell(value) -> str:
    """Escape a value for use inside a Markdown table cell."""
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _epss_pct(v: Vulnerability) -> str:
    return f"{v.epss_score:.0%}" if v.epss_score is not None else "—"


def render_markdown(
    page: list[Vulnerability],
    header: dict,
    total_found: int,
    all_vulns: list[Vulnerability] | None = None,
) -> str:
    """Render a prioritized Markdown triage briefing.

    ``page`` is the (already limited/sorted) set of rows to tabulate;
    ``all_vulns`` (defaulting to ``page``) drives the executive-summary counts
    so they reflect the full matched set even when the table is truncated.
    """
    summary_set = all_vulns if all_vulns is not None else page
    critical = sum(1 for v in summary_set if v.severity == "Critical")
    important = sum(1 for v in summary_set if v.severity == "Important")
    exploited = sum(1 for v in summary_set if v.exploited)
    disclosed = sum(1 for v in summary_set if v.publicly_disclosed)
    kev = sum(1 for v in summary_set if v.kev is not None)

    month = header.get("month", "")
    title = header.get("title") or "Security Updates"

    lines: list[str] = []
    lines.append(f"# Patch Tuesday Triage — {title} ({month})")
    lines.append("")
    lines.append(
        f"**{total_found}** vulnerabilities matched; showing the top "
        f"**{len(page)}** by urgency (KEV/exploited → EPSS → severity → CVSS)."
    )
    lines.append("")
    lines.append(
        f"- Critical: **{critical}** · Important: **{important}**\n"
        f"- Exploited: **{exploited}** · Publicly disclosed: **{disclosed}** · "
        f"On CISA KEV: **{kev}**"
    )
    lines.append("")

    columns = [
        "CVE",
        "Title",
        "Families",
        "Impact",
        "Sev",
        "CVSS",
        "EPSS",
        "KEV due",
        "Exploited",
        "KBs",
        "Why prioritized",
    ]
    lines.append("| " + " | ".join(columns) + " |")
    lines.append("|" + "|".join(["---"] * len(columns)) + "|")

    for v in page:
        kbs = ", ".join(sorted({k.kb for k in v.kb_articles}))
        row = [
            f"[{v.cve}]({v.url})",
            _md_cell(v.title),
            _md_cell(", ".join(v.product_families)),
            _md_cell(v.impact),
            _md_cell(v.severity or "—"),
            _md_cell(v.max_cvss if v.max_cvss is not None else "—"),
            _epss_pct(v),
            _md_cell(_kev_due_date(v) or "—"),
            "yes" if v.exploited else "",
            _md_cell(kbs or "—"),
            _md_cell(prioritization_rationale(v)),
        ]
        lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines)
