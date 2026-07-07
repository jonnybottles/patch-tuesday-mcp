"""Unified search tool for querying MSRC security updates (Patch Tuesday)."""

import re
import time

from .. import telemetry
from ..feeds import msrc_api
from ..feeds.msrc_api import MsrcApiError
from ..models.vulnerability import (
    SEVERITY_ORDER,
    MonthlyRelease,
    Vulnerability,
    sort_vulnerabilities,
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# How many recent months a KB lookup scans before giving up
KB_SCAN_MONTHS = 6

MAX_LIMIT = 100


async def msrc_search(
    query: str | None = None,
    cve: str | None = None,
    kb: str | None = None,
    month: str | None = None,
    product: str | None = None,
    severity: str | None = None,
    exploited: bool | None = None,
    publicly_disclosed: bool | None = None,
    min_cvss: float | None = None,
    limit: int = 10,
    offset: int = 0,
    include_stats: bool = False,
) -> dict:
    """Search Microsoft security updates (Patch Tuesday) from the official MSRC API.

    Combines keyword search, CVE/KB lookup, and product/severity/exploitation
    filtering into a single flexible tool. All filter parameters are optional
    and can be combined. When no filters are provided, returns the most urgent
    vulnerabilities from the latest Patch Tuesday release (exploited first,
    then by severity and CVSS score).

    Use this tool to:
    - Get the latest Patch Tuesday overview (include_stats=True, limit=0)
    - Browse the most urgent fixes this month (no filters)
    - Look up a specific CVE with full detail (cve="CVE-2026-41108") -- works
      across all months, returns KBs, affected products, CVSS, description, FAQs
    - Find which CVEs a KB article fixes (kb="5094123" or kb="KB5094123") --
      scans recent months
    - Search by keyword (query="Exchange" or query="DNS spoofing")
    - Filter to a product (product="Windows Server 2022") -- partial match
    - Filter by severity (severity="Critical") -- Critical/Important/Moderate/Low
    - Find actively exploited vulnerabilities (exploited=True)
    - Find publicly disclosed zero-days (publicly_disclosed=True)
    - Filter by CVSS score (min_cvss=8.0)
    - Look at a past month (month="2026-Apr" or month="2026-04")
    - Combine filters (product="Exchange" + severity="Critical" + month="2026-05")
    - Paginate with offset (offset=10, limit=10 for page 2)

    Args:
        query: Optional keyword; case-insensitive match across CVE ID, title,
            description, component tag, and affected product names.
        cve: Optional CVE ID (e.g. "CVE-2026-41108"). Fast path: ignores other
            filters and returns full detail for that single CVE, searching
            across all months automatically.
        kb: Optional KB article number (e.g. "5094123" or "KB5094123"). Fast
            path: returns all CVEs fixed by that KB, scanning the most recent
            months (up to 6).
        month: Optional monthly release to search, formatted "2026-Apr" or
            "2026-04". Defaults to the latest available release.
        product: Optional product name filter (case-insensitive partial match
            against affected product names, e.g. "Windows Server 2022").
        severity: Optional maximum-severity filter. Valid values: Critical,
            Important, Moderate, Low.
        exploited: Optional filter for vulnerabilities known to be exploited
            in the wild (True) or not (False).
        publicly_disclosed: Optional filter for publicly disclosed
            vulnerabilities.
        min_cvss: Optional minimum CVSS base score (0-10).
        limit: Maximum number of results to return (default: 10, max: 100).
            Set to 0 with include_stats=True for a stats-only month overview.
        offset: Number of results to skip for pagination (default: 0).
        include_stats: When True, includes aggregate counts (by severity,
            impact, product family, exploited, publicly disclosed) for the
            filtered result set.

    Returns:
        Dictionary with:
        - month: Release ID (e.g. "2026-Jun") and title/release date
        - total_found: Number of vulnerabilities matching the filters
        - vulnerabilities: List of compact vulnerability summaries (up to
          limit); full detail returned for cve= lookups
        - filters_applied: Summary of which filters were used
        - stats: (only when include_stats=True) aggregate counts
    """
    start = time.perf_counter()
    result = await _search_impl(
        query=query,
        cve=cve,
        kb=kb,
        month=month,
        product=product,
        severity=severity,
        exploited=exploited,
        publicly_disclosed=publicly_disclosed,
        min_cvss=min_cvss,
        limit=limit,
        offset=offset,
        include_stats=include_stats,
    )
    telemetry.track_tool_call(
        "msrc_search",
        result.get("filters_applied", {}),
        result.get("total_found", 0),
        (time.perf_counter() - start) * 1000,
    )
    return result


async def _search_impl(
    query: str | None,
    cve: str | None,
    kb: str | None,
    month: str | None,
    product: str | None,
    severity: str | None,
    exploited: bool | None,
    publicly_disclosed: bool | None,
    min_cvss: float | None,
    limit: int,
    offset: int,
    include_stats: bool,
) -> dict:
    # --- CVE fast path: cross-month single-CVE detail lookup ---
    if cve:
        return await _lookup_cve(cve)

    # --- KB fast path: which CVEs does this KB fix ---
    if kb:
        return await _lookup_kb(kb)

    filters_applied = _build_filters_summary(
        query=query,
        month=month,
        product=product,
        severity=severity,
        exploited=exploited,
        publicly_disclosed=publicly_disclosed,
        min_cvss=min_cvss,
        offset=offset,
    )

    # Validate inputs before any network call
    if severity is not None:
        severity = severity.capitalize()
        if severity not in SEVERITY_ORDER:
            return _error(
                f"Invalid severity: {severity!r}. "
                f"Valid values: {', '.join(SEVERITY_ORDER)}",
                filters_applied,
            )

    month_id: str | None = None
    if month is not None:
        month_id = msrc_api.normalize_month_id(month)
        if month_id is None:
            return _error(
                f"Invalid month: {month!r}. Use formats like '2026-Apr' or '2026-04'.",
                filters_applied,
            )

    limit = max(0, min(limit, MAX_LIMIT))
    offset = max(0, offset)

    try:
        if month_id is None:
            month_id = await msrc_api.get_latest_month_id()
        release = await msrc_api.fetch_month(month_id)
    except MsrcApiError as exc:
        if "not found" in str(exc):
            return _error(f"No security update release found for {month_id}.", filters_applied)
        return _error(str(exc), filters_applied)

    matched = _filter_vulnerabilities(
        release.vulnerabilities,
        query=query,
        product=product,
        severity=severity,
        exploited=exploited,
        publicly_disclosed=publicly_disclosed,
        min_cvss=min_cvss,
    )
    matched = sort_vulnerabilities(matched)

    response = {
        **_release_header(release),
        "total_found": len(matched),
        "vulnerabilities": [v.to_summary_dict() for v in matched[offset : offset + limit]],
        "filters_applied": filters_applied,
    }
    if include_stats:
        response["stats"] = MonthlyRelease(
            id=release.id, vulnerabilities=matched
        ).stats()
    return response


async def _lookup_cve(cve: str) -> dict:
    cve = cve.strip().upper()
    filters_applied = {"cve": cve}
    if not _CVE_RE.match(cve):
        return _error(
            f"Invalid CVE format: {cve!r}. Expected e.g. 'CVE-2026-41108'.",
            filters_applied,
        )

    try:
        month_id = await msrc_api.find_month_for_cve(cve)
        if month_id is None:
            return _error(f"{cve} was not found in the MSRC Security Update Guide.",
                          filters_applied)
        release = await msrc_api.fetch_month(month_id)
    except MsrcApiError as exc:
        return _error(str(exc), filters_applied)

    vuln = next((v for v in release.vulnerabilities if v.cve == cve), None)
    if vuln is None:
        return _error(
            f"{cve} is listed under {month_id} but has no entry in that document.",
            filters_applied,
        )

    return {
        **_release_header(release),
        "total_found": 1,
        "vulnerabilities": [vuln.to_detail_dict()],
        "filters_applied": filters_applied,
    }


async def _lookup_kb(kb: str) -> dict:
    kb_number = kb.strip().upper().removeprefix("KB").strip()
    filters_applied = {"kb": f"KB{kb_number}"}
    if not kb_number.isdigit():
        return _error(
            f"Invalid KB number: {kb!r}. Expected e.g. '5094123' or 'KB5094123'.",
            filters_applied,
        )

    try:
        entries = await msrc_api.fetch_update_index()
    except MsrcApiError as exc:
        return _error(str(exc), filters_applied)

    for entry in entries[:KB_SCAN_MONTHS]:
        try:
            release = await msrc_api.fetch_month(entry["id"])
        except MsrcApiError:
            continue
        matched = [
            v
            for v in release.vulnerabilities
            if any(k.kb == kb_number for k in v.kb_articles)
        ]
        if matched:
            matched = sort_vulnerabilities(matched)
            return {
                **_release_header(release),
                "total_found": len(matched),
                "vulnerabilities": [v.to_summary_dict() for v in matched],
                "filters_applied": filters_applied,
            }

    return _error(
        f"KB{kb_number} was not found in the last {KB_SCAN_MONTHS} monthly releases.",
        filters_applied,
    )


def _filter_vulnerabilities(
    vulnerabilities: list[Vulnerability],
    query: str | None,
    product: str | None,
    severity: str | None,
    exploited: bool | None,
    publicly_disclosed: bool | None,
    min_cvss: float | None,
) -> list[Vulnerability]:
    query_lower = query.lower() if query else None
    product_lower = product.lower() if product else None

    matched = []
    for v in vulnerabilities:
        if query_lower:
            haystack = " ".join(
                [v.cve, v.title, v.description, v.tag, *v.affected_products]
            ).lower()
            if query_lower not in haystack:
                continue
        if product_lower:
            if not any(product_lower in p.lower() for p in v.affected_products):
                continue
        if severity and v.severity != severity:
            continue
        if exploited is not None and v.exploited != exploited:
            continue
        if publicly_disclosed is not None and v.publicly_disclosed != publicly_disclosed:
            continue
        if min_cvss is not None and (v.max_cvss is None or v.max_cvss < min_cvss):
            continue
        matched.append(v)
    return matched


def _release_header(release: MonthlyRelease) -> dict:
    return {
        "month": release.id,
        "title": release.title,
        "release_date": release.initial_release_date,
    }


def _build_filters_summary(**filters) -> dict:
    summary = {k: v for k, v in filters.items() if v not in (None, 0)}
    if not summary:
        summary["note"] = (
            "No filters applied; returning the most urgent vulnerabilities "
            "from the latest release"
        )
    return summary


def _error(message: str, filters_applied: dict) -> dict:
    return {
        "total_found": 0,
        "vulnerabilities": [],
        "filters_applied": filters_applied,
        "error": message,
    }
