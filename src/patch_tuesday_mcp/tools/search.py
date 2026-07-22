"""Unified search tool for querying MSRC security updates (Patch Tuesday)."""

import asyncio
import logging
import re
import time
from typing import Annotated

from pydantic import Field

from .. import telemetry
from ..feeds import enrichment, known_issues, msrc_api
from ..feeds.msrc_api import MsrcApiError
from ..models.vulnerability import (
    EXPLOITATION_LIKELY_VALUES,
    SEVERITY_ORDER,
    MonthlyRelease,
    Vulnerability,
    compute_stats,
    sort_vulnerabilities,
)
from . import formatters, profiles

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# How many recent months a KB lookup scans before giving up
KB_SCAN_MONTHS = 6

# How many KB numbers a single batched kb=[...] lookup accepts
MAX_KB_BATCH = 30

# Supersedence chain walking: max hops followed and how many monthly docs
# (starting at the queried KB's month) may be scanned for predecessors
CHAIN_MAX_DEPTH = 12
CHAIN_SCAN_MONTHS = 24

MAX_LIMIT = 100

# Output formats for the monthly search view. "json" (default) is the most
# complete; "markdown"/"csv" add an additive triage rendering of the page.
OUTPUT_FORMATS = {"json", "markdown", "csv"}
REPORT_KINDS = {None, "triage"}

# Historical trend search: how many released months a single request may span.
MAX_TREND_MONTHS = 12

# Allowed single-letter values for the CVSS v3.x base-metric filters.
CVSS_FILTER_VALUES = {
    "attack_vector": {"N", "A", "L", "P"},
    "privileges_required": {"N", "L", "H"},
    "user_interaction": {"N", "R"},
    "scope": {"U", "C"},
}


async def msrc_search(
    query: str | None = None,
    cve: str | None = None,
    kb: str | list[str] | None = None,
    month: str | None = None,
    product: str | None = None,
    product_profile: str | None = None,
    products: list[str] | None = None,
    product_families: list[str] | None = None,
    severity: str | None = None,
    exploited: bool | None = None,
    publicly_disclosed: bool | None = None,
    kev: bool | None = None,
    ransomware: bool | None = None,
    exploitation_likely: bool | None = None,
    cwe: str | None = None,
    min_epss: Annotated[float | None, Field(ge=0, le=1)] = None,
    min_cvss: Annotated[float | None, Field(ge=0, le=10)] = None,
    attack_vector: str | None = None,
    privileges_required: str | None = None,
    user_interaction: str | None = None,
    scope: str | None = None,
    include_chain: bool = False,
    include_guidance: bool = False,
    include_references: bool = False,
    include_kb_details: bool = False,
    include_kev_details: bool = False,
    include_known_issues: bool = False,
    include_update_summary: bool = False,
    include_temporal: bool = False,
    list_months: bool = False,
    format: str = "json",
    report: str | None = None,
    force_refresh: bool = False,
    include_freshness: bool = False,
    months_back: int | None = None,
    start_month: str | None = None,
    end_month: str | None = None,
    limit: Annotated[int, Field(ge=0, le=MAX_LIMIT)] = 10,
    offset: Annotated[int, Field(ge=0)] = 0,
    include_stats: bool = False,
) -> dict:
    """Search Microsoft security updates (Patch Tuesday) from the official MSRC API.

    Combines keyword search, CVE/KB lookup, and product/severity/exploitation
    filtering into a single flexible tool. All filter parameters are optional
    and can be combined. When no filters are provided, returns the most urgent
    vulnerabilities from the most recent *released* Patch Tuesday (CISA-KEV-
    listed or exploited first, then by EPSS exploitation probability, severity,
    and CVSS score). The upcoming month's document exists before its Patch
    Tuesday but only holds early Chromium/third-party and out-of-band entries;
    it is skipped by default and served only when requested via month=.
    Results are enriched with EPSS scores (FIRST.org daily exploit
    prediction, 0-1) and CISA KEV (Known Exploited Vulnerabilities) catalog
    data when available.

    Use this tool to:
    - Get the latest Patch Tuesday overview (include_stats=True, limit=0)
    - Browse the most urgent fixes this month (no filters)
    - Look up a specific CVE with full detail (cve="CVE-2026-41108") -- works
      across all months, returns KBs, affected products, CVSS, description,
      FAQs, EPSS score, and KEV status
    - Find which CVEs a KB article fixes (kb="5094123" or kb="KB5094123") --
      scans recent months, or a specific month when combined with month=
    - Look up many KBs in one call (kb=["5094123", "KB5094127", ...], up to
      30) -- e.g. a machine's installed-update list; returns one grouped
      per-KB result entry each, with per-KB found/not-found status
    - Check whether a KB has been superseded by newer patches (kb="5087538",
      include_chain=True) -- walks Microsoft-stated supersedence links
    - See what Microsoft has confirmed an update breaks (kb=...,
      include_known_issues=True) -- known issues from the KB's public support
      page: symptoms, workarounds, and the resolving update when stated
    - See what an update changes (kb=..., include_update_summary=True) -- the
      KB support page's summary and improvements highlights, beyond the
      security fixes already listed in the MSRC data
    - Find KEV-listed CVEs this month (kev=True) -- confirmed exploited, with
      federal remediation due dates
    - High exploitation probability (min_epss=0.5) -- EPSS >= 50%
    - Search by keyword (query="Exchange" or query="DNS spoofing")
    - Filter to a product (product="Windows Server 2022") -- partial match
    - Filter to a product watchlist (product_profile="identity-core", or
      products=["Exchange Server", "Windows Server"] /
      product_families=["Windows", "Azure"]) -- keeps vulns matching any listed
      product or family; matching is local and profiles never leave the host
    - Filter by severity (severity="Critical") -- Critical/Important/Moderate/Low
    - Find actively exploited vulnerabilities (exploited=True)
    - Find publicly disclosed zero-days (publicly_disclosed=True)
    - Filter by CVSS score (min_cvss=8.0)
    - Look at a past month (month="2026-Apr" or month="2026-04")
    - Combine filters (product="Exchange" + severity="Critical" + month="2026-05")
    - Search a historical range (query="HTTP.sys" + months_back=6, or
      start_month="2026-Jan" + end_month="2026-Jun") -- aggregates matching
      CVEs across released months with per-month trend counts
    - Paginate with offset (offset=10, limit=10 for page 2)

    Args:
        query: Optional keyword; case-insensitive match across CVE ID, title,
            description, component tag, and affected product names.
        cve: Optional CVE ID (e.g. "CVE-2026-41108"). Fast path: ignores other
            filters and returns full detail for that single CVE, searching
            across all months automatically.
        kb: Optional KB article number (e.g. "5094123" or "KB5094123") or a
            list of up to 30 of them for a batched lookup. Fast path: returns
            the CVEs fixed by that KB, scanning the most recent months (up to
            6), or only the given month when month= is also set. A list input
            returns a grouped response instead: a results array with one entry
            per KB ("kb", "found", and on success the same body as a
            single-KB lookup; on a miss "error"/"error_kind"), deduplicated,
            order preserved. limit/offset apply per KB; other filters are
            ignored. Accepts numeric KB ids only (any malformed list entry
            fails the whole call); kb_articles in results may also contain
            non-KB vendor-fix labels such as "Release Notes", which cannot be
            looked up here.
        month: Optional monthly release to search, formatted "2026-Apr" or
            "2026-04". Defaults to the most recent release whose Patch
            Tuesday (second Tuesday of the month) has already occurred; pass
            the upcoming month explicitly to see its pre-release entries.
            Combined with kb=, restricts the KB lookup to that month.
        product: Optional product name filter (case-insensitive partial match
            against affected product names, e.g. "Windows Server 2022").
        product_profile: Optional named watchlist (e.g. "identity-core") that
            expands locally into product/family matchers. Built-in profiles can
            be overridden/extended via a JSON file at MSRC_PROFILES_PATH. An
            unknown name returns an invalid_input error listing the available
            profiles. Profile contents are matched locally and never sent to
            MSRC, FIRST.org, CISA, or telemetry.
        products: Optional list of product-name partial matchers. A vulnerability
            is kept if any entry matches one of its affected products.
        product_families: Optional list of product-family partial matchers. A
            vulnerability is kept if any entry matches one of its product
            families. Combined with products/product_profile as a union (match
            any listed product OR family).
        severity: Optional maximum-severity filter. Valid values: Critical,
            Important, Moderate, Low.
        exploited: Optional filter for vulnerabilities known to be exploited
            in the wild (True) or not (False), per Microsoft's assessment.
        publicly_disclosed: Optional filter for publicly disclosed
            vulnerabilities.
        kev: Optional filter for CVEs on (True) or off (False) the CISA Known
            Exploited Vulnerabilities catalog.
        ransomware: Optional filter for CVEs whose CISA KEV entry reports
            known ransomware campaign use (True) or not / not on KEV (False).
        exploitation_likely: Optional filter on Microsoft's latest-release
            exploitation assessment: True matches "Exploitation More Likely"
            or "Exploitation Detected"; False matches everything else
            (including unassessed entries). Matching results include an
            exploitation_assessment field.
        cwe: Optional weakness filter; case-insensitive substring match
            against CWE entries (e.g. "CWE-416" or "use after free").
            Matching results include their cwe list.
        min_epss: Optional minimum EPSS score (0-1), the probability of
            exploitation in the next 30 days (e.g. 0.5 for >= 50%).
        min_cvss: Optional minimum CVSS base score (0-10).
        attack_vector: Optional CVSS attack-vector filter, one of N (network),
            A (adjacent), L (local), P (physical). Matches the parsed CVSS v3.x
            vector; entries without a parseable vector are excluded.
        privileges_required: Optional CVSS privileges-required filter, one of
            N (none), L (low), H (high).
        user_interaction: Optional CVSS user-interaction filter, one of
            N (none), R (required).
        scope: Optional CVSS scope filter, one of U (unchanged), C (changed).
        include_chain: When True together with kb=, adds a supersedence_chain
            showing which KBs this KB replaces (newest to oldest), walked from
            Microsoft-stated supersedence links. Ignored without kb=.
        include_guidance: When True together with cve=, adds a guidance list to
            the CVE detail output with any Microsoft-provided mitigations,
            workarounds, and will-not-fix advisories (type/description/url).
            Omitted by default to keep responses lean. Ignored without cve=.
        include_references: When True, adds deterministic reference links
            (MSRC, NVD, EPSS, and KEV when listed) to each result row in
            month/KB/trend lists. CVE detail lookups always include them.
        include_kb_details: When True, kb_articles entries become full objects
            (per-KB url, fixed_build, supersedence, sub_type, and
            restart_required) instead of bare KB numbers; on cve= lookups it
            additionally adds restart_required to each KB entry.
        include_kev_details: When True, KEV-listed rows carry the full KEV
            entry (due_date, ransomware_use, required_action, vendor_project,
            product, vulnerability_name) instead of a boolean flag; on cve=
            lookups it extends the kev block with the extra catalog fields.
        include_known_issues: When True together with kb=, adds a known_issues
            block per KB with the issues Microsoft has publicly confirmed for
            that update (title, symptoms, workaround, and the resolving KB
            when stated), scraped best-effort from the KB's support page on
            support.microsoft.com. This reports what Microsoft has confirmed
            breaks -- it does not predict behavior in a specific environment.
            The block's status field is honest about coverage: "published"
            (issues listed), "none_published" (Microsoft publishes no
            known-issues data for this KB -- the norm for most non-Windows
            products; Windows cumulative/preview updates are the main
            source), or "unavailable" (the page could not be fetched or
            parsed; NOT the same as no issues). Attached even when the KB is
            not found in MSRC security releases (e.g. preview-only updates).
            Ignored without kb=.
        include_update_summary: When True together with kb=, adds an
            update_summary block per KB describing what the update changes,
            scraped best-effort from the same support.microsoft.com KB page:
            the page's Summary/Highlights text plus its Improvements bullet
            list (size-capped; truncated=True marks a capped block). The
            status field is honest like known_issues: "published" (a summary
            exists), "none_published" (Microsoft publishes no summary section
            for this KB), or "unavailable" (the page could not be fetched or
            parsed; NOT the same as no summary). Attached even when the KB is
            not found in MSRC security releases; combines freely with
            include_known_issues -- both blocks are served by a single fetch
            of the same page. Ignored without kb=.
        include_temporal: When True, cvss blocks gain the CVSS temporal score
            Microsoft publishes (exploit-code maturity adjusted). Applies to
            cve= detail and to list rows that carry a cvss block.
        list_months: When True, ignore other filters and return the catalog of
            available monthly releases (id, title, initial/current release
            dates, newest first) — useful for discovering valid month= values
            and spotting same-month revisions.
        format: Output format for a monthly/filtered search: "json" (default,
            most complete), "markdown", or "csv". "markdown" adds a prioritized
            triage briefing (executive summary + table) under a markdown key;
            "csv" adds a spreadsheet-ready table under a csv key plus a columns
            list. The JSON vulnerabilities list is always included. Ignored for
            cve=/kb= fast-path lookups.
        report: Optional report profile for format="markdown"/"csv". Currently
            only "triage" (the default rendering) is supported; reserved for
            future report shapes.
        force_refresh: When True, bypass the in-process caches for this request
            and re-fetch the MSRC document and EPSS/KEV enrichment from source.
            Use to pick up a same-day MSRC revision or fresh EPSS/KEV data.
            Only the data needed for this request is refreshed; unrelated cached
            months are left intact.
        include_freshness: When True (or when force_refresh is used), add a
            freshness block to the response reporting the cache age and TTL of
            the MSRC document and the EPSS/KEV enrichment data.
        months_back: Optional historical-trend control; search the N most recent
            released months (N >= 1) instead of a single month, aggregating
            matches with per-month counts. Mutually exclusive with
            start_month/end_month. Capped at 12 months per request.
        start_month: Optional start of a historical-trend range (e.g. "2026-Jan"
            or "2026-01"), inclusive. When end_month is omitted the range runs
            through the latest released month. Capped at 12 months.
        end_month: Optional end of a historical-trend range (inclusive); requires
            start_month (or months_back). Pre-release months are excluded.
        limit: Maximum number of results to return (default: 10, max: 100).
            Set to 0 with include_stats=True for a stats-only month overview.
        offset: Number of results to skip for pagination (default: 0).
        include_stats: When True, includes aggregate counts (by severity,
            impact, product family, exploited, KEV, publicly disclosed) for
            the filtered result set.

    Returns:
        Dictionary with:
        - month: Release ID (e.g. "2026-Jun") and title/release date
        - total_found: Number of vulnerabilities matching the filters
        - vulnerabilities: List of compact vulnerability summaries (up to
          limit) with epss_score and kev flag when available; full detail
          (epss_percentile, KEV due dates) returned for cve= lookups
        - filters_applied: Summary of which filters were used
        - stats: (only when include_stats=True) aggregate counts
        - supersedence_chain / chain_complete: (only for kb= lookups with
          include_chain=True) the walked chain, newest to oldest
        - known_issues: (only for kb= lookups with include_known_issues=True)
          per-KB block with status ("published" / "none_published" /
          "unavailable"), an issues list (title, symptoms, workaround,
          resolution, resolved_by) when published, a note otherwise, and the
          source_url of the Microsoft support page
        - update_summary: (only for kb= lookups with
          include_update_summary=True) per-KB block with status ("published"
          / "none_published" / "unavailable"), the page title, a summary
          string and an improvements list of what the update changes when
          published (truncated=True when size caps trimmed content), a note
          otherwise, and the source_url of the Microsoft support page
        - total_kbs / results: (only when kb= is a list) grouped batch output;
          results holds one entry per KB with kb, found, and either the
          single-KB response body or a per-KB error/error_kind, while the
          top-level total_found sums across all KBs
        - guidance: (only for cve= lookups with include_guidance=True) list of
          mitigation/workaround/will-not-fix advisories, when Microsoft
          provides them
        - format / markdown / csv / columns: (only when format="markdown" or
          "csv") the chosen format plus the rendered triage view; csv also
          carries the stable column-name list
        - freshness: (only with include_freshness=True or force_refresh=True)
          cache age/TTL for the MSRC document and EPSS/KEV enrichment
        - range / months_searched / trend: (only for historical-trend searches
          via months_back or start_month/end_month) the resolved month range,
          the number of months searched, and per-month aggregate counts
          (total, by_severity, exploited, publicly_disclosed, kev)
        - available_months: (only with list_months=True) the release catalog,
          newest first
        - error / error_kind: (only on failure) a message plus a category
          (invalid_input, not_found, upstream, internal)
        - note: (when relevant) explains month selection, e.g. that a newer
          pre-Patch-Tuesday document was skipped, or (with
          release_status="pre-patch-tuesday") that the requested month has
          not had its Patch Tuesday yet
    """
    start = time.perf_counter()
    try:
        result = await _search_impl(
            query=query,
            cve=cve,
            kb=kb,
            month=month,
            product=product,
            product_profile=product_profile,
            products=products,
            product_families=product_families,
            severity=severity,
            exploited=exploited,
            publicly_disclosed=publicly_disclosed,
            kev=kev,
            ransomware=ransomware,
            exploitation_likely=exploitation_likely,
            cwe=cwe,
            min_epss=min_epss,
            min_cvss=min_cvss,
            attack_vector=attack_vector,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            include_chain=include_chain,
            include_guidance=include_guidance,
            include_references=include_references,
            include_kb_details=include_kb_details,
            include_kev_details=include_kev_details,
            include_known_issues=include_known_issues,
            include_update_summary=include_update_summary,
            include_temporal=include_temporal,
            list_months=list_months,
            format=format,
            report=report,
            force_refresh=force_refresh,
            include_freshness=include_freshness,
            months_back=months_back,
            start_month=start_month,
            end_month=end_month,
            limit=limit,
            offset=offset,
            include_stats=include_stats,
        )
    except Exception:
        # Contract: msrc_search never raises. Anything _search_impl did not
        # convert itself (unexpected CVRF shapes, plumbing bugs) is logged
        # server-side and reported generically so internals don't leak.
        logger.exception("msrc_search failed unexpectedly")
        result = {
            "total_found": 0,
            "vulnerabilities": [],
            "filters_applied": {},
            "error": "The search failed due to an unexpected internal error.",
            "error_kind": "internal",
        }
    telemetry.track_tool_call(
        "msrc_search",
        result.get("filters_applied", {}),
        result.get("total_found", 0),
        (time.perf_counter() - start) * 1000,
        error_kind=result.get("error_kind", ""),
    )
    return result


async def _search_impl(
    query: str | None,
    cve: str | None,
    kb: str | list[str] | None,
    month: str | None,
    product: str | None,
    product_profile: str | None,
    products: list[str] | None,
    product_families: list[str] | None,
    severity: str | None,
    exploited: bool | None,
    publicly_disclosed: bool | None,
    kev: bool | None,
    ransomware: bool | None,
    exploitation_likely: bool | None,
    cwe: str | None,
    min_epss: float | None,
    min_cvss: float | None,
    attack_vector: str | None,
    privileges_required: str | None,
    user_interaction: str | None,
    scope: str | None,
    include_chain: bool,
    include_guidance: bool,
    include_references: bool,
    include_kb_details: bool,
    include_kev_details: bool,
    include_known_issues: bool,
    include_update_summary: bool,
    include_temporal: bool,
    list_months: bool,
    format: str,
    report: str | None,
    force_refresh: bool,
    include_freshness: bool,
    months_back: int | None,
    start_month: str | None,
    end_month: str | None,
    limit: int,
    offset: int,
    include_stats: bool,
) -> dict:
    # --- CVE fast path: cross-month single-CVE detail lookup ---
    if cve:
        return await _lookup_cve(
            cve,
            include_guidance,
            force_refresh,
            include_kb_details=include_kb_details,
            include_kev_details=include_kev_details,
            include_temporal=include_temporal,
        )

    # --- KB fast path: which CVEs does this KB fix ---
    if isinstance(kb, list):
        return await _lookup_kbs(
            kb,
            include_chain,
            month,
            limit,
            offset,
            force_refresh,
            include_references=include_references,
            include_kb_details=include_kb_details,
            include_kev_details=include_kev_details,
            include_known_issues=include_known_issues,
            include_update_summary=include_update_summary,
        )
    if kb:
        return await _lookup_kb(
            kb,
            include_chain,
            month,
            limit,
            offset,
            force_refresh,
            include_references=include_references,
            include_kb_details=include_kb_details,
            include_kev_details=include_kev_details,
            include_known_issues=include_known_issues,
            include_update_summary=include_update_summary,
        )

    # --- Release-catalog discovery: which months exist ---
    if list_months:
        return await _list_months(force_refresh)

    filters_applied = _build_filters_summary(
        query=query,
        month=month,
        product=product,
        product_profile=product_profile,
        products=products,
        product_families=product_families,
        severity=severity,
        exploited=exploited,
        publicly_disclosed=publicly_disclosed,
        kev=kev,
        ransomware=ransomware,
        exploitation_likely=exploitation_likely,
        cwe=cwe,
        min_epss=min_epss,
        min_cvss=min_cvss,
        attack_vector=attack_vector,
        privileges_required=privileges_required,
        user_interaction=user_interaction,
        scope=scope,
        format=format if format != "json" else None,
        report=report,
        force_refresh=force_refresh if force_refresh else None,
        months_back=months_back,
        start_month=start_month,
        end_month=end_month,
        offset=offset,
    )

    # Validate inputs before any network call
    fmt = (format or "json").lower()
    if fmt not in OUTPUT_FORMATS:
        return _error(
            f"Invalid format: {format!r}. Valid values: {', '.join(sorted(OUTPUT_FORMATS))}.",
            filters_applied,
        )
    if report not in REPORT_KINDS:
        valid = ", ".join(sorted(r for r in REPORT_KINDS if r))
        return _error(
            f"Invalid report: {report!r}. Valid values: {valid}.",
            filters_applied,
        )
    if severity is not None:
        severity = severity.capitalize()
        if severity not in SEVERITY_ORDER:
            return _error(
                f"Invalid severity: {severity!r}. Valid values: {', '.join(SEVERITY_ORDER)}",
                filters_applied,
            )

    vector_filters: dict[str, str] = {}
    for name, value in (
        ("attack_vector", attack_vector),
        ("privileges_required", privileges_required),
        ("user_interaction", user_interaction),
        ("scope", scope),
    ):
        if value is None:
            continue
        normalized = value.strip().upper()
        allowed = CVSS_FILTER_VALUES[name]
        if normalized not in allowed:
            return _error(
                f"Invalid {name}: {value!r}. Valid values: {', '.join(sorted(allowed))}.",
                filters_applied,
            )
        vector_filters[name] = normalized

    # Resolve a named product profile (watchlist) into product/family matcher
    # lists, merged with any explicit products/product_families. Matching stays
    # local; profile contents are never sent to MSRC or telemetry.
    product_terms = list(products or [])
    family_terms = list(product_families or [])
    if product_profile:
        try:
            prof_products, prof_families = profiles.resolve_profile(product_profile)
        except profiles.ProfileError as exc:
            return _error(str(exc), filters_applied)
        product_terms += prof_products
        family_terms += prof_families

    limit = max(0, min(limit, MAX_LIMIT))
    offset = max(0, offset)

    # --- Historical trend path: aggregate across a range of released months ---
    summary_options = {
        "include_references": include_references,
        "include_kb_details": include_kb_details,
        "include_kev_details": include_kev_details,
        "include_temporal": include_temporal,
        "include_cwe": cwe is not None,
        "include_exploitability": exploitation_likely is not None,
    }

    if months_back is not None or start_month is not None or end_month is not None:
        return await _trend_search(
            filters_applied=filters_applied,
            query=query,
            product=product,
            product_terms=product_terms,
            family_terms=family_terms,
            severity=severity,
            exploited=exploited,
            publicly_disclosed=publicly_disclosed,
            kev=kev,
            ransomware=ransomware,
            exploitation_likely=exploitation_likely,
            cwe=cwe,
            min_epss=min_epss,
            min_cvss=min_cvss,
            vector_filters=vector_filters,
            summary_options=summary_options,
            months_back=months_back,
            start_month=start_month,
            end_month=end_month,
            fmt=fmt,
            force_refresh=force_refresh,
            include_freshness=include_freshness,
            limit=limit,
            offset=offset,
            include_stats=include_stats,
        )

    month_id: str | None = None
    if month is not None:
        month_id = msrc_api.normalize_month_id(month)
        if month_id is None:
            return _invalid_month_error(month, filters_applied)

    skipped_pre_release: str | None = None
    try:
        if month_id is None:
            month_id, skipped_pre_release = await msrc_api.get_default_month_id(
                force_refresh=force_refresh
            )
        release = await msrc_api.fetch_month(month_id, force_refresh=force_refresh)
    except MsrcApiError as exc:
        if "not found" in str(exc):
            return _error(
                f"No security update release found for {month_id}.",
                filters_applied,
                kind="not_found",
            )
        return _error(str(exc), filters_applied, kind="upstream")

    # Enrich the whole month (not just the returned page) so KEV/EPSS
    # filtering and sorting stay consistent across pagination
    await _enrich(release.vulnerabilities, force_refresh=force_refresh)

    matched = _filter_vulnerabilities(
        release.vulnerabilities,
        query=query,
        product=product,
        severity=severity,
        exploited=exploited,
        publicly_disclosed=publicly_disclosed,
        kev=kev,
        ransomware=ransomware,
        exploitation_likely=exploitation_likely,
        cwe=cwe,
        min_epss=min_epss,
        min_cvss=min_cvss,
        vector_filters=vector_filters,
        product_terms=product_terms,
        family_terms=family_terms,
    )
    matched = sort_vulnerabilities(matched)

    # Surface the parsed CVSS components in summaries when the caller filtered
    # on them, so it is clear why each result matched.
    include_cvss = bool(vector_filters)
    response = {
        **_release_header(release),
        "total_found": len(matched),
        "vulnerabilities": [
            v.to_summary_dict(include_cvss=include_cvss, **summary_options)
            for v in matched[offset : offset + limit]
        ],
        "filters_applied": filters_applied,
    }
    if include_stats:
        response["stats"] = compute_stats(matched)

    if fmt != "json":
        page = matched[offset : offset + limit]
        response["format"] = fmt
        if fmt == "markdown":
            response["markdown"] = formatters.render_markdown(
                page, _release_header(release), len(matched), all_vulns=matched
            )
        elif fmt == "csv":
            response["csv"] = formatters.render_csv(page)
            response["columns"] = list(formatters.TRIAGE_COLUMNS)

    if include_freshness or force_refresh:
        response["freshness"] = {
            "msrc": await msrc_api.month_freshness(month_id),
            "epss": enrichment.epss_freshness([v.cve for v in matched]),
            "kev": enrichment.kev_freshness(),
        }
        if force_refresh:
            response["freshness"]["force_refresh"] = True

    if skipped_pre_release:
        release_time = msrc_api.patch_tuesday_utc(skipped_pre_release)
        response["note"] = (
            f"A newer document for {skipped_pre_release} exists but its Patch Tuesday "
            f"({release_time:%Y-%m-%d}) has not occurred yet; showing the latest full "
            f"release. Pass month='{skipped_pre_release}' to see its early and "
            f"out-of-band entries."
        )
    elif month is not None:
        release_time = msrc_api.patch_tuesday_utc(month_id)
        if release_time is not None and release_time > msrc_api.utcnow():
            response["release_status"] = "pre-patch-tuesday"
            response["note"] = (
                f"{month_id}'s Patch Tuesday is {release_time:%Y-%m-%d}; this document "
                "currently contains only early and out-of-band entries (e.g. "
                "Chromium/third-party CVEs) and will fill in on release day."
            )

    return response


def _trend_entry(release: MonthlyRelease, matched: list[Vulnerability]) -> dict:
    """Compact per-month aggregate for a historical-trend response."""
    stats = compute_stats(matched)
    return {
        "month": release.id,
        "title": release.title,
        "total": len(matched),
        "by_severity": stats["by_severity"],
        "exploited": stats["exploited"],
        "publicly_disclosed": stats["publicly_disclosed"],
        "kev": stats["kev"],
    }


async def _trend_search(
    *,
    filters_applied: dict,
    query: str | None,
    product: str | None,
    product_terms: list[str],
    family_terms: list[str],
    severity: str | None,
    exploited: bool | None,
    publicly_disclosed: bool | None,
    kev: bool | None,
    ransomware: bool | None,
    exploitation_likely: bool | None,
    cwe: str | None,
    min_epss: float | None,
    min_cvss: float | None,
    vector_filters: dict[str, str],
    summary_options: dict,
    months_back: int | None,
    start_month: str | None,
    end_month: str | None,
    fmt: str,
    force_refresh: bool,
    include_freshness: bool,
    limit: int,
    offset: int,
    include_stats: bool,
) -> dict:
    """Aggregate matching vulnerabilities across a range of released months."""
    if months_back is not None and (start_month is not None or end_month is not None):
        return _error(
            "Specify either months_back or start_month/end_month, not both.",
            filters_applied,
        )
    if months_back is not None and months_back < 1:
        return _error("months_back must be >= 1.", filters_applied)
    if months_back is not None and months_back > MAX_TREND_MONTHS:
        return _error(
            f"months_back={months_back} exceeds the maximum range; the maximum "
            f"is {MAX_TREND_MONTHS} months.",
            filters_applied,
        )
    if end_month is not None and start_month is None and months_back is None:
        return _error(
            "end_month requires start_month (or use months_back).", filters_applied
        )

    start_id: str | None = None
    end_id: str | None = None
    if start_month is not None:
        start_id = msrc_api.normalize_month_id(start_month)
        if start_id is None:
            return _invalid_month_error(start_month, filters_applied)
    if end_month is not None:
        end_id = msrc_api.normalize_month_id(end_month)
        if end_id is None:
            return _invalid_month_error(end_month, filters_applied)

    now = msrc_api.utcnow()
    try:
        entries = await msrc_api.fetch_update_index(force_refresh=force_refresh)
    except MsrcApiError as exc:
        return _error(str(exc), filters_applied, kind="upstream")

    # Released months only (newest-first, matching fetch_update_index ordering)
    released = [
        e
        for e in entries
        if (rt := msrc_api.patch_tuesday_utc(e["id"])) is not None and rt <= now
    ]
    if not released:
        return _error(
            "No released monthly security updates found.",
            filters_applied,
            kind="not_found",
        )

    if months_back is not None:
        selected = released[:months_back]
    else:
        start_dt = msrc_api.patch_tuesday_utc(start_id)
        end_dt = msrc_api.patch_tuesday_utc(end_id) if end_id else now
        if start_dt is None or end_dt is None:
            return _error("Invalid month range.", filters_applied)
        if start_dt > end_dt:
            return _error(
                "start_month must be on or before end_month.", filters_applied
            )
        selected = [
            e for e in released if start_dt <= msrc_api.patch_tuesday_utc(e["id"]) <= end_dt
        ]

    if not selected:
        return _error(
            "No released months matched the requested range.",
            filters_applied,
            kind="not_found",
        )
    if len(selected) > MAX_TREND_MONTHS:
        return _error(
            f"Requested range spans {len(selected)} months; the maximum is "
            f"{MAX_TREND_MONTHS}. Narrow the range with months_back or "
            "start_month/end_month.",
            filters_applied,
        )

    try:
        releases = await asyncio.gather(
            *(msrc_api.fetch_month(e["id"], force_refresh=force_refresh) for e in selected)
        )
    except MsrcApiError as exc:
        return _error(str(exc), filters_applied, kind="upstream")

    # Enrich the whole range once so KEV/EPSS filtering and sorting stay
    # consistent across months and pagination.
    all_vulns = [v for release in releases for v in release.vulnerabilities]
    await _enrich(all_vulns, force_refresh=force_refresh)

    include_cvss = bool(vector_filters)
    trend: list[dict] = []
    combined: list[Vulnerability] = []
    for release in releases:
        month_matched = _filter_vulnerabilities(
            release.vulnerabilities,
            query=query,
            product=product,
            severity=severity,
            exploited=exploited,
            publicly_disclosed=publicly_disclosed,
            kev=kev,
            ransomware=ransomware,
            exploitation_likely=exploitation_likely,
            cwe=cwe,
            min_epss=min_epss,
            min_cvss=min_cvss,
            vector_filters=vector_filters,
            product_terms=product_terms,
            family_terms=family_terms,
        )
        combined.extend(month_matched)
        trend.append(_trend_entry(release, month_matched))

    combined = sort_vulnerabilities(combined)
    page = combined[offset : offset + limit]

    response: dict = {
        "range": {
            "start": selected[-1]["id"],
            "end": selected[0]["id"],
            "months": [e["id"] for e in selected],
        },
        "months_searched": len(selected),
        "total_found": len(combined),
        "vulnerabilities": [
            v.to_summary_dict(include_cvss=include_cvss, **summary_options) for v in page
        ],
        "trend": trend,
        "filters_applied": filters_applied,
    }
    if include_stats:
        response["stats"] = compute_stats(combined)

    if fmt != "json":
        response["format"] = fmt
        header = {
            "month": f"{selected[-1]['id']} → {selected[0]['id']}",
            "title": "Historical Trend",
        }
        if fmt == "markdown":
            response["markdown"] = formatters.render_markdown(
                page, header, len(combined), all_vulns=combined
            )
        elif fmt == "csv":
            response["csv"] = formatters.render_csv(page)
            response["columns"] = list(formatters.TRIAGE_COLUMNS)

    if include_freshness or force_refresh:
        response["freshness"] = {
            "msrc": [await msrc_api.month_freshness(e["id"]) for e in selected],
            "epss": enrichment.epss_freshness([v.cve for v in all_vulns]),
            "kev": enrichment.kev_freshness(),
        }
        if force_refresh:
            response["freshness"]["force_refresh"] = True

    return response


async def _enrich(vulnerabilities: list[Vulnerability], force_refresh: bool = False) -> None:
    """Attach KEV and EPSS data in place. Best-effort: fetch failures leave
    the enrichment fields unset and never raise."""
    kev_map, epss_map = await asyncio.gather(
        enrichment.fetch_kev(force_refresh=force_refresh),
        enrichment.fetch_epss([v.cve for v in vulnerabilities], force_refresh=force_refresh),
    )
    for v in vulnerabilities:
        kev_entry = kev_map.get(v.cve)
        if kev_entry is not None:
            v.kev = kev_entry
        scores = epss_map.get(v.cve)
        if scores is not None:
            v.epss_score, v.epss_percentile = scores


async def _lookup_cve(
    cve: str,
    include_guidance: bool = False,
    force_refresh: bool = False,
    include_kb_details: bool = False,
    include_kev_details: bool = False,
    include_temporal: bool = False,
) -> dict:
    cve = cve.strip().upper()
    filters_applied: dict = {"cve": cve}
    for name, flag in (
        ("include_guidance", include_guidance),
        ("include_kb_details", include_kb_details),
        ("include_kev_details", include_kev_details),
        ("include_temporal", include_temporal),
    ):
        if flag:
            filters_applied[name] = True
    if force_refresh:
        filters_applied["force_refresh"] = True
    if not _CVE_RE.match(cve):
        return _error(
            f"Invalid CVE format: {cve!r}. Expected e.g. 'CVE-2026-41108'.",
            filters_applied,
        )

    try:
        month_id = await msrc_api.find_month_for_cve(cve)
        if month_id is None:
            return _error(
                f"{cve} was not found in the MSRC Security Update Guide.",
                filters_applied,
                kind="not_found",
            )
        release = await msrc_api.fetch_month(month_id, force_refresh=force_refresh)
    except MsrcApiError as exc:
        return _error(str(exc), filters_applied, kind="upstream")

    vuln = next((v for v in release.vulnerabilities if v.cve == cve), None)
    if vuln is None:
        return _error(
            f"{cve} is listed under {month_id} but has no entry in that document.",
            filters_applied,
            kind="not_found",
        )

    await _enrich([vuln], force_refresh=force_refresh)

    return {
        **_release_header(release),
        "total_found": 1,
        "vulnerabilities": [
            vuln.to_detail_dict(
                include_guidance=include_guidance,
                include_kb_details=include_kb_details,
                include_kev_details=include_kev_details,
                include_temporal=include_temporal,
            )
        ],
        "filters_applied": filters_applied,
    }


async def _lookup_kb(
    kb: str,
    include_chain: bool = False,
    month: str | None = None,
    limit: int = 10,
    offset: int = 0,
    force_refresh: bool = False,
    include_references: bool = False,
    include_kb_details: bool = False,
    include_kev_details: bool = False,
    include_known_issues: bool = False,
    include_update_summary: bool = False,
) -> dict:
    """Single-KB lookup, optionally decorated from the KB's support page.

    The known-issues and update-summary blocks are best-effort and attach
    even when the KB is absent from MSRC security releases (preview-only
    updates publish support pages too) — but never to an invalid_input error,
    where there is no usable KB number to look up. Both blocks are served by
    a single fetch of the same page.
    """
    response = await _lookup_kb_msrc(
        kb,
        include_chain,
        month,
        limit,
        offset,
        force_refresh,
        include_references=include_references,
        include_kb_details=include_kb_details,
        include_kev_details=include_kev_details,
        include_known_issues=include_known_issues,
        include_update_summary=include_update_summary,
    )
    if response.get("error_kind") != "invalid_input":
        kb_number = kb.strip().upper().removeprefix("KB").strip()
        if include_known_issues:
            response["known_issues"] = await known_issues.fetch_known_issues(kb_number)
        if include_update_summary:
            response["update_summary"] = await known_issues.fetch_update_summary(kb_number)
    return response


async def _lookup_kb_msrc(
    kb: str,
    include_chain: bool = False,
    month: str | None = None,
    limit: int = 10,
    offset: int = 0,
    force_refresh: bool = False,
    include_references: bool = False,
    include_kb_details: bool = False,
    include_kev_details: bool = False,
    include_known_issues: bool = False,
    include_update_summary: bool = False,
) -> dict:
    kb_number = kb.strip().upper().removeprefix("KB").strip()
    filters_applied = {"kb": f"KB{kb_number}"}
    if month is not None:
        filters_applied["month"] = month
    for name, flag in (
        ("include_chain", include_chain),
        ("include_references", include_references),
        ("include_kb_details", include_kb_details),
        ("include_kev_details", include_kev_details),
        ("include_known_issues", include_known_issues),
        ("include_update_summary", include_update_summary),
    ):
        if flag:
            filters_applied[name] = True
    if force_refresh:
        filters_applied["force_refresh"] = True
    if not kb_number.isdigit():
        return _error(
            f"Invalid KB number: {kb!r}. Expected a numeric KB id like '5094123' or "
            "'KB5094123'. kb_articles entries such as 'Release Notes' are vendor-fix "
            "labels, not KB ids -- pick a numeric entry from kb_articles instead.",
            filters_applied,
        )

    month_id: str | None = None
    if month is not None:
        month_id = msrc_api.normalize_month_id(month)
        if month_id is None:
            return _invalid_month_error(month, filters_applied)

    limit = max(0, min(limit, MAX_LIMIT))
    offset = max(0, offset)

    try:
        entries = await msrc_api.fetch_update_index(force_refresh=force_refresh)
    except MsrcApiError as exc:
        return _error(str(exc), filters_applied, kind="upstream")

    if month_id is not None:
        candidates = [e for e in entries if e["id"] == month_id]
        if not candidates:
            return _error(
                f"No security update release found for {month_id}.",
                filters_applied,
                kind="not_found",
            )
    else:
        candidates = entries[:KB_SCAN_MONTHS]

    scan_failures = 0
    for entry in candidates:
        try:
            release = await msrc_api.fetch_month(entry["id"], force_refresh=force_refresh)
        except MsrcApiError as exc:
            # A missing month document is a real "not there"; anything else
            # (5xx, timeout) means the scan was incomplete and must not be
            # reported as a definitive not-found.
            if "not found" not in str(exc):
                scan_failures += 1
            continue
        matched = [
            v for v in release.vulnerabilities if any(k.kb == kb_number for k in v.kb_articles)
        ]
        if matched:
            await _enrich(matched, force_refresh=force_refresh)
            matched = sort_vulnerabilities(matched)
            response = {
                **_release_header(release),
                "total_found": len(matched),
                "vulnerabilities": [
                    v.to_summary_dict(
                        include_references=include_references,
                        include_kb_details=include_kb_details,
                        include_kev_details=include_kev_details,
                    )
                    for v in matched[offset : offset + limit]
                ],
                "filters_applied": filters_applied,
            }
            if include_chain:
                response.update(await _walk_chain(kb_number, release, entries))
            return response

    where = month_id if month_id else f"the last {KB_SCAN_MONTHS} monthly releases"
    if scan_failures:
        return _error(
            f"KB{kb_number} was not found in {where}, but {scan_failures} monthly "
            "document(s) could not be fetched, so the scan was incomplete. Retry later.",
            filters_applied,
            kind="upstream",
        )
    return _error(
        f"KB{kb_number} was not found in {where}.",
        filters_applied,
        kind="not_found",
    )


async def _lookup_kbs(
    kbs: list[str],
    include_chain: bool = False,
    month: str | None = None,
    limit: int = 10,
    offset: int = 0,
    force_refresh: bool = False,
    include_references: bool = False,
    include_kb_details: bool = False,
    include_kev_details: bool = False,
    include_known_issues: bool = False,
    include_update_summary: bool = False,
) -> dict:
    """Batched KB lookup: one grouped response with a per-KB result entry.

    Each KB resolves through the same scan as a single-KB lookup; the
    in-process month cache guarantees every monthly document is fetched
    upstream at most once for the whole batch. A KB that is not found (or
    whose scan hit upstream failures) becomes a found=False entry rather
    than failing the batch; malformed input fails the whole call because a
    silently dropped KB would corrupt any report built on the result.
    """
    normalized = [str(raw).strip().upper().removeprefix("KB").strip() for raw in kbs]
    seen: set[str] = set()
    kb_numbers = [n for n in normalized if not (n in seen or seen.add(n))]

    filters_applied: dict = {"kb": [f"KB{n}" for n in kb_numbers]}
    if month is not None:
        filters_applied["month"] = month
    for name, flag in (
        ("include_chain", include_chain),
        ("include_references", include_references),
        ("include_kb_details", include_kb_details),
        ("include_kev_details", include_kev_details),
        ("include_known_issues", include_known_issues),
        ("include_update_summary", include_update_summary),
    ):
        if flag:
            filters_applied[name] = True
    if force_refresh:
        filters_applied["force_refresh"] = True

    if not kb_numbers:
        return _error(
            "kb= was an empty list. Provide at least one KB number, e.g. ['5094123'].",
            filters_applied,
        )
    invalid = sorted({raw for raw, n in zip(kbs, normalized) if not n.isdigit()})
    if invalid:
        return _error(
            f"Invalid KB number(s): {', '.join(repr(v) for v in invalid)}. Expected "
            "numeric KB ids like '5094123' or 'KB5094123'. kb_articles entries such as "
            "'Release Notes' are vendor-fix labels, not KB ids.",
            filters_applied,
        )
    if len(kb_numbers) > MAX_KB_BATCH:
        return _error(
            f"Too many KB numbers ({len(kb_numbers)} after deduplication); a single "
            f"call accepts at most {MAX_KB_BATCH}. Split the list across calls.",
            filters_applied,
        )

    if include_known_issues or include_update_summary:
        # Warm the support-page cache for the whole batch concurrently; the
        # per-KB lookups below are then served from it (one combined record
        # covers both blocks).
        await known_issues.prefetch(kb_numbers)

    results: list[dict] = []
    total_found = 0
    for number in kb_numbers:
        single = await _lookup_kb(
            number,
            include_chain,
            month,
            limit,
            offset,
            force_refresh,
            include_references=include_references,
            include_kb_details=include_kb_details,
            include_kev_details=include_kev_details,
            include_known_issues=include_known_issues,
            include_update_summary=include_update_summary,
        )
        single.pop("filters_applied", None)
        entry = {"kb": f"KB{number}", "found": "error" not in single, **single}
        total_found += entry.get("total_found", 0)
        results.append(entry)

    return {
        "total_kbs": len(results),
        "total_found": total_found,
        "results": results,
        "filters_applied": filters_applied,
    }


async def _list_months(force_refresh: bool) -> dict:
    """Return the catalog of available monthly releases, newest first."""
    filters_applied: dict = {"list_months": True}
    if force_refresh:
        filters_applied["force_refresh"] = True
    try:
        entries = await msrc_api.fetch_update_index(force_refresh=force_refresh)
    except MsrcApiError as exc:
        return _error(str(exc), filters_applied, kind="upstream")
    return {
        "total_found": len(entries),
        "available_months": [dict(e) for e in entries],
        "filters_applied": filters_applied,
    }


def _collect_predecessors(kb_number: str, release: MonthlyRelease) -> dict[str, int]:
    """Count the distinct Microsoft-stated Supercedence values for a KB.

    A KB can list different predecessors for different product groups, so the
    same KB appears with multiple supercedence values across the month's
    remediation entries. Non-numeric values (after stripping a KB prefix) are
    discarded rather than guessed at.
    """
    counts: dict[str, int] = {}
    for v in release.vulnerabilities:
        for k in v.kb_articles:
            if k.kb != kb_number or not k.supercedence:
                continue
            pred = k.supercedence.strip().upper().removeprefix("KB").strip()
            if pred.isdigit():
                counts[pred] = counts.get(pred, 0) + 1
    return counts


async def _find_kb_month(kb_number: str, months: list[dict]) -> tuple[MonthlyRelease | None, int]:
    """Scan monthly docs (slim parse) for the first one containing a KB.

    Returns (release_or_None, fetch_failure_count) so callers can distinguish
    "definitively not there" from "the scan itself was incomplete".
    """
    failures = 0
    for entry in months:
        try:
            release = await msrc_api.fetch_month(entry["id"], slim=True)
        except MsrcApiError as exc:
            if "not found" not in str(exc):
                failures += 1
            continue
        if any(k.kb == kb_number for v in release.vulnerabilities for k in v.kb_articles):
            return release, failures
    return None, failures


async def _walk_chain(kb_number: str, release: MonthlyRelease, entries: list[dict]) -> dict:
    """Walk Microsoft-stated supersedence links backward from a KB.

    Only explicit Supercedence values are followed -- no date or product
    heuristics -- because wrongly calling a patch superseded is worse than an
    incomplete chain. Newest -> oldest, capped by CHAIN_MAX_DEPTH hops within
    a CHAIN_SCAN_MONTHS window starting at the queried KB's month.
    """
    start_idx = next((i for i, e in enumerate(entries) if e["id"] == release.id), 0)
    window = entries[start_idx : start_idx + CHAIN_SCAN_MONTHS]

    chain: list[dict] = []
    seen = {kb_number}
    current_kb = kb_number
    current_release = release
    pos = 0  # index of the current KB's month within the window
    complete = False
    note: str | None = None

    for _ in range(CHAIN_MAX_DEPTH):
        hop: dict = {"kb": current_kb, "month": current_release.id, "source": "microsoft"}
        predecessors = _collect_predecessors(current_kb, current_release)
        if not predecessors:
            # Microsoft states no predecessor: the chain ends here, complete
            chain.append(hop)
            complete = True
            break

        ordered = sorted(predecessors.items(), key=lambda item: (-item[1], item[0]))
        target = ordered[0][0]
        hop["supersedes"] = target
        if len(ordered) > 1:
            hop["other_predecessors"] = [pred for pred, _ in ordered[1:]]
        chain.append(hop)

        if target in seen:
            note = f"Stopped: KB{target} already appears in the chain (cycle)."
            break
        seen.add(target)

        # Predecessors are older, so scan from the current month backward
        # (same month included: out-of-band updates can supersede within it)
        predecessor_release, fetch_failures = await _find_kb_month(target, window[pos:])
        if predecessor_release is None:
            if fetch_failures:
                note = (
                    f"Stopped: KB{target} was not found within the "
                    f"{CHAIN_SCAN_MONTHS}-month scan window, but {fetch_failures} "
                    "monthly document(s) could not be fetched; the chain may be "
                    "incomplete."
                )
            else:
                note = (
                    f"Stopped: KB{target} was not found within the "
                    f"{CHAIN_SCAN_MONTHS}-month scan window."
                )
            break
        current_kb = target
        current_release = predecessor_release
        pos = next((i for i, e in enumerate(window) if e["id"] == predecessor_release.id), pos)
    else:
        note = f"Stopped: chain depth cap ({CHAIN_MAX_DEPTH} hops) reached."

    result: dict = {"supersedence_chain": chain, "chain_complete": complete}
    if note:
        result["chain_note"] = note
    return result


def _filter_vulnerabilities(
    vulnerabilities: list[Vulnerability],
    query: str | None,
    product: str | None,
    severity: str | None,
    exploited: bool | None,
    publicly_disclosed: bool | None,
    kev: bool | None,
    min_epss: float | None,
    min_cvss: float | None,
    vector_filters: dict[str, str] | None = None,
    ransomware: bool | None = None,
    exploitation_likely: bool | None = None,
    cwe: str | None = None,
    product_terms: list[str] | None = None,
    family_terms: list[str] | None = None,
) -> list[Vulnerability]:
    query_lower = query.lower() if query else None
    product_lower = product.lower() if product else None
    cwe_lower = cwe.strip().lower() if cwe else None
    vector_filters = vector_filters or {}
    product_terms_lower = [t.lower() for t in product_terms or [] if t.strip()]
    family_terms_lower = [t.lower() for t in family_terms or [] if t.strip()]
    watchlist = bool(product_terms_lower or family_terms_lower)

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
        if watchlist:
            # Union match: keep the vuln if any listed product term matches an
            # affected product OR any listed family term matches a product
            # family. This implements profile/watchlist membership.
            prod_hit = any(
                term in p.lower() for term in product_terms_lower for p in v.affected_products
            )
            fam_hit = any(
                term in fam.lower() for term in family_terms_lower for fam in v.product_families
            )
            if not (prod_hit or fam_hit):
                continue
        if severity and v.severity != severity:
            continue
        if exploited is not None and v.exploited != exploited:
            continue
        if publicly_disclosed is not None and v.publicly_disclosed != publicly_disclosed:
            continue
        if kev is not None and (v.kev is not None) != kev:
            continue
        if ransomware is not None:
            known = (
                v.kev is not None
                and str(v.kev.get("ransomware_use") or "").lower() == "known"
            )
            if known != ransomware:
                continue
        if exploitation_likely is not None:
            # Fail-open: entries without an assessment are never "likely"
            likely = v.exploitation_assessment in EXPLOITATION_LIKELY_VALUES
            if likely != exploitation_likely:
                continue
        if cwe_lower:
            if not any(cwe_lower in entry.lower() for entry in v.cwe):
                continue
        if min_epss is not None and (v.epss_score is None or v.epss_score < min_epss):
            continue
        if min_cvss is not None and (v.max_cvss is None or v.max_cvss < min_cvss):
            continue
        if vector_filters:
            # Entries without a parseable CVSS vector cannot match a vector filter.
            if v.cvss is None or any(
                getattr(v.cvss, field) != value for field, value in vector_filters.items()
            ):
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
    # Keep False values (e.g. exploited=False is a real filter); drop only
    # unset params, empty strings, and the default offset
    summary = {
        k: v
        for k, v in filters.items()
        if v is not None and v != "" and not (k == "offset" and v == 0)
    }
    if not summary:
        summary["note"] = (
            "No filters applied; returning the most urgent vulnerabilities from the latest release"
        )
    return summary


def _invalid_month_error(month: str, filters_applied: dict) -> dict:
    return _error(
        f"Invalid month: {month!r}. Use formats like '2026-Apr' or '2026-04'.",
        filters_applied,
    )


def _error(message: str, filters_applied: dict, kind: str = "invalid_input") -> dict:
    return {
        "total_found": 0,
        "vulnerabilities": [],
        "filters_applied": filters_applied,
        "error": message,
        "error_kind": kind,
    }
