"""Live end-to-end smoke tests against the real MSRC / FIRST EPSS / CISA KEV APIs.

Skipped by default. Run with:  pytest tests/test_live_smoke.py --run-live
(or set PT_RUN_LIVE=1). These validate the enriched search behavior (CVSS
parsing/filters, reference links) against live data, so exact counts are
not asserted — only shapes and invariants that must always hold.
"""

import pytest

from patch_tuesday_mcp.models.cvss import parse_cvss_vector
from patch_tuesday_mcp.tools.search import msrc_search

pytestmark = pytest.mark.live


async def test_live_latest_month_search_shape():
    result = await msrc_search(limit=5)
    assert "error" not in result, result.get("error")
    assert result["month"], "expected a released month id like 2026-Jun"
    assert result["total_found"] > 0
    assert 0 < len(result["vulnerabilities"]) <= 5
    for v in result["vulnerabilities"]:
        assert v["cve"].upper().startswith("CVE-")
        assert v["url"].startswith("https://msrc.microsoft.com/")
        # Broad summaries stay lean — CVSS/reference fields are opt-in.
        assert "cvss" not in v
        assert "references" not in v


async def test_live_cve_detail_has_parsed_cvss_and_references():
    latest = await msrc_search(limit=100)
    assert latest["vulnerabilities"], "no vulnerabilities in latest release"
    cve = latest["vulnerabilities"][0]["cve"]

    detail = (await msrc_search(cve=cve))["vulnerabilities"][0]

    # References are always present and well-formed.
    refs = detail["references"]
    assert refs["msrc"].endswith(cve)
    assert refs["nvd"] == f"https://nvd.nist.gov/vuln/detail/{cve}"
    assert f"cve={cve}" in refs["epss"]

    # When MSRC supplies a vector, it must parse and stay self-consistent.
    if detail.get("cvss_vector"):
        assert "cvss" in detail, "vector present but no parsed cvss object"
        reparsed = parse_cvss_vector(detail["cvss_vector"])
        assert reparsed is not None
        assert detail["cvss"] == reparsed.to_dict()
        assert detail["cvss"]["attack_vector"] in {"N", "A", "L", "P"}


async def test_live_attack_vector_filter_is_consistent():
    result = await msrc_search(attack_vector="N", limit=25)
    assert "error" not in result, result.get("error")
    # May legitimately be empty in a quiet month; any results must all match and
    # carry the parsed cvss object that justified the match.
    for v in result["vulnerabilities"]:
        assert v["cvss"]["attack_vector"] == "N"


async def test_live_kev_filter_and_references():
    result = await msrc_search(kev=True, limit=5)
    assert "error" not in result, result.get("error")
    if result["total_found"] == 0:
        pytest.skip("no KEV-listed CVEs in the latest release this month")
    cve = result["vulnerabilities"][0]["cve"]
    detail = (await msrc_search(cve=cve))["vulnerabilities"][0]
    assert detail.get("kev") is not None
    assert "kev" in detail["references"]
    assert "cisa.gov" in detail["references"]["kev"]


async def test_live_invalid_vector_value_is_rejected():
    result = await msrc_search(attack_vector="Z")
    assert result["error_kind"] == "invalid_input"
    assert "Invalid attack_vector" in result["error"]


async def test_live_include_guidance_shape():
    latest = await msrc_search(limit=100)
    assert latest["vulnerabilities"], "no vulnerabilities in latest release"
    cve = latest["vulnerabilities"][0]["cve"]

    # Guidance is opt-in and may legitimately be absent for a given CVE; when
    # present, every entry must carry a known type and non-empty description.
    detail = (await msrc_search(cve=cve, include_guidance=True))["vulnerabilities"][0]
    default = (await msrc_search(cve=cve))["vulnerabilities"][0]
    assert "guidance" not in default
    for entry in detail.get("guidance", []):
        assert entry["type"] in {"mitigation", "workaround", "will_not_fix"}
        assert entry["description"]


async def test_live_markdown_and_csv_report_shape():
    import csv
    import io

    from patch_tuesday_mcp.tools.formatters import TRIAGE_COLUMNS

    md = await msrc_search(format="markdown", limit=5)
    assert "error" not in md, md.get("error")
    assert md["format"] == "markdown"
    assert md["markdown"].startswith("# Patch Tuesday Triage")
    assert "| CVE | Title |" in md["markdown"]
    # Total reflects the whole month; the table is limited to the page.
    assert md["total_found"] >= len(md["vulnerabilities"])

    out = await msrc_search(format="csv", limit=5)
    assert out["format"] == "csv"
    assert out["columns"] == TRIAGE_COLUMNS
    rows = list(csv.DictReader(io.StringIO(out["csv"])))
    assert len(rows) == len(out["vulnerabilities"])
    for row in rows:
        assert row["cve"].upper().startswith("CVE-")
        assert list(row.keys()) == TRIAGE_COLUMNS


async def test_live_force_refresh_and_freshness_metadata():
    # force_refresh must succeed and surface freshness for MSRC + enrichment.
    result = await msrc_search(force_refresh=True, limit=5)
    assert "error" not in result, result.get("error")
    fresh = result["freshness"]
    assert fresh["force_refresh"] is True
    assert fresh["msrc"]["month"] == result["month"]
    assert fresh["msrc"]["available"] is True
    assert fresh["msrc"]["age_seconds"] >= 0
    # Enrichment is best-effort; when present it carries a TTL.
    assert "ttl_seconds" in fresh["epss"]
    assert "ttl_seconds" in fresh["kev"]

    # Freshness is opt-in and omitted by default.
    default = await msrc_search(limit=5)
    assert "freshness" not in default


async def test_live_trend_search_across_recent_months():
    result = await msrc_search(months_back=3, limit=50)
    assert "error" not in result, result.get("error")
    assert "month" not in result, "trend responses use a range, not a single month"
    assert 1 <= result["months_searched"] <= 3
    assert result["range"]["months"], "expected a resolved month list"
    assert len(result["trend"]) == result["months_searched"]
    # total_found is the sum of matches across the returned per-month counts.
    assert result["total_found"] == sum(entry["total"] for entry in result["trend"])
    # Trend is newest-first: the first entry matches the range end.
    assert result["trend"][0]["month"] == result["range"]["end"]

    # Range cap is enforced.
    capped = await msrc_search(months_back=99)
    assert capped["error_kind"] == "invalid_input"



