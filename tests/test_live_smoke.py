"""Live end-to-end smoke tests against the real MSRC / FIRST EPSS / CISA KEV APIs.

Skipped by default. Run with:  pytest tests/test_live_smoke.py --run-live
(or set PT_RUN_LIVE=1). These validate the CVSS parsing/filters and reference
links against live data, so exact counts are not asserted — only shapes and
invariants that must always hold.
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
        # Broad summaries stay lean — cvss/references are opt-in.
        assert "cvss" not in v
        assert "references" not in v


async def test_live_cve_detail_has_parsed_cvss_and_references():
    latest = await msrc_search(limit=100)
    assert latest["vulnerabilities"], "no vulnerabilities in latest release"
    cve = latest["vulnerabilities"][0]["cve"]

    detail = (await msrc_search(cve=cve))["vulnerabilities"][0]

    # references are always present and well-formed.
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
