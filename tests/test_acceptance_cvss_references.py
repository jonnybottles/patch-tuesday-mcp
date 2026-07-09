"""Behavioural tests for the CVSS vector breakdown and generated reference links.

These cover the parsed ``cvss`` object and vector filters (``attack_vector``,
``privileges_required``, ``user_interaction``, ``scope``) plus the ``references``
block (MSRC/NVD/EPSS/KEV) end to end through ``msrc_search``.

Tool-level tests reuse the same mocked-feeds pattern as ``test_tools.py`` so they
run fully offline; a companion live smoke test lives in ``test_live_smoke.py``.
"""

import json
from pathlib import Path

import pytest

from patch_tuesday_mcp.feeds import enrichment, msrc_api
from patch_tuesday_mcp.feeds.enrichment import EnrichmentError
from patch_tuesday_mcp.feeds.msrc_api import MsrcApiError, clear_cache
from patch_tuesday_mcp.models.cvss import parse_cvss_vector
from patch_tuesday_mcp.models.vulnerability import Vulnerability, parse_cvrf
from patch_tuesday_mcp.tools.search import msrc_search

FIXTURE = Path(__file__).parent / "fixtures" / "cvrf_sample.json"

INDEX_RESPONSE = {
    "value": [
        {
            "ID": "2026-Jun",
            "DocumentTitle": "June 2026 Security Updates",
            "InitialReleaseDate": "2026-06-09T07:00:00Z",
            "CurrentReleaseDate": "2026-07-07T07:00:00Z",
        }
    ]
}


@pytest.fixture(autouse=True)
def mock_api(monkeypatch):
    clear_cache()
    enrichment.clear_cache()

    with open(FIXTURE, encoding="utf-8") as f:
        cvrf_doc = json.load(f)

    async def fake_get_json(url, timeout=60.0):
        if url.endswith("/updates"):
            return INDEX_RESPONSE
        if "/updates('CVE-2026-41108')" in url:
            return {"value": [{"ID": "2026-Jun"}]}
        if "/updates('" in url:
            raise MsrcApiError("not found")
        if url.endswith("/cvrf/2026-Jun"):
            return cvrf_doc
        raise MsrcApiError(f"unexpected URL in test: {url}")

    async def fake_enrichment_get_json(url, timeout=30.0):
        if "api.first.org" in url:
            return {"status": "OK", "data": []}
        if "cisa.gov" in url:
            # CVE-2026-99999 is on KEV for reference-link assertions.
            return {
                "vulnerabilities": [
                    {"cveID": "CVE-2026-99999", "dueDate": "2026-07-06"}
                ]
            }
        raise EnrichmentError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(msrc_api, "_get_json", fake_get_json)
    monkeypatch.setattr(enrichment, "_get_json", fake_enrichment_get_json)
    yield
    clear_cache()
    enrichment.clear_cache()


def _fixture_release():
    with open(FIXTURE, encoding="utf-8") as f:
        return parse_cvrf(json.load(f))


# --- CVSS vector breakdown ---------------------------------------------------


def test_full_vector_parses_to_components():
    """Vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → AV=N, PR=N, UI=N."""
    parsed = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert parsed is not None
    assert parsed.attack_vector == "N"
    assert parsed.privileges_required == "N"
    assert parsed.user_interaction == "N"


async def test_detail_output_exposes_components():
    """Parsed components are exposed in msrc_search CVE detail output."""
    detail = (await msrc_search(cve="CVE-2026-41108"))["vulnerabilities"][0]
    assert detail["cvss"]["attack_vector"] == "L"
    assert detail["cvss"]["privileges_required"] == "L"
    assert detail["cvss"]["user_interaction"] == "N"


async def test_vector_filters_return_only_matches():
    """attack_vector=N + privileges_required=N returns only matching CVEs."""
    result = await msrc_search(attack_vector="N", privileges_required="N")
    assert result["total_found"] == 1
    assert result["vulnerabilities"][0]["cve"] == "CVE-2026-47644"
    # Cross-check every returned entry actually satisfies the filter.
    for v in result["vulnerabilities"]:
        assert v["cvss"]["attack_vector"] == "N"
        assert v["cvss"]["privileges_required"] == "N"


def test_malformed_vector_preserves_raw_no_exception():
    """Malformed vector keeps raw cvss_vector available; no exception escapes."""
    # parse_cvss_vector must not raise on garbage.
    assert parse_cvss_vector("totally invalid") is None
    vuln = Vulnerability(
        cve="CVE-2026-1",
        cvss_vector="totally invalid",
        cvss=parse_cvss_vector("totally invalid"),
    )
    detail = vuln.to_detail_dict()
    assert detail["cvss_vector"] == "totally invalid"
    assert "cvss" not in detail


async def test_no_vector_filters_is_backward_compatible():
    """Without vector filters, response shape is unchanged (additive only)."""
    result = await msrc_search()
    assert result["total_found"] == 6
    # Summaries stay lean: no cvss/references unless requested.
    for v in result["vulnerabilities"]:
        assert "cvss" not in v
        assert "references" not in v


async def test_month_search_tolerates_mixed_vectors():
    """Malformed/missing vectors don't fail a monthly search."""
    # The fixture mixes full base+temporal vectors and a base-only vector; a
    # broad search must still succeed and enrich every entry.
    result = await msrc_search(limit=100)
    assert "error" not in result
    assert result["total_found"] == 6


# --- Generated reference links -----------------------------------------------


async def test_detail_includes_msrc_and_nvd():
    """CVE detail references include MSRC and NVD links."""
    detail = (await msrc_search(cve="CVE-2026-41108"))["vulnerabilities"][0]
    refs = detail["references"]
    assert refs["msrc"].endswith("CVE-2026-41108")
    assert refs["nvd"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-41108"


def test_kev_listed_cve_includes_kev_reference():
    """KEV-listed CVE detail references include a CISA KEV catalog link."""
    vuln = Vulnerability(cve="CVE-2026-99999", kev={"due_date": "2026-07-06"})
    detail = vuln.to_detail_dict()
    assert "kev" in detail["references"]
    assert "cisa.gov" in detail["references"]["kev"]


async def test_summary_omits_references_by_default():
    """Broad summary output does not carry references (context stays small)."""
    result = await msrc_search()
    assert all("references" not in v for v in result["vulnerabilities"])


def test_no_extra_api_calls_for_references():
    """References are generated deterministically, without network calls."""
    # references() is pure string construction on a Vulnerability with no feeds
    # access — constructing one offline and calling it must succeed.
    release = _fixture_release()
    vuln = release.vulnerabilities[0]
    refs = vuln.references()
    assert refs["msrc"] and refs["nvd"] and refs["epss"]
