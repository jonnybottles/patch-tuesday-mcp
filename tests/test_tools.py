"""Tests for the msrc_search consolidated tool (mocked feeds layer)."""

import json
from pathlib import Path

import pytest

from patch_tuesday_mcp.feeds import msrc_api
from patch_tuesday_mcp.feeds.msrc_api import MsrcApiError, clear_cache
from patch_tuesday_mcp.tools.search import msrc_search

FIXTURE = Path(__file__).parent / "fixtures" / "cvrf_sample.json"

INDEX_RESPONSE = {
    "value": [
        {
            "ID": "2026-Jun",
            "DocumentTitle": "June 2026 Security Updates",
            "InitialReleaseDate": "2026-06-09T07:00:00Z",
            "CurrentReleaseDate": "2026-07-07T07:00:00Z",
        },
        {
            "ID": "2026-May",
            "DocumentTitle": "May 2026 Security Updates",
            "InitialReleaseDate": "2026-05-12T07:00:00Z",
            "CurrentReleaseDate": "2026-06-01T07:00:00Z",
        },
    ]
}


@pytest.fixture(autouse=True)
def mock_api(monkeypatch):
    clear_cache()

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
        if url.endswith("/cvrf/2026-May"):
            raise MsrcApiError("not found")
        raise MsrcApiError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(msrc_api, "_get_json", fake_get_json)
    yield
    clear_cache()


async def test_no_filters_returns_latest_month_most_urgent_first():
    result = await msrc_search()
    assert result["month"] == "2026-Jun"
    assert result["total_found"] == 6
    assert "error" not in result
    # Synthetic exploited CVE sorts first
    assert result["vulnerabilities"][0]["cve"] == "CVE-2026-99999"
    assert result["vulnerabilities"][0]["exploited"] is True
    # Summaries are compact
    assert "description" not in result["vulnerabilities"][0]


async def test_cve_fast_path_returns_detail():
    result = await msrc_search(cve="cve-2026-41108")  # case-insensitive
    assert result["total_found"] == 1
    detail = result["vulnerabilities"][0]
    assert detail["cve"] == "CVE-2026-41108"
    assert detail["description"]
    assert detail["kb_articles"][0]["kb"].isdigit()
    assert detail["affected_products"]


async def test_cve_not_found():
    result = await msrc_search(cve="CVE-1900-00000")
    assert result["total_found"] == 0
    assert "not found" in result["error"]


async def test_cve_invalid_format():
    result = await msrc_search(cve="not-a-cve")
    assert "Invalid CVE format" in result["error"]


async def test_kb_lookup():
    detail = await msrc_search(cve="CVE-2026-41108")
    kb = detail["vulnerabilities"][0]["kb_articles"][0]["kb"]

    result = await msrc_search(kb=f"KB{kb}")
    assert result["total_found"] >= 1
    assert any(v["cve"] == "CVE-2026-41108" for v in result["vulnerabilities"])
    assert result["filters_applied"]["kb"] == f"KB{kb}"


async def test_kb_invalid():
    result = await msrc_search(kb="notakb")
    assert "Invalid KB number" in result["error"]


async def test_severity_filter():
    result = await msrc_search(severity="critical")  # case-insensitive
    assert result["total_found"] >= 1
    assert all(v["severity"] == "Critical" for v in result["vulnerabilities"])


async def test_severity_invalid():
    result = await msrc_search(severity="Apocalyptic")
    assert "Invalid severity" in result["error"]


async def test_exploited_filter():
    result = await msrc_search(exploited=True)
    assert result["total_found"] == 1
    assert result["vulnerabilities"][0]["cve"] == "CVE-2026-99999"


async def test_product_filter():
    result = await msrc_search(product="windows 10")
    assert result["total_found"] >= 1

    # Verify against the parsed fixture directly
    with open(FIXTURE, encoding="utf-8") as f:
        from patch_tuesday_mcp.models.vulnerability import parse_cvrf

        release = parse_cvrf(json.load(f))
    by_cve = {v.cve: v for v in release.vulnerabilities}
    for v in result["vulnerabilities"]:
        products = by_cve[v["cve"]].affected_products
        assert any("windows 10" in p.lower() for p in products)


async def test_query_filter_matches_title():
    result = await msrc_search(query="DNS")
    assert result["total_found"] >= 1
    assert any("DNS" in v["title"] for v in result["vulnerabilities"])


async def test_min_cvss_filter():
    result = await msrc_search(min_cvss=7.0)
    assert result["total_found"] >= 1
    assert all(v["max_cvss"] >= 7.0 for v in result["vulnerabilities"])


async def test_month_normalization_and_invalid():
    result = await msrc_search(month="2026-06")
    assert result["month"] == "2026-Jun"

    result = await msrc_search(month="junk")
    assert "Invalid month" in result["error"]


async def test_month_not_found():
    result = await msrc_search(month="2026-May")
    assert "No security update release found" in result["error"]


async def test_stats_only_overview():
    result = await msrc_search(include_stats=True, limit=0)
    assert result["vulnerabilities"] == []
    stats = result["stats"]
    assert stats["total"] == 6
    assert stats["exploited"] == 1
    assert stats["by_severity"]
    assert stats["by_product_family"]


async def test_stats_reflect_filters():
    result = await msrc_search(severity="Critical", include_stats=True)
    assert result["stats"]["total"] == result["total_found"]


async def test_pagination():
    page1 = await msrc_search(limit=2, offset=0)
    page2 = await msrc_search(limit=2, offset=2)
    assert len(page1["vulnerabilities"]) == 2
    assert len(page2["vulnerabilities"]) == 2
    cves1 = {v["cve"] for v in page1["vulnerabilities"]}
    cves2 = {v["cve"] for v in page2["vulnerabilities"]}
    assert cves1.isdisjoint(cves2)
