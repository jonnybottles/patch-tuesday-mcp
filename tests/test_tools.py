"""Tests for the msrc_search consolidated tool (mocked feeds layer)."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from patch_tuesday_mcp.feeds import enrichment, msrc_api
from patch_tuesday_mcp.feeds.enrichment import EnrichmentError
from patch_tuesday_mcp.feeds.msrc_api import MsrcApiError, clear_cache
from patch_tuesday_mcp.tools import search as search_module
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
        if url.endswith("/cvrf/2026-May"):
            raise MsrcApiError("not found")
        raise MsrcApiError(f"unexpected URL in test: {url}")

    async def fake_enrichment_get_json(url, timeout=30.0):
        # Default: nothing on KEV, nothing known to EPSS
        if "api.first.org" in url:
            return {"status": "OK", "data": []}
        if "cisa.gov" in url:
            return {"vulnerabilities": []}
        raise EnrichmentError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(msrc_api, "_get_json", fake_get_json)
    monkeypatch.setattr(enrichment, "_get_json", fake_enrichment_get_json)
    yield
    clear_cache()
    enrichment.clear_cache()


def _set_enrichment(
    monkeypatch,
    kev: dict[str, dict] | None = None,
    epss: dict[str, tuple[str, str]] | None = None,
) -> None:
    """Re-patch enrichment with canned KEV entries and EPSS (score, percentile) strings."""
    kev_entries = kev or {}
    epss_scores = epss or {}

    async def fake_enrichment_get_json(url, timeout=30.0):
        if "api.first.org" in url:
            cves = url.split("cve=")[1].split(",")
            return {
                "status": "OK",
                "data": [
                    {"cve": c, "epss": epss_scores[c][0], "percentile": epss_scores[c][1]}
                    for c in cves
                    if c in epss_scores
                ],
            }
        if "cisa.gov" in url:
            return {
                "vulnerabilities": [{"cveID": c, **fields} for c, fields in kev_entries.items()]
            }
        raise EnrichmentError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(enrichment, "_get_json", fake_enrichment_get_json)
    enrichment.clear_cache()


KEV_FIELDS = {
    "dateAdded": "2026-06-15",
    "dueDate": "2026-07-06",
    "knownRansomwareCampaignUse": "Known",
}


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
    assert result["error_kind"] == "not_found"


async def test_cve_invalid_format():
    result = await msrc_search(cve="not-a-cve")
    assert "Invalid CVE format" in result["error"]
    assert result["error_kind"] == "invalid_input"


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
    assert result["error_kind"] == "invalid_input"


async def test_kb_with_month():
    detail = await msrc_search(cve="CVE-2026-41108")
    kb = detail["vulnerabilities"][0]["kb_articles"][0]["kb"]

    # Month containing the KB (accepts numeric form)
    result = await msrc_search(kb=kb, month="2026-06")
    assert result["month"] == "2026-Jun"
    assert result["total_found"] >= 1
    assert result["filters_applied"]["month"] == "2026-06"

    # Month that exists in the index but does not contain the KB
    result = await msrc_search(kb=kb, month="2026-May")
    assert result["total_found"] == 0
    assert "2026-May" in result["error"]
    assert result["error_kind"] == "not_found"

    # Invalid month is rejected up front
    result = await msrc_search(kb=kb, month="junk")
    assert "Invalid month" in result["error"]


async def test_filters_applied_keeps_false_values():
    result = await msrc_search(exploited=False)
    assert result["filters_applied"]["exploited"] is False
    assert "note" not in result["filters_applied"]
    assert result["total_found"] == 5, "all but the one exploited CVE"


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


async def test_attack_vector_filter_network_only():
    result = await msrc_search(attack_vector="n")  # case-insensitive
    assert result["total_found"] == 1
    vuln = result["vulnerabilities"][0]
    assert vuln["cve"] == "CVE-2026-47644"
    # Parsed CVSS is surfaced in the summary when a vector filter is applied.
    assert vuln["cvss"]["attack_vector"] == "N"
    assert result["filters_applied"]["attack_vector"] == "n"


async def test_attack_vector_and_privileges_required_combined():
    result = await msrc_search(attack_vector="N", privileges_required="N")
    assert result["total_found"] == 1
    assert result["vulnerabilities"][0]["cve"] == "CVE-2026-47644"


async def test_vector_filters_can_exclude_all():
    # CVE-2026-47644 is AV:N but UI:R, so AV:N + UI:N matches nothing.
    result = await msrc_search(attack_vector="N", user_interaction="N")
    assert result["total_found"] == 0
    assert "error" not in result


async def test_scope_filter_matches_all_fixture_entries():
    result = await msrc_search(scope="U", limit=0, include_stats=True)
    assert result["stats"]["total"] == 6  # every fixture CVE is S:U


async def test_invalid_vector_filter_value_rejected():
    result = await msrc_search(attack_vector="X")
    assert "Invalid attack_vector" in result["error"]
    assert result["error_kind"] == "invalid_input"


async def test_cve_detail_includes_cvss_and_references():
    result = await msrc_search(cve="CVE-2026-41108")
    detail = result["vulnerabilities"][0]
    assert detail["cvss"]["attack_vector"] == "L"
    assert detail["references"]["nvd"].endswith("CVE-2026-41108")
    assert "epss" in detail["references"]


async def test_no_vector_filter_keeps_summary_lean():
    result = await msrc_search()
    assert all("cvss" not in v for v in result["vulnerabilities"])


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


# --- EPSS / KEV enrichment ---


async def test_kev_filter(monkeypatch):
    _set_enrichment(
        monkeypatch,
        kev={"CVE-2026-99999": KEV_FIELDS, "CVE-2026-45472": KEV_FIELDS},
    )

    on_kev = await msrc_search(kev=True)
    assert {v["cve"] for v in on_kev["vulnerabilities"]} == {
        "CVE-2026-99999",
        "CVE-2026-45472",
    }
    assert all(v["kev"] is True for v in on_kev["vulnerabilities"])
    assert on_kev["filters_applied"]["kev"] is True

    off_kev = await msrc_search(kev=False)
    assert off_kev["total_found"] == 4
    assert all("kev" not in v for v in off_kev["vulnerabilities"])


async def test_min_epss_filter(monkeypatch):
    _set_enrichment(
        monkeypatch,
        epss={
            "CVE-2026-41108": ("0.900000000", "0.995000000"),
            "CVE-2026-45472": ("0.300000000", "0.800000000"),
        },
    )

    result = await msrc_search(min_epss=0.5)
    assert [v["cve"] for v in result["vulnerabilities"]] == ["CVE-2026-41108"]
    assert result["vulnerabilities"][0]["epss_score"] == 0.9
    assert result["filters_applied"]["min_epss"] == 0.5


async def test_sort_kev_exploited_tier_then_epss(monkeypatch):
    # Tier 1: exploited CVE-2026-99999 (EPSS .9) and KEV-listed CVE-2026-46245
    # (Moderate, EPSS .05). Tier 2 sorts by EPSS before severity/CVSS.
    _set_enrichment(
        monkeypatch,
        kev={"CVE-2026-46245": KEV_FIELDS},
        epss={
            "CVE-2026-99999": ("0.9", "0.99"),
            "CVE-2026-46245": ("0.05", "0.3"),
            "CVE-2026-50656": ("0.7", "0.97"),
            "CVE-2026-47644": ("0.02", "0.2"),
        },
    )

    result = await msrc_search()
    assert [v["cve"] for v in result["vulnerabilities"]] == [
        "CVE-2026-99999",  # tier 1, EPSS 0.9
        "CVE-2026-46245",  # tier 1 via KEV despite Moderate severity
        "CVE-2026-50656",  # tier 2, EPSS 0.7
        "CVE-2026-47644",  # tier 2, EPSS 0.02 beats unscored Criticals
        "CVE-2026-45472",  # tier 2, no EPSS, Critical
        "CVE-2026-41108",  # tier 2, no EPSS, Important
    ]


async def test_summary_and_detail_enrichment_fields(monkeypatch):
    _set_enrichment(
        monkeypatch,
        kev={"CVE-2026-41108": KEV_FIELDS},
        epss={"CVE-2026-41108": ("0.923110000", "0.999130000")},
    )

    summary = (await msrc_search(query="CVE-2026-41108"))["vulnerabilities"][0]
    assert summary["epss_score"] == 0.92311
    assert summary["kev"] is True, "summary carries only a presence flag"

    detail = (await msrc_search(cve="CVE-2026-41108"))["vulnerabilities"][0]
    assert detail["epss_score"] == 0.92311
    assert detail["epss_percentile"] == 0.99913
    assert detail["kev"] == {
        "date_added": "2026-06-15",
        "due_date": "2026-07-06",
        "ransomware_use": "Known",
    }


async def test_enrichment_degradation(monkeypatch):
    """Both enrichment sources failing must not break or taint MSRC results."""

    async def failing_get_json(url, timeout=30.0):
        raise EnrichmentError("boom")

    monkeypatch.setattr(enrichment, "_get_json", failing_get_json)
    enrichment.clear_cache()

    result = await msrc_search()
    assert "error" not in result
    assert result["total_found"] == 6
    for v in result["vulnerabilities"]:
        assert "epss_score" not in v
        assert "kev" not in v

    detail = await msrc_search(cve="CVE-2026-41108")
    assert "error" not in detail
    assert "epss_score" not in detail["vulnerabilities"][0]


async def test_stats_include_kev_count(monkeypatch):
    _set_enrichment(
        monkeypatch,
        kev={"CVE-2026-99999": KEV_FIELDS, "CVE-2026-45472": KEV_FIELDS},
    )

    result = await msrc_search(include_stats=True, limit=0)
    assert result["stats"]["kev"] == 2
    assert result["stats"]["exploited"] == 1


# --- Supersedence chain walking ---


def _synthetic_month(month_id: str, date: str, kbs: list[tuple[str, str | None]]) -> dict:
    """Build a minimal CVRF doc; one synthetic vuln per (kb, supercedence) pair."""
    return {
        "DocumentTracking": {
            "Identification": {"ID": {"Value": month_id}},
            "InitialReleaseDate": date,
            "CurrentReleaseDate": date,
        },
        "DocumentTitle": {"Value": f"{month_id} Security Updates"},
        "ProductTree": {"FullProductName": [], "Branch": []},
        "Vulnerability": [
            {
                "CVE": f"CVE-2026-{80000 + i}",
                "Title": {"Value": f"Synthetic vulnerability {i}"},
                "Notes": [
                    {"Type": 2, "Value": "<p>Synthetic description</p>"},
                    {"Type": 4, "Value": "Synthetic FAQ"},
                ],
                "Threats": [{"Type": 3, "Description": {"Value": "Important"}}],
                "Remediations": [
                    {
                        "Type": 2,
                        "Description": {"Value": kb},
                        "Supercedence": supercedence,
                        "SubType": "Security Update",
                    }
                ],
            }
            for i, (kb, supercedence) in enumerate(kbs)
        ],
    }


def _patch_chain_months(monkeypatch, docs: dict[str, dict]) -> None:
    """Point the MSRC mock at synthetic monthly docs (newest month first)."""
    dates = {}
    for i, month_id in enumerate(docs):
        dates[month_id] = f"2026-{12 - i:02d}-09T07:00:00Z"

    index = {
        "value": [
            {
                "ID": month_id,
                "DocumentTitle": f"{month_id} Security Updates",
                "InitialReleaseDate": dates[month_id],
                "CurrentReleaseDate": dates[month_id],
            }
            for month_id in docs
        ]
    }

    async def fake_get_json(url, timeout=60.0):
        if url.endswith("/updates"):
            return index
        for month_id, doc in docs.items():
            if url.endswith(f"/cvrf/{month_id}"):
                return doc
        raise MsrcApiError("not found")

    monkeypatch.setattr(msrc_api, "_get_json", fake_get_json)
    clear_cache()


async def test_chain_happy_path(monkeypatch):
    _patch_chain_months(
        monkeypatch,
        {
            "2026-Jun": _synthetic_month("2026-Jun", "", [("5300003", "5300002")]),
            "2026-May": _synthetic_month("2026-May", "", [("5300002", "KB5300001")]),
            "2026-Apr": _synthetic_month("2026-Apr", "", [("5300001", None)]),
        },
    )

    result = await msrc_search(kb="5300003", include_chain=True)
    assert "error" not in result
    assert result["chain_complete"] is True
    assert "chain_note" not in result
    assert result["supersedence_chain"] == [
        {"kb": "5300003", "month": "2026-Jun", "supersedes": "5300002", "source": "microsoft"},
        {"kb": "5300002", "month": "2026-May", "supersedes": "5300001", "source": "microsoft"},
        {"kb": "5300001", "month": "2026-Apr", "source": "microsoft"},
    ]
    # Memory guard: only the queried KB's month is parsed full, the rest slim
    assert "2026-Jun" in msrc_api._month_cache
    assert set(msrc_api._slim_month_cache) == {"2026-May", "2026-Apr"}


async def test_chain_depth_cap(monkeypatch):
    _patch_chain_months(
        monkeypatch,
        {
            "2026-Jun": _synthetic_month("2026-Jun", "", [("5300003", "5300002")]),
            "2026-May": _synthetic_month("2026-May", "", [("5300002", "5300001")]),
            "2026-Apr": _synthetic_month("2026-Apr", "", [("5300001", None)]),
        },
    )
    monkeypatch.setattr(search_module, "CHAIN_MAX_DEPTH", 2)

    result = await msrc_search(kb="5300003", include_chain=True)
    assert result["chain_complete"] is False
    assert "depth cap" in result["chain_note"]
    assert len(result["supersedence_chain"]) == 2


async def test_chain_cycle_guard(monkeypatch):
    _patch_chain_months(
        monkeypatch,
        {
            "2026-Jun": _synthetic_month("2026-Jun", "", [("5300003", "5300002")]),
            "2026-May": _synthetic_month("2026-May", "", [("5300002", "5300003")]),
        },
    )

    result = await msrc_search(kb="5300003", include_chain=True)
    assert result["chain_complete"] is False
    assert "cycle" in result["chain_note"]
    assert [hop["kb"] for hop in result["supersedence_chain"]] == ["5300003", "5300002"]


async def test_chain_predecessor_not_found(monkeypatch):
    _patch_chain_months(
        monkeypatch,
        {
            "2026-Jun": _synthetic_month("2026-Jun", "", [("5300003", "5300002")]),
            "2026-May": _synthetic_month("2026-May", "", [("5309999", None)]),
        },
    )

    result = await msrc_search(kb="5300003", include_chain=True)
    assert "error" not in result
    assert result["chain_complete"] is False
    assert "not found" in result["chain_note"]
    assert result["supersedence_chain"] == [
        {"kb": "5300003", "month": "2026-Jun", "supersedes": "5300002", "source": "microsoft"},
    ]


async def test_chain_multiple_predecessors(monkeypatch):
    _patch_chain_months(
        monkeypatch,
        {
            "2026-Jun": _synthetic_month(
                "2026-Jun",
                "",
                # Same KB with different stated predecessors across product groups
                [("5300003", "5300002"), ("5300003", "5300002"), ("5300003", "5300009")],
            ),
            "2026-May": _synthetic_month("2026-May", "", [("5300002", None)]),
        },
    )

    result = await msrc_search(kb="5300003", include_chain=True)
    assert result["chain_complete"] is True
    first_hop = result["supersedence_chain"][0]
    assert first_hop["supersedes"] == "5300002", "most frequent predecessor is followed"
    assert first_hop["other_predecessors"] == ["5300009"]


async def test_include_chain_without_kb_is_ignored():
    result = await msrc_search(include_chain=True)
    assert "error" not in result
    assert "supersedence_chain" not in result
    assert "chain_complete" not in result


async def test_default_month_skips_pre_patch_tuesday_document(monkeypatch):
    """Before the upcoming month's Patch Tuesday, no-month queries serve the
    latest full release and say why; the partial month stays reachable."""
    _patch_chain_months(
        monkeypatch,
        {
            "2026-Jul": _synthetic_month("2026-Jul", "", [("5400001", None)]),
            "2026-Jun": _synthetic_month("2026-Jun", "", [("5300001", None)]),
        },
    )
    monkeypatch.setattr(msrc_api, "utcnow", lambda: datetime(2026, 7, 7, tzinfo=timezone.utc))

    result = await msrc_search()
    assert result["month"] == "2026-Jun"
    assert "2026-Jul" in result["note"] and "2026-07-14" in result["note"]
    assert "release_status" not in result

    # Explicitly requesting the pre-release month works, clearly annotated
    result = await msrc_search(month="2026-Jul")
    assert result["month"] == "2026-Jul"
    assert result["release_status"] == "pre-patch-tuesday"
    assert "2026-07-14" in result["note"]

    # A past month requested explicitly gets no annotation
    result = await msrc_search(month="2026-Jun")
    assert "note" not in result
    assert "release_status" not in result


async def test_default_month_after_patch_tuesday(monkeypatch):
    _patch_chain_months(
        monkeypatch,
        {
            "2026-Jul": _synthetic_month("2026-Jul", "", [("5400001", None)]),
            "2026-Jun": _synthetic_month("2026-Jun", "", [("5300001", None)]),
        },
    )
    monkeypatch.setattr(msrc_api, "utcnow", lambda: datetime(2026, 7, 20, tzinfo=timezone.utc))

    result = await msrc_search()
    assert result["month"] == "2026-Jul"
    assert "note" not in result
    assert "release_status" not in result


async def test_kb_lookup_respects_limit_and_offset(monkeypatch):
    _patch_chain_months(
        monkeypatch,
        {
            "2026-Jun": _synthetic_month(
                "2026-Jun", "", [("5300003", None), ("5300003", None), ("5300003", None)]
            ),
        },
    )

    page1 = await msrc_search(kb="5300003", limit=2)
    assert page1["total_found"] == 3
    assert len(page1["vulnerabilities"]) == 2

    page2 = await msrc_search(kb="5300003", limit=2, offset=2)
    assert page2["total_found"] == 3
    assert len(page2["vulnerabilities"]) == 1

    cves1 = {v["cve"] for v in page1["vulnerabilities"]}
    cves2 = {v["cve"] for v in page2["vulnerabilities"]}
    assert cves1.isdisjoint(cves2)
