"""Tests for CVRF normalization models against a real (truncated) CVRF document."""

import json
from pathlib import Path

import pytest

from patch_tuesday_mcp.models.vulnerability import (
    MonthlyRelease,
    Vulnerability,
    _parse_vulnerability,
    parse_cvrf,
    parse_exploit_status,
    sort_vulnerabilities,
    strip_html,
)

FIXTURE = Path(__file__).parent / "fixtures" / "cvrf_sample.json"


@pytest.fixture(scope="module")
def cvrf_doc() -> dict:
    with open(FIXTURE, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def release(cvrf_doc) -> MonthlyRelease:
    return parse_cvrf(cvrf_doc)


def test_release_metadata(release):
    assert release.id == "2026-Jun"
    assert release.title == "June 2026 Security Updates"
    assert release.initial_release_date.startswith("2026-06-09")
    assert len(release.vulnerabilities) == 6


def test_windows_dns_vulnerability(release):
    vuln = next(v for v in release.vulnerabilities if v.cve == "CVE-2026-41108")
    assert "DNS" in vuln.title
    assert vuln.impact == "Elevation of Privilege"
    assert vuln.severity == "Important"
    assert vuln.max_cvss == 7.0
    assert vuln.cvss_vector and vuln.cvss_vector.startswith("CVSS:3.1/")
    assert vuln.exploited is False
    assert vuln.kb_articles, "expected vendor-fix KBs"
    assert all(k.kb.isdigit() for k in vuln.kb_articles)
    assert vuln.affected_products, "expected affected product names resolved"
    assert "Windows" in vuln.product_families or "ESU" in vuln.product_families
    assert vuln.description, "expected HTML-stripped description"
    assert "<" not in vuln.description


def test_synthetic_exploited_flag(release):
    vuln = next(v for v in release.vulnerabilities if v.cve == "CVE-2026-99999")
    assert vuln.exploited is True
    assert vuln.exploitability.get("Exploited") == "Yes"


def test_publicly_disclosed_flag(release):
    disclosed = [v for v in release.vulnerabilities if v.publicly_disclosed]
    assert disclosed, "fixture includes a publicly disclosed CVE"


def test_summary_dict_is_compact(release):
    vuln = next(v for v in release.vulnerabilities if v.cve == "CVE-2026-41108")
    summary = vuln.to_summary_dict()
    assert summary["cve"] == "CVE-2026-41108"
    assert "description" not in summary
    assert "affected_products" not in summary
    assert "faqs" not in summary
    assert summary["url"].endswith("CVE-2026-41108")
    assert isinstance(summary["kb_articles"], list)


def test_detail_dict_is_complete(release):
    vuln = next(v for v in release.vulnerabilities if v.cve == "CVE-2026-41108")
    detail = vuln.to_detail_dict()
    assert detail["description"]
    assert detail["affected_products"]
    assert detail["kb_articles"][0]["kb"]
    assert detail["cvss_vector"]


def test_stats(release):
    stats = release.stats()
    assert stats["total"] == 6
    assert stats["exploited"] == 1
    assert stats["publicly_disclosed"] >= 1
    severities = {s["name"] for s in stats["by_severity"]}
    assert "Critical" in severities
    assert stats["by_product_family"], "expected family counts"


def test_sort_exploited_first(release):
    ordered = sort_vulnerabilities(release.vulnerabilities)
    assert ordered[0].cve == "CVE-2026-99999", "exploited CVE sorts first"
    # Critical outranks Important among non-exploited
    non_exploited = [v for v in ordered if not v.exploited and v.severity]
    severity_ranks = ["Critical", "Important", "Moderate", "Low"]
    ranks = [severity_ranks.index(v.severity) for v in non_exploited]
    assert ranks == sorted(ranks)


KEV_ENTRY = {
    "date_added": "2026-06-15",
    "due_date": "2026-07-06",
    "ransomware_use": "Known",
}


def test_enrichment_fields_in_summary_and_detail():
    vuln = Vulnerability(
        cve="CVE-2026-99999", epss_score=0.92311, epss_percentile=0.99913, kev=KEV_ENTRY
    )
    summary = vuln.to_summary_dict()
    assert summary["epss_score"] == 0.92311
    assert summary["kev"] is True, "summary carries a compact presence flag"
    assert "epss_percentile" not in summary

    detail = vuln.to_detail_dict()
    assert detail["epss_score"] == 0.92311
    assert detail["epss_percentile"] == 0.99913
    assert detail["kev"] == KEV_ENTRY


def test_enrichment_fields_absent_when_unset():
    vuln = Vulnerability(cve="CVE-2026-41108")
    assert "epss_score" not in vuln.to_summary_dict()
    assert "kev" not in vuln.to_summary_dict()
    assert "epss_percentile" not in vuln.to_detail_dict()
    assert "kev" not in vuln.to_detail_dict()


def test_stats_kev_count():
    release = MonthlyRelease(
        id="2026-Jun",
        vulnerabilities=[
            Vulnerability(cve="CVE-2026-1", kev=KEV_ENTRY),
            Vulnerability(cve="CVE-2026-2", kev=KEV_ENTRY, exploited=True),
            Vulnerability(cve="CVE-2026-3"),
        ],
    )
    stats = release.stats()
    assert stats["kev"] == 2
    assert stats["exploited"] == 1


def test_sort_kev_and_epss_tiers():
    kev_low_sev = Vulnerability(cve="CVE-2026-1", severity="Low", kev=KEV_ENTRY, epss_score=0.1)
    exploited = Vulnerability(cve="CVE-2026-2", severity="Low", exploited=True, epss_score=0.8)
    high_epss = Vulnerability(cve="CVE-2026-3", severity="Low", epss_score=0.9)
    critical_no_epss = Vulnerability(cve="CVE-2026-4", severity="Critical", max_cvss=9.8)

    ordered = sort_vulnerabilities([critical_no_epss, high_epss, kev_low_sev, exploited])
    assert [v.cve for v in ordered] == [
        "CVE-2026-2",  # KEV/exploited tier, EPSS 0.8
        "CVE-2026-1",  # KEV/exploited tier, EPSS 0.1
        "CVE-2026-3",  # second tier: EPSS outranks severity
        "CVE-2026-4",  # second tier: no EPSS, despite Critical/9.8
    ]


def test_slim_parse_skips_text(cvrf_doc):
    release = parse_cvrf(cvrf_doc, include_text=False)
    assert all(v.description == "" for v in release.vulnerabilities)
    assert all(v.faqs == [] for v in release.vulnerabilities)
    # Everything else is still parsed
    vuln = next(v for v in release.vulnerabilities if v.cve == "CVE-2026-41108")
    assert vuln.severity == "Important"
    assert vuln.kb_articles


def test_parse_exploit_status():
    parsed = parse_exploit_status(
        "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"
    )
    assert parsed == {
        "Publicly Disclosed": "No",
        "Exploited": "Yes",
        "Latest Software Release": "Exploitation Detected",
    }


def test_strip_html():
    assert strip_html("<p>Hello&nbsp;<b>world</b></p>\n") == "Hello world"


def test_cvss_vector_parsed_onto_vulnerability(release):
    vuln = next(v for v in release.vulnerabilities if v.cve == "CVE-2026-41108")
    assert vuln.cvss is not None
    assert vuln.cvss.attack_vector == "L"
    assert vuln.cvss.privileges_required == "L"
    assert vuln.cvss.user_interaction == "N"
    # Raw vector is preserved alongside the parsed components.
    assert vuln.cvss_vector.startswith("CVSS:3.1/")


def test_detail_dict_includes_parsed_cvss(release):
    vuln = next(v for v in release.vulnerabilities if v.cve == "CVE-2026-47644")
    detail = vuln.to_detail_dict()
    assert detail["cvss"]["attack_vector"] == "N"
    assert detail["cvss"]["user_interaction"] == "R"
    assert detail["cvss_vector"]  # raw string still present


def test_summary_omits_cvss_by_default_but_opts_in(release):
    vuln = next(v for v in release.vulnerabilities if v.cve == "CVE-2026-41108")
    assert "cvss" not in vuln.to_summary_dict()
    opted_in = vuln.to_summary_dict(include_cvss=True)
    assert opted_in["cvss"]["attack_vector"] == "L"


def test_malformed_cvss_vector_does_not_break_model():
    vuln = Vulnerability(cve="CVE-2026-1", cvss_vector="garbage", cvss=None)
    assert vuln.cvss is None
    detail = vuln.to_detail_dict()
    assert "cvss" not in detail  # nothing parsed
    assert detail["cvss_vector"] == "garbage"  # raw preserved


def test_references_generated_without_kev():
    vuln = Vulnerability(cve="CVE-2026-41108")
    refs = vuln.references()
    assert refs["msrc"].endswith("CVE-2026-41108")
    assert refs["nvd"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-41108"
    assert "cve=CVE-2026-41108" in refs["epss"]
    assert "kev" not in refs


def test_references_include_kev_when_present():
    vuln = Vulnerability(cve="CVE-2026-99999", kev={"due_date": "2026-07-06"})
    refs = vuln.references()
    assert "cisa.gov" in refs["kev"]


def test_detail_dict_includes_references(release):
    vuln = next(v for v in release.vulnerabilities if v.cve == "CVE-2026-41108")
    detail = vuln.to_detail_dict()
    assert "references" in detail
    assert detail["references"]["nvd"].endswith("CVE-2026-41108")


def test_summary_omits_references_by_default_but_opts_in(release):
    vuln = next(v for v in release.vulnerabilities if v.cve == "CVE-2026-41108")
    assert "references" not in vuln.to_summary_dict()
    assert "references" in vuln.to_summary_dict(include_references=True)


# --- Mitigations & workarounds (guidance) ---

_GUIDANCE_RAW = {
    "CVE": "CVE-2026-70000",
    "Title": {"Value": "Example guidance vuln"},
    "Remediations": [
        {"Type": 2, "Description": {"Value": "5099999"}, "SubType": "Security Update"},
        {
            "Type": 1,
            "Description": {"Value": "<p>Disable the <b>Foo</b> service.</p>"},
            "URL": "https://msrc.microsoft.com/mitigation",
        },
        {"Type": 0, "Description": {"Value": "Block inbound port 445."}},
        # Duplicate mitigation across products must be de-duplicated.
        {"Type": 1, "Description": {"Value": "<p>Disable the <b>Foo</b> service.</p>"}},
        {"Type": 4, "Description": {"Value": "This behavior is by design."}},
        # None-available (type 3) with no text is not surfaced as guidance.
        {"Type": 3, "Description": {"Value": None}, "URL": "https://support/x"},
    ],
}


def test_parses_mitigation_workaround_and_will_not_fix():
    vuln = _parse_vulnerability(_GUIDANCE_RAW, {}, {})
    # Vendor-fix KBs remain in kb_articles, unaffected.
    assert [k.kb for k in vuln.kb_articles] == ["5099999"]
    types = [g.type for g in vuln.guidance]
    assert types == ["mitigation", "workaround", "will_not_fix"]
    mitigation = vuln.guidance[0]
    assert mitigation.description == "Disable the Foo service."  # HTML stripped
    assert mitigation.url == "https://msrc.microsoft.com/mitigation"


def test_guidance_is_gated_in_detail_output():
    vuln = _parse_vulnerability(_GUIDANCE_RAW, {}, {})
    assert "guidance" not in vuln.to_detail_dict()
    detail = vuln.to_detail_dict(include_guidance=True)
    assert [g["type"] for g in detail["guidance"]] == [
        "mitigation",
        "workaround",
        "will_not_fix",
    ]


def test_slim_parse_skips_guidance_text():
    vuln = _parse_vulnerability(_GUIDANCE_RAW, {}, {}, include_text=False)
    assert vuln.guidance == []
    # KB remediation (small, always needed for chain walking) is retained.
    assert [k.kb for k in vuln.kb_articles] == ["5099999"]
