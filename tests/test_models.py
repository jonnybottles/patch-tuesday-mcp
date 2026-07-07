"""Tests for CVRF normalization models against a real (truncated) CVRF document."""

import json
from pathlib import Path

import pytest

from patch_tuesday_mcp.models.vulnerability import (
    MonthlyRelease,
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
