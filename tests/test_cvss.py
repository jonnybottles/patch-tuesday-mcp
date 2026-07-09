"""Unit tests for CVSS v3.x vector parsing."""

from patch_tuesday_mcp.models.cvss import CvssVector, parse_cvss_vector


def test_parses_full_v31_vector():
    parsed = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert isinstance(parsed, CvssVector)
    assert parsed.version == "3.1"
    assert parsed.attack_vector == "N"
    assert parsed.attack_complexity == "L"
    assert parsed.privileges_required == "N"
    assert parsed.user_interaction == "N"
    assert parsed.scope == "U"
    assert parsed.confidentiality == "H"
    assert parsed.integrity == "H"
    assert parsed.availability == "H"


def test_ignores_temporal_and_environmental_metrics():
    parsed = parse_cvss_vector("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C")
    assert parsed is not None
    d = parsed.to_dict()
    # Only base metrics (plus version) survive; temporal metrics are dropped.
    assert set(d) == {
        "version",
        "attack_vector",
        "attack_complexity",
        "privileges_required",
        "user_interaction",
        "scope",
        "confidentiality",
        "integrity",
        "availability",
    }


def test_supports_v30():
    parsed = parse_cvss_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N")
    assert parsed is not None
    assert parsed.version == "3.0"
    assert parsed.attack_vector == "A"
    assert parsed.scope == "C"


def test_none_and_empty_return_none():
    assert parse_cvss_vector(None) is None
    assert parse_cvss_vector("") is None
    assert parse_cvss_vector("   ") is None


def test_non_v3_versions_return_none():
    # CVSS v2 (no CVSS: prefix) and v4 are not parsed as v3.
    assert parse_cvss_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None
    assert parse_cvss_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N") is None


def test_malformed_values_are_dropped_not_raised():
    # AV:Z is invalid and dropped; the rest of the vector still parses.
    parsed = parse_cvss_vector("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N")
    assert parsed is not None
    assert parsed.attack_vector is None
    assert parsed.attack_complexity == "L"
    assert parsed.privileges_required == "N"


def test_garbage_returns_none():
    assert parse_cvss_vector("not a vector") is None
    assert parse_cvss_vector("CVSS:3.1/") is None
