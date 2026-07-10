"""Tests for local product-profile (watchlist) loading and resolution."""

import json

import pytest

from patch_tuesday_mcp.tools import profiles


def test_builtin_profiles_resolve():
    products, families = profiles.resolve_profile("identity-core")
    assert "Exchange Server" in products
    assert "Windows" in families


def test_resolve_is_case_insensitive():
    a = profiles.resolve_profile("identity-core")
    b = profiles.resolve_profile("IDENTITY-CORE")
    assert a == b


def test_unknown_profile_raises_with_available_list():
    with pytest.raises(profiles.ProfileError) as exc:
        profiles.resolve_profile("nope")
    msg = str(exc.value)
    assert "nope" in msg
    assert "identity-core" in msg  # lists available profiles


def test_file_override_replaces_builtin(monkeypatch, tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps(
            {"identity-core": {"families": ["Windows", "Azure"], "products": ["Contoso App"]}}
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("MSRC_PROFILES_PATH", str(path))
    products, families = profiles.resolve_profile("identity-core")
    assert products == ["Contoso App"]
    assert families == ["Windows", "Azure"]


def test_file_can_add_new_profile(monkeypatch, tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"custom": {"products": ["Widget"]}}), encoding="utf-8")
    monkeypatch.setenv("MSRC_PROFILES_PATH", str(path))
    products, families = profiles.resolve_profile("custom")
    assert products == ["Widget"]
    assert families == []
    # built-ins remain available alongside file profiles
    assert "identity-core" in profiles.load_profiles()


def test_missing_file_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("MSRC_PROFILES_PATH", str(tmp_path / "absent.json"))
    with pytest.raises(profiles.ProfileError):
        profiles.load_profiles()


def test_malformed_json_raises(monkeypatch, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setenv("MSRC_PROFILES_PATH", str(path))
    with pytest.raises(profiles.ProfileError):
        profiles.load_profiles()


def test_invalid_structure_raises(monkeypatch, tmp_path):
    path = tmp_path / "bad.json"
    # products must be a list of strings
    path.write_text(json.dumps({"x": {"products": "Widget"}}), encoding="utf-8")
    monkeypatch.setenv("MSRC_PROFILES_PATH", str(path))
    with pytest.raises(profiles.ProfileError):
        profiles.load_profiles()


def test_empty_profile_entry_raises(monkeypatch, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"x": {}}), encoding="utf-8")
    monkeypatch.setenv("MSRC_PROFILES_PATH", str(path))
    with pytest.raises(profiles.ProfileError):
        profiles.load_profiles()
