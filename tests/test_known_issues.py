"""Tests for the Microsoft support-page known-issues feed (mocked HTTP).

The feed scrapes the public per-KB support page (an unstructured source), so
these tests pin the honest-status contract: `published` vs `none_published`
vs `unavailable`, with upstream failures never masquerading as "none".
"""

import asyncio
from pathlib import Path

import httpx
import pytest

from patch_tuesday_mcp.feeds import http_client, known_issues
from patch_tuesday_mcp.feeds.known_issues import (
    KnownIssuesError,
    clear_cache,
    fetch_known_issues,
    prefetch,
)

FIXTURES = Path(__file__).parent / "fixtures"
SOURCE_URL = "https://support.microsoft.com/en-us/topic/test-kb-page"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def reset_cache():
    clear_cache()
    yield
    clear_cache()


def _set_page(monkeypatch, html: str, url: str = SOURCE_URL) -> list:
    """Patch the network seam to serve one canned page; return the call log."""
    calls = []

    async def fake_fetch(kb_number):
        calls.append(kb_number)
        return (url, html)

    monkeypatch.setattr(known_issues, "_fetch_kb_page", fake_fetch)
    return calls


# --- Parser: published issues ---


def test_parse_published_issue_fields():
    result = known_issues._parse_known_issues(
        _load("kb_known_issues.html"), "5094126", SOURCE_URL
    )
    assert result["status"] == "published"
    assert result["source_url"] == SOURCE_URL
    issues = result["issues"]
    assert len(issues) == 2

    office = issues[0]
    assert office["title"] == (
        "Microsoft Office applications might fail to open from certain third-party apps"
    )
    assert "OLE automation" in office["symptoms"]
    assert "open the application or document directly" in office["workaround"]
    assert "resolved_by" not in office

    recycle = issues[1]
    assert recycle["title"] == "Deleting from Recycle Bin displays an internal file name"
    assert "$Rxxxxx.ext" in recycle["symptoms"]
    assert "addressed in" in recycle["workaround"]
    assert recycle["resolved_by"] == "KB5095093"


def test_parse_strips_zero_width_junk():
    result = known_issues._parse_known_issues(
        _load("kb_known_issues.html"), "5094126", SOURCE_URL
    )
    for issue in result["issues"]:
        for value in issue.values():
            assert chr(0x200B) not in value
            assert "\xa0" not in value


def test_parse_heading_variant_still_matches():
    html = _load("kb_known_issues.html").replace(
        "Known issues in this update", "Known issues with this security update"
    )
    result = known_issues._parse_known_issues(html, "5094126", SOURCE_URL)
    assert result["status"] == "published"
    assert len(result["issues"]) == 2


def test_parse_slicing_excludes_neighbor_sections():
    result = known_issues._parse_known_issues(
        _load("kb_known_issues.html"), "5094126", SOURCE_URL
    )
    titles = " ".join(issue["title"] for issue in result["issues"])
    assert "How to get this update" not in titles
    assert "Highlights" not in titles


def test_parse_unsegmented_body_lands_in_symptoms():
    # Some issue bodies carry prose without bold Symptoms/Workaround labels;
    # the whole text describes the problem, so it maps to symptoms.
    html = _load("kb_known_issues.html")
    html = html.replace('<b class="ocpLegacyBold">Symptoms</b>', "").replace(
        '<b class="ocpLegacyBold">Workaround</b>', ""
    )
    result = known_issues._parse_known_issues(html, "5094126", SOURCE_URL)
    assert result["status"] == "published"
    office = result["issues"][0]
    assert "OLE automation" in office["symptoms"]
    assert "workaround" not in office


def test_parse_block_without_title_is_skipped():
    html = _load("kb_known_issues.html").replace(
        ">Deleting from Recycle Bin displays an internal file name<", "><"
    )
    result = known_issues._parse_known_issues(html, "5094126", SOURCE_URL)
    assert result["status"] == "published"
    assert len(result["issues"]) == 1, "a titleless block must be skipped, not invented"


# --- Parser: none published ---


def test_parse_none_aware_section_is_none_published():
    result = known_issues._parse_known_issues(
        _load("kb_none_aware.html"), "5091234", SOURCE_URL
    )
    assert result["status"] == "none_published"
    assert "not currently aware of any issues" in result["note"]
    assert result["source_url"] == SOURCE_URL
    assert "issues" not in result


def test_parse_missing_section_is_none_published():
    result = known_issues._parse_known_issues(
        _load("kb_no_issues_section.html"), "5002880", SOURCE_URL
    )
    assert result["status"] == "none_published"
    assert "known-issues section" in result["note"]
    assert result["source_url"] == SOURCE_URL


# --- Parser: markup drift degrades to unavailable, never a silent none ---


def test_parse_drifted_markup_is_unavailable_with_pointer():
    html = _load("kb_known_issues.html").replace("ocpExpandoHeadTitleContainer", "ocpRenamed")
    result = known_issues._parse_known_issues(html, "5094126", SOURCE_URL)
    assert result["status"] == "unavailable"
    assert "could not be parsed" in result["note"]
    assert result["source_url"] == SOURCE_URL


# --- _fetch_kb_page: redirect policy (manual, single hop, same host only) ---


def _patch_transport(monkeypatch, *, location_status=301, location=None,
                     body_status=200, body=b"<html>ok</html>"):
    fetched = []

    async def fake_get_location(url, *, timeout):
        fetched.append(("head", url))
        return (location_status, location)

    async def fake_get_bounded(url, *, headers=None, timeout, max_bytes):
        fetched.append(("get", url))
        return (body_status, body)

    monkeypatch.setattr(http_client, "get_location", fake_get_location)
    monkeypatch.setattr(http_client, "get_bounded", fake_get_bounded)
    return fetched


async def test_fetch_follows_single_same_host_relative_redirect(monkeypatch):
    fetched = _patch_transport(monkeypatch, location="/en-us/topic/some-kb-slug")
    url, html = await known_issues._fetch_kb_page("5094126")
    assert url == "https://support.microsoft.com/en-us/topic/some-kb-slug"
    assert html == "<html>ok</html>"
    assert ("get", url) in fetched


async def test_fetch_accepts_absolute_same_host_https_redirect(monkeypatch):
    _patch_transport(
        monkeypatch, location="https://support.microsoft.com/en-us/topic/some-kb-slug"
    )
    url, _ = await known_issues._fetch_kb_page("5094126")
    assert url == "https://support.microsoft.com/en-us/topic/some-kb-slug"


async def test_fetch_rejects_cross_host_redirect(monkeypatch):
    _patch_transport(monkeypatch, location="https://evil.example.com/en-us/topic/x")
    with pytest.raises(KnownIssuesError):
        await known_issues._fetch_kb_page("5094126")


async def test_fetch_rejects_redirect_without_location(monkeypatch):
    _patch_transport(monkeypatch, location=None)
    with pytest.raises(KnownIssuesError):
        await known_issues._fetch_kb_page("5094126")


async def test_fetch_404_means_no_page(monkeypatch):
    _patch_transport(monkeypatch, location_status=404)
    assert await known_issues._fetch_kb_page("5094126") == (None, None)


async def test_fetch_direct_200_reads_original_url(monkeypatch):
    fetched = _patch_transport(monkeypatch, location_status=200)
    url, html = await known_issues._fetch_kb_page("5094126")
    assert url == known_issues.SUPPORT_KB_URL.format(kb="5094126")
    assert html == "<html>ok</html>"
    assert ("get", url) in fetched


async def test_fetch_landing_non_200_raises(monkeypatch):
    _patch_transport(monkeypatch, location="/en-us/topic/x", body_status=500)
    with pytest.raises(KnownIssuesError):
        await known_issues._fetch_kb_page("5094126")


async def test_fetch_unexpected_first_hop_status_raises(monkeypatch):
    _patch_transport(monkeypatch, location_status=503)
    with pytest.raises(KnownIssuesError):
        await known_issues._fetch_kb_page("5094126")


async def test_fetch_wraps_httpx_errors(monkeypatch):
    async def broken_get_location(url, *, timeout):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(http_client, "get_location", broken_get_location)
    with pytest.raises(KnownIssuesError):
        await known_issues._fetch_kb_page("5094126")


async def test_fetch_oversized_body_raises_known_issues_error(monkeypatch):
    async def fake_get_location(url, *, timeout):
        return (301, "/en-us/topic/x")

    async def oversized_get_bounded(url, *, headers=None, timeout, max_bytes):
        raise http_client.ResponseTooLarge("too big")

    monkeypatch.setattr(http_client, "get_location", fake_get_location)
    monkeypatch.setattr(http_client, "get_bounded", oversized_get_bounded)
    with pytest.raises(KnownIssuesError):
        await known_issues._fetch_kb_page("5094126")


# --- fetch_known_issues: orchestration, honest statuses, caching ---


async def test_lookup_published_and_cached(monkeypatch):
    calls = _set_page(monkeypatch, _load("kb_known_issues.html"))
    first = await fetch_known_issues("5094126")
    assert first["status"] == "published"
    assert len(first["issues"]) == 2

    second = await fetch_known_issues("5094126")
    assert second == first
    assert len(calls) == 1, "second lookup must be served from the cache"


async def test_lookup_no_page_is_none_published_and_cached(monkeypatch):
    calls = []

    async def fake_fetch(kb_number):
        calls.append(kb_number)
        return (None, None)

    monkeypatch.setattr(known_issues, "_fetch_kb_page", fake_fetch)
    result = await fetch_known_issues("1111111")
    assert result["status"] == "none_published"
    assert "no per-KB support page" in result["note"]
    assert "source_url" not in result

    await fetch_known_issues("1111111")
    assert len(calls) == 1


async def test_lookup_wrong_landing_page_is_none_published(monkeypatch):
    # A bogus KB redirects to an unrelated article; the page must not be
    # trusted when neither the URL slug nor the title names the requested KB.
    # (The fixture carries the awa-kb_id analytics meta echoing the request —
    # like the real site does even on wrong landings — so in-body digit
    # matches must not count as verification.)
    _set_page(monkeypatch, _load("kb_wrong_landing.html"))
    result = await fetch_known_issues("9999999")
    assert result["status"] == "none_published"
    assert "no per-KB support page" in result["note"]


async def test_lookup_never_attributes_another_pages_issues(monkeypatch):
    # The dangerous fuzzy-redirect case: the landing page HAS known issues,
    # but belongs to a different KB. Its issues must not be attributed to the
    # requested KB, even though the analytics meta echoes the requested id.
    html = _load("kb_known_issues.html").replace(
        "<head>", '<head>\n<meta name="awa-kb_id" content="1234567" />'
    )
    _set_page(
        monkeypatch, html, url="https://support.microsoft.com/en-us/topic/some-other-article"
    )
    result = await fetch_known_issues("1234567")
    assert result["status"] == "none_published"
    assert "no per-KB support page" in result["note"]
    assert "issues" not in result


async def test_lookup_url_slug_match_trusts_page(monkeypatch):
    # Some pages never state their KB in the title; the canonical URL slug
    # (e.g. .../june-9-2026-kb5094126-os-builds...) is verification enough.
    html = _load("kb_known_issues.html").replace("KB5094126", "").replace("5094126", "")
    _set_page(
        monkeypatch,
        html,
        url="https://support.microsoft.com/en-us/topic/june-9-2026-kb5094126-os-builds-x",
    )
    result = await fetch_known_issues("5094126")
    assert result["status"] == "published"


async def test_lookup_fetch_failure_is_unavailable_and_not_cached(monkeypatch):
    async def failing_fetch(kb_number):
        raise KnownIssuesError("boom")

    monkeypatch.setattr(known_issues, "_fetch_kb_page", failing_fetch)
    result = await fetch_known_issues("5094126")
    assert result["status"] == "unavailable"
    assert result["note"]

    # A later successful fetch must not be blocked by a cached failure.
    _set_page(monkeypatch, _load("kb_known_issues.html"))
    recovered = await fetch_known_issues("5094126")
    assert recovered["status"] == "published"


async def test_lookup_ttl_expiry_refetches(monkeypatch):
    calls = _set_page(monkeypatch, _load("kb_known_issues.html"))
    await fetch_known_issues("5094126")
    monkeypatch.setattr(known_issues, "KNOWN_ISSUES_TTL_SECONDS", 0)
    await fetch_known_issues("5094126")
    assert len(calls) == 2, "an expired entry must be re-fetched"


async def test_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(known_issues, "MAX_CACHE_ENTRIES", 2)
    template = _load("kb_known_issues.html")

    async def fake_fetch(kb_number):
        return (SOURCE_URL, template.replace("5094126", kb_number))

    monkeypatch.setattr(known_issues, "_fetch_kb_page", fake_fetch)
    for kb in ("5000001", "5000002", "5000003"):
        await fetch_known_issues(kb)
    assert len(known_issues._cache) <= 2, "cache must not grow unboundedly"


async def test_lookup_never_raises(monkeypatch):
    async def exploding_fetch(kb_number):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(known_issues, "_fetch_kb_page", exploding_fetch)
    result = await fetch_known_issues("5094126")
    assert result["status"] == "unavailable"


# --- prefetch: batch warm-up with bounded concurrency ---


async def test_prefetch_warms_cache_with_bounded_concurrency(monkeypatch):
    template = _load("kb_known_issues.html")
    active = 0
    peak = 0
    calls = []

    async def slow_fetch(kb_number):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        calls.append(kb_number)
        return (SOURCE_URL, template.replace("5094126", kb_number))

    monkeypatch.setattr(known_issues, "_fetch_kb_page", slow_fetch)
    kbs = [f"500000{i}" for i in range(6)]
    await prefetch(kbs)
    assert peak >= 2, "prefetch must fetch concurrently"
    assert peak <= known_issues.FETCH_CONCURRENCY, "prefetch concurrency must stay bounded"

    for kb in kbs:
        await fetch_known_issues(kb)
    assert len(calls) == 6, "individual lookups must be served from the warmed cache"


async def test_prefetch_swallows_failures(monkeypatch):
    async def failing_fetch(kb_number):
        raise KnownIssuesError("boom")

    monkeypatch.setattr(known_issues, "_fetch_kb_page", failing_fetch)
    await prefetch(["5094126", "5094127"])  # must not raise
    result = await fetch_known_issues("5094126")
    assert result["status"] == "unavailable"


# --- Telemetry ---


async def test_lookup_emits_telemetry(monkeypatch):
    events = []
    monkeypatch.setattr(
        known_issues.telemetry, "track_event", lambda name, props: events.append((name, props))
    )
    _set_page(monkeypatch, _load("kb_known_issues.html"))
    await fetch_known_issues("5094126")

    async def failing_fetch(kb_number):
        raise KnownIssuesError("boom")

    monkeypatch.setattr(known_issues, "_fetch_kb_page", failing_fetch)
    await fetch_known_issues("5094127")

    outcomes = [p["ok"] for n, p in events if p.get("source") == "known_issues"]
    assert True in outcomes
    assert False in outcomes
