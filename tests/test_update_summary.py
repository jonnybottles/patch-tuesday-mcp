"""Tests for the Microsoft support-page update-summary feed (mocked HTTP).

The update-summary block ("what this update changes": the KB page's
Summary/Highlights text plus its Improvements bullets) shares one fetch, one
trust check, and one cache record with the known-issues feed. These tests pin
the parser across both markup generations, the honest three-way status
contract, the size caps, and the shared-record behavior.
"""

import asyncio
from pathlib import Path

import pytest

from patch_tuesday_mcp.feeds import known_issues
from patch_tuesday_mcp.feeds.known_issues import (
    KnownIssuesError,
    clear_cache,
    fetch_known_issues,
    fetch_update_summary,
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


# --- Parser: published summaries across both markup generations ---


def test_parse_legacy_highlights_and_improvements():
    result = known_issues._parse_update_summary(
        _load("kb_known_issues.html"), "5094126", SOURCE_URL
    )
    assert result["status"] == "published"
    assert result["source_url"] == SOURCE_URL
    assert "KB5094126" in result["title"]
    # The Highlights intro and its bullets flatten into the summary text.
    assert "quality improvements" in result["summary"]
    assert "addresses security issues" in result["summary"]
    # The legacy <h2> Improvements region contains <h3> expando blocks; its
    # bullets must be captured (the level-2 region does not stop at <h3>).
    assert result["improvements"] == [
        "[Taskbar] Fixed: Icons might not appear after you sign in.",
        "[File Explorer] Fixed: Extraction of large ZIP archives is slow.",
    ]
    assert "truncated" not in result


def test_parse_legacy_excludes_neighbor_sections():
    result = known_issues._parse_update_summary(
        _load("kb_known_issues.html"), "5094126", SOURCE_URL
    )
    joined = " ".join(result["improvements"])
    # Nothing from the known-issues section or the how-to section may leak.
    assert "OLE automation" not in joined
    assert "Recycle Bin" not in joined
    assert "Before you install" not in result["summary"]
    # The per-version expando heading is not itself an improvement item.
    assert "Windows 11, version 24H2" not in joined


def test_parse_servicing_summary_and_rollout_bullets():
    result = known_issues._parse_update_summary(
        _load("kb_servicing_layout.html"), "5094126", SOURCE_URL
    )
    assert result["status"] == "published"
    assert "quality improvements" in result["summary"]
    # No <h1> on servicing pages: title falls back to <title>, site suffix cut.
    assert "KB5094126" in result["title"]
    assert "Microsoft Support" not in result["title"]
    # Gradual + Normal rollout h3 subsections, in document order.
    assert result["improvements"] == [
        "[Start menu] New: Grid view for the All list.",
        "[Servicing] Fixed: An issue affecting update installation.",
    ]
    joined = " ".join(result["improvements"])
    assert "Recycle Bin" not in joined, "known-issues <details> bullets must not leak"


def test_parse_summary_only_page_published_without_improvements():
    result = known_issues._parse_update_summary(
        _load("kb_no_issues_section.html"), "5002880", SOURCE_URL
    )
    assert result["status"] == "published"
    assert "improvements and fixes for Microsoft SharePoint Server 2016" in result["summary"]
    # The prose-only "Improvements and fixes" section has no bullets.
    assert "improvements" not in result
    assert "KB5002880" in result["title"]


def test_parse_duplicate_rollout_sections_deduped():
    # SSU+LCU combined pages repeat sections; items must stay unique, in order.
    html = _load("kb_servicing_layout.html").replace(
        "</main>",
        "<h3><strong>Gradual rollout</strong></h3>"
        "<ul><li><p>[Start menu] New: Grid view for the All list.</p></li></ul></main>",
    )
    result = known_issues._parse_update_summary(html, "5094126", SOURCE_URL)
    items = result["improvements"]
    assert items.count("[Start menu] New: Grid view for the All list.") == 1
    assert items[0] == "[Start menu] New: Grid view for the All list."


def test_parse_caps_and_marks_truncated():
    long_item = "<li><p>" + "y" * 400 + "</p></li>"
    bullets = "".join(f"<li><p>Item {i} filler text</p></li>" for i in range(30))
    html = (
        "<html><head><title>KB5000001 test page</title></head><body>"
        "<h1>May 1, 2026 KB5000001</h1>"
        "<h2>Summary</h2><p>" + "s" * 2000 + "</p>"
        "<h2>Improvements</h2><ul>" + long_item + bullets + "</ul>"
        "</body></html>"
    )
    result = known_issues._parse_update_summary(html, "5000001", SOURCE_URL)
    assert result["status"] == "published"
    assert len(result["summary"]) <= known_issues._SUMMARY_MAX_CHARS + 3
    assert len(result["improvements"]) == known_issues._MAX_IMPROVEMENT_ITEMS
    assert len(result["improvements"][0]) <= known_issues._IMPROVEMENT_ITEM_MAX_CHARS + 3
    assert result["truncated"] is True


def test_parse_level2_improvements_region_stops_at_excluded_section():
    # On a page where a level-2 Improvements region runs into the known-issues
    # section before the next <h2>, the excluded-section guard must cut it.
    html = (
        "<html><head><title>KB5000002 page</title></head><body>"
        "<h2>Summary</h2><p>Intro.</p>"
        "<h2>Improvements</h2><ul><li><p>Real item.</p></li></ul>"
        "<h3><strong>Known issues in this update</strong></h3>"
        "<details><summary>Bad</summary>"
        "<ul><li><p>Leaked known-issue bullet.</p></li></ul></details>"
        "<h2>How to get this update</h2><ul><li><p>Windows Update channel row.</p></li></ul>"
        "</body></html>"
    )
    result = known_issues._parse_update_summary(html, "5000002", SOURCE_URL)
    assert result["improvements"] == ["Real item."]


def test_parse_skips_link_only_reference_items():
    # Real CU pages open the Improvements section with a list of links to the
    # prior preview updates and release notes; link-only items are references,
    # not improvements.
    html = (
        "<html><head><title>KB5000006 page</title></head><body>"
        "<h2>Improvements</h2><ul>"
        '<li><a href="../may-update">May 12, 2026 preview update</a></li>'
        '<li><a href="https://msrc.microsoft.com/x">Security Updates</a>.</li>'
        "<li><p><strong>[Secure Boot]</strong> Real improvement text.</p></li>"
        "</ul></body></html>"
    )
    result = known_issues._parse_update_summary(html, "5000006", SOURCE_URL)
    assert result["improvements"] == ["[Secure Boot] Real improvement text."]


def test_parse_no_summary_section_is_none_published():
    html = (
        "<html><head><title>Some article about KB5000003</title></head><body>"
        "<h2>How to get this update</h2><p>Windows Update.</p>"
        "</body></html>"
    )
    result = known_issues._parse_update_summary(html, "5000003", SOURCE_URL)
    assert result["status"] == "none_published"
    assert result["note"]
    assert result["source_url"] == SOURCE_URL


def test_parse_empty_summary_region_is_unavailable():
    # A summary heading with nothing extractable means layout drift, which
    # must never masquerade as "none published".
    html = (
        "<html><head><title>KB5000004 page</title></head><body>"
        "<h2>Summary</h2><h2>How to get this update</h2><p>x</p>"
        "</body></html>"
    )
    result = known_issues._parse_update_summary(html, "5000004", SOURCE_URL)
    assert result["status"] == "unavailable"
    assert "could not be parsed" in result["note"]
    assert result["source_url"] == SOURCE_URL


def test_parse_strips_zero_width_junk():
    html = (
        "<html><head><title>KB5000005 page</title></head><body>"
        "<h2>Summary</h2><p>Qual&#8203;ity&nbsp;text.</p>"
        "<h2>Improvements</h2><ul><li><p>Item&#8203;&nbsp;one.</p></li></ul>"
        "</body></html>"
    )
    result = known_issues._parse_update_summary(html, "5000005", SOURCE_URL)
    assert "​" not in result["summary"]
    assert "\xa0" not in result["summary"]
    for item in result["improvements"]:
        assert "​" not in item
        assert "\xa0" not in item


# --- fetch_update_summary: shared record, honest statuses, caching ---


async def test_fetch_update_summary_shares_one_fetch_with_known_issues(monkeypatch):
    calls = _set_page(monkeypatch, _load("kb_known_issues.html"))
    issues = await fetch_known_issues("5094126")
    summary = await fetch_update_summary("5094126")
    assert issues["status"] == "published"
    assert summary["status"] == "published"
    assert len(calls) == 1, "both blocks must be served by a single page fetch"


async def test_fetch_update_summary_no_page_is_none_published_and_cached(monkeypatch):
    calls = []

    async def fake_fetch(kb_number):
        calls.append(kb_number)
        return (None, None)

    monkeypatch.setattr(known_issues, "_fetch_kb_page", fake_fetch)
    result = await fetch_update_summary("1111111")
    assert result["status"] == "none_published"
    assert "no per-KB support page" in result["note"]
    assert "source_url" not in result

    await fetch_update_summary("1111111")
    assert len(calls) == 1


async def test_fetch_update_summary_untrusted_landing_is_none_published(monkeypatch):
    # The wrong landing page even HAS a Summary section — it must not be
    # attributed to the requested KB (trust check runs before parsing).
    _set_page(monkeypatch, _load("kb_wrong_landing.html"))
    result = await fetch_update_summary("9999999")
    assert result["status"] == "none_published"
    assert "summary" not in result


async def test_fetch_update_summary_failure_is_unavailable_and_not_cached(monkeypatch):
    async def failing_fetch(kb_number):
        raise KnownIssuesError("boom")

    monkeypatch.setattr(known_issues, "_fetch_kb_page", failing_fetch)
    result = await fetch_update_summary("5094126")
    assert result["status"] == "unavailable"
    assert result["source_url"].startswith("https://support.microsoft.com/")

    _set_page(monkeypatch, _load("kb_known_issues.html"))
    recovered = await fetch_update_summary("5094126")
    assert recovered["status"] == "published"


async def test_partial_drift_record_not_cached(monkeypatch):
    # Known-issues markup drifted but the summary still parses: the summary is
    # served, yet the record must not be cached (an unavailable member would be
    # pinned for a whole TTL otherwise), so a second lookup refetches.
    html = _load("kb_known_issues.html").replace(
        "ocpExpandoHeadTitleContainer", "renamedTitleContainer"
    )
    calls = _set_page(monkeypatch, html)
    assert (await fetch_update_summary("5094126"))["status"] == "published"
    assert (await fetch_known_issues("5094126"))["status"] == "unavailable"
    await fetch_update_summary("5094126")
    assert len(calls) == 3, "a partially-drifted record must not be cached"


async def test_fetch_update_summary_never_raises(monkeypatch):
    async def exploding_fetch(kb_number):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(known_issues, "_fetch_kb_page", exploding_fetch)
    result = await fetch_update_summary("5094126")
    assert result["status"] == "unavailable"


async def test_prefetch_warms_update_summary_too(monkeypatch):
    template = _load("kb_known_issues.html")
    calls = []

    async def fake_fetch(kb_number):
        calls.append(kb_number)
        await asyncio.sleep(0)
        return (SOURCE_URL, template.replace("5094126", kb_number))

    monkeypatch.setattr(known_issues, "_fetch_kb_page", fake_fetch)
    kbs = ["5000001", "5000002"]
    await prefetch(kbs)
    for kb in kbs:
        assert (await fetch_update_summary(kb))["status"] == "published"
    assert len(calls) == 2, "summary lookups must be served from the warmed cache"


async def test_telemetry_carries_both_statuses(monkeypatch):
    events = []
    monkeypatch.setattr(
        known_issues.telemetry, "track_event", lambda name, props: events.append((name, props))
    )
    _set_page(monkeypatch, _load("kb_known_issues.html"))
    await fetch_update_summary("5094126")

    props = next(p for n, p in events if p.get("source") == "known_issues")
    assert props["status"] == "published"
    assert props["summary_status"] == "published"
