"""Per-KB data scraped from the Microsoft support page: known issues + summary.

Microsoft publishes no keyless API for this data (the Graph windowsupdates
API requires an AAD tenant), so this feed reads the public per-KB support
page — https://support.microsoft.com/en-us/help/<kb> — and serves two
response blocks from a single fetch and combined cache record:

- ``fetch_known_issues``: the "Known issues in this update" section.
- ``fetch_update_summary``: what the update changes — the page's
  Summary/Highlights text plus its Improvements bullet list (size-capped via
  ``_SUMMARY_MAX_CHARS`` / ``_MAX_IMPROVEMENT_ITEMS`` /
  ``_IMPROVEMENT_ITEM_MAX_CHARS``; a capped block carries ``truncated``).

The source is unstructured HTML, so retrieval is strictly best-effort and
every block carries an honest status:

- ``published``: the section parsed into structured content.
- ``none_published``: Microsoft publishes no such data for this KB (no
  per-KB page, or no section on the page). Common for non-Windows products.
- ``unavailable``: the page could not be fetched or no longer parses (layout
  drift). Never reported as ``none_published`` — an upstream failure must not
  masquerade as "nothing published".

Fetch failures never raise into a search; both fetchers always return a
dict. A record is only cached when neither block is ``unavailable``, so a
transient failure (or partial layout drift) is never pinned for a TTL.

Quirks of the source that shape this module: the /help/<kb> URL answers with
a short chain of same-host redirects to the canonical article (historically
one hop to /topic/...; the 2026 site migration added a second hop to
/servicing/os/...), so we follow a bounded number of hops, validating each
target ourselves — the shared client never follows redirects on its own.
Unknown KB numbers redirect to *unrelated* articles — which still echo the
requested id in an analytics meta tag — so a landing page is only trusted
when its URL slug or its title names the requested KB. Two markup
generations coexist: legacy pages use ``ocpSection``/``ocpExpando`` divs
with ``<b class="ocpLegacyBold">`` segment labels, while the newer
/servicing/ pages use ``<details>``/``<summary>`` blocks with ``<strong>``
labels under an ``<h3>`` heading; both are parsed, for both blocks.
"""

import asyncio
import logging
import os
import re
import time
from html.parser import HTMLParser
from urllib.parse import urlsplit

import httpx

from .. import telemetry
from . import http_client

SUPPORT_HOST = "support.microsoft.com"
SUPPORT_KB_URL = "https://support.microsoft.com/en-us/help/{kb}"

# KB pages measure ~150-360 KB; far beyond that means a misbehaving upstream.
MAX_RESPONSE_BYTES = int(os.getenv("MCP_KNOWN_ISSUES_MAX_RESPONSE_BYTES", str(4 * 1024 * 1024)))

KNOWN_ISSUES_TTL_SECONDS = 6 * 3600
MAX_CACHE_ENTRIES = 500  # combined records are ~2-9 KB, so worst case ~5 MB
FETCH_CONCURRENCY = 3
MAX_REDIRECT_HOPS = 3  # /help -> /topic -> /servicing today; one spare

# A known-issues section with no parseable issue entries is an explicit
# "none" statement when its prose is short; anything longer suggests issue
# content our parser no longer understands (layout drift).
_NONE_TEXT_MAX_CHARS = 400

# Update-summary size caps: Windows CU pages list dozens of improvement
# bullets across rollout waves; cap to keep the per-KB response weight (and
# the cached record) bounded. A capped block carries ``truncated: True``.
_SUMMARY_MAX_CHARS = 1500
_MAX_IMPROVEMENT_ITEMS = 20
_IMPROVEMENT_ITEM_MAX_CHARS = 300

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

logger = logging.getLogger(__name__)

# kb number -> (fetched_at, result); insertion order doubles as LRU recency.
# Only published/none_published results are cached: a transient failure must
# not pin "unavailable" for a whole TTL.
_cache: dict[str, tuple[float, dict]] = {}

_fetch_semaphore: asyncio.Semaphore | None = None
_semaphore_loop: asyncio.AbstractEventLoop | None = None


class KnownIssuesError(Exception):
    """Raised when the known-issues source returns an error or unexpected response."""


def clear_cache() -> None:
    """Reset the cache (used by tests)."""
    global _fetch_semaphore, _semaphore_loop
    _cache.clear()
    _fetch_semaphore = None
    _semaphore_loop = None


def _get_fetch_semaphore() -> asyncio.Semaphore:
    """Semaphore bound to the running loop (recreated across test loops)."""
    global _fetch_semaphore, _semaphore_loop
    loop = asyncio.get_running_loop()
    if _fetch_semaphore is None or _semaphore_loop is not loop:
        _fetch_semaphore = asyncio.Semaphore(FETCH_CONCURRENCY)
        _semaphore_loop = loop
    return _fetch_semaphore


def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


# --- HTML parsing (stdlib only; the source publishes no structured format) ---

# The section heading across both markup generations: legacy pages carry the
# text directly in an <h2>, the newer /servicing/ pages wrap it in inline
# tags (e.g. <strong>) under an <h3>. Tolerate the small wording variants
# Microsoft has used over the years.
_HEADING_RE = re.compile(
    r"<h(?P<level>[23])[^>]*>\s*(?:<[a-z][^>]*>\s*)*[^<]*"
    r"known issues (?:in|with) this (?:security )?update",
    re.IGNORECASE,
)
# Legacy layout: the section ends at the next top-level section or <h2>;
# issue entries inside it are div-based, never <section>, and legacy issue
# bodies may legitimately contain <h3> tags.
_REGION_END_RE = re.compile(r"<h2[\s>]|<section\s", re.IGNORECASE)
# /servicing/ layout: the <h3> section ends at the next heading of either
# level (the page repeats the section under a second <h3> for the combined
# SSU+LCU package — only the first is parsed).
_REGION_END_NEW_RE = re.compile(r"<h[23][\s>]", re.IGNORECASE)
_ISSUE_BLOCK_RE = re.compile(r'<div class="ocpSection">', re.IGNORECASE)
_ISSUE_TITLE_RE = re.compile(
    r'class="ocpExpandoHeadTitleContainer"[^>]*>(?P<title>.*?)</div>', re.DOTALL
)
_ISSUE_BODY_RE = re.compile(r'class="ocpExpandoBody"[^>]*>', re.IGNORECASE)
# /servicing/ layout: one collapsible <details> element per issue.
_DETAILS_RE = re.compile(r"<details[\s>].*?</details>", re.IGNORECASE | re.DOTALL)
_SUMMARY_RE = re.compile(r"<summary[^>]*>(?P<title>.*?)</summary>", re.IGNORECASE | re.DOTALL)
# Bold paragraph labels segmenting an issue body (legacy <b>, servicing <strong>).
_MARKER_RE = re.compile(
    r'<(?:b class="ocpLegacyBold"|strong)[^>]*>[^<]*?'
    r"(?P<label>symptoms?|workaround|next steps?|resolution)"
    r"[^<]*?</(?:b|strong)>",
    re.IGNORECASE,
)
_RESOLVED_BY_RE = re.compile(
    r"(?:addressed|resolved)\s*(?:in|by)[^.]{0,80}?KB\s?(\d{6,8})", re.IGNORECASE
)

_JUNK_TO_SPACE = dict.fromkeys([0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF, 0xA0], " ")


class _TextExtractor(HTMLParser):
    """Flatten an HTML fragment to plain text (entities resolved, tags dropped)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def handle_starttag(self, tag: str, attrs: list) -> None:
        # Block boundaries become spaces so joined paragraphs stay readable.
        if tag in ("p", "br", "li", "div", "h3", "td", "tr"):
            self.parts.append(" ")


def _text(fragment: str) -> str:
    extractor = _TextExtractor()
    extractor.feed(fragment)
    text = "".join(extractor.parts).translate(_JUNK_TO_SPACE)
    text = re.sub(r"\s+", " ", text).strip()
    return re.sub(r"\s+([.,;:!?)])", r"\1", text)


def _segment_issue_body(body_html: str) -> dict[str, str]:
    """Split an issue body on its bold Symptoms/Workaround/Resolution labels."""
    markers = list(_MARKER_RE.finditer(body_html))
    if not markers:
        text = _text(body_html)
        return {"symptoms": text} if text else {}

    label_field = {
        "symptom": "symptoms",
        "symptoms": "symptoms",
        "workaround": "workaround",
        "next step": "workaround",
        "next steps": "workaround",
        "resolution": "resolution",
    }
    segments: dict[str, list[str]] = {}
    for i, marker in enumerate(markers):
        field = label_field[marker.group("label").lower()]
        end = markers[i + 1].start() if i + 1 < len(markers) else len(body_html)
        text = _text(body_html[marker.end() : end])
        if text:
            segments.setdefault(field, []).append(text)
    return {field: " ".join(parts) for field, parts in segments.items()}


def _attach_resolved_by(issue: dict) -> dict:
    resolved = _RESOLVED_BY_RE.search(
        f"{issue.get('workaround', '')} {issue.get('resolution', '')}"
    )
    if resolved:
        issue["resolved_by"] = f"KB{resolved.group(1)}"
    return issue


def _parse_issue_block(block_html: str) -> dict | None:
    """Parse a legacy ocpSection issue block."""
    title_match = _ISSUE_TITLE_RE.search(block_html)
    if not title_match:
        return None
    title = _text(title_match.group("title"))
    if not title:
        return None

    issue: dict = {"title": title}
    body_match = _ISSUE_BODY_RE.search(block_html)
    if body_match:
        issue.update(_segment_issue_body(block_html[body_match.end() :]))
    return _attach_resolved_by(issue)


def _parse_details_block(block_html: str) -> dict | None:
    """Parse a /servicing/-layout <details> issue block."""
    title_match = _SUMMARY_RE.search(block_html)
    if not title_match:
        return None
    title = _text(title_match.group("title"))
    if not title:
        return None

    issue: dict = {"title": title}
    issue.update(_segment_issue_body(block_html[title_match.end() :]))
    return _attach_resolved_by(issue)


def _parse_known_issues(html: str, kb_number: str, source_url: str) -> dict:
    """Parse a KB support page into the known-issues result contract.

    Pure and side-effect free; returns a ``published`` / ``none_published`` /
    ``unavailable`` dict as documented in the module docstring.
    """
    heading = _HEADING_RE.search(html)
    if heading is None:
        return {
            "status": "none_published",
            "note": (
                f"The Microsoft support page for KB{kb_number} does not publish a "
                "known-issues section (common for non-Windows products)."
            ),
            "source_url": source_url,
        }

    tail = html[heading.end() :]
    end_re = _REGION_END_RE if heading.group("level") == "2" else _REGION_END_NEW_RE
    region_end = end_re.search(tail)
    region = tail[: region_end.start()] if region_end else tail

    issues = []
    for block in _ISSUE_BLOCK_RE.split(region)[1:]:
        issue = _parse_issue_block(block)
        if issue:
            issues.append(issue)
    if not issues:
        for match in _DETAILS_RE.finditer(region):
            issue = _parse_details_block(match.group(0))
            if issue:
                issues.append(issue)

    if issues:
        return {"status": "published", "issues": issues, "source_url": source_url}

    # No structured entries: a short section is Microsoft's explicit "none"
    # statement; a long one means content our parser no longer understands.
    region_text = _text(region)
    if len(region_text) <= _NONE_TEXT_MAX_CHARS:
        return {
            "status": "none_published",
            "note": region_text
            or f"The known-issues section on the KB{kb_number} support page is empty.",
            "source_url": source_url,
        }
    return {
        "status": "unavailable",
        "note": (
            "A known-issues section exists on the Microsoft support page but could not "
            "be parsed into structured entries (the page layout may have changed); "
            "consult the source page directly."
        ),
        "source_url": source_url,
    }


# --- Update-summary parsing (same page, different section family) ---

# Summary/Highlights heading across both generations: legacy pages carry
# <h2>Summary</h2> or <h2>Highlights</h2>, servicing pages <h2 id="summary">.
# Anchored on <h[23] so <summary> tags inside <details> can never match; the
# lookahead keeps the closing "<" out of the match so slicing at end() lands
# right after the heading text.
_SUMMARY_HEADING_RE = re.compile(
    r"<h[23][^>]*>\s*(?:<[a-z][^>]*>\s*)*(?:summary|highlights)\s*(?=<)",
    re.IGNORECASE,
)
# The summary region is intro prose (plus Highlights bullets on legacy
# pages); in both layouts it ends at the next heading or section boundary.
_SUMMARY_REGION_END_RE = re.compile(r"<h[23][\s>]|<section\s", re.IGNORECASE)
# Improvements headings ("Improvements", "Improvements and fixes") plus the
# servicing per-rollout subsections, which can appear directly under Summary
# without a parent Improvements heading.
_IMPROVEMENTS_HEADING_RE = re.compile(
    r"<h(?P<level>[23])[^>]*>\s*(?:<[a-z][^>]*>\s*)*"
    r"(?:improvements|gradual rollout|normal rollout)",
    re.IGNORECASE,
)
# Section headings whose bullets must never be harvested as improvements
# (guards a level-2 region from swallowing a following <h3> section).
_SUMMARY_EXCLUDE_RE = re.compile(
    r"<h[23][^>]*>\s*(?:<[a-z][^>]*>\s*)*[^<]*"
    r"(?:known issues|servicing stack|how to get|file information)",
    re.IGNORECASE,
)
_LI_RE = re.compile(r"<li[^>]*>(?P<item>.*?)</li>", re.IGNORECASE | re.DOTALL)
_ANCHOR_RE = re.compile(r"<a\s[^>]*>.*?</a>", re.IGNORECASE | re.DOTALL)
_H1_RE = re.compile(r"<h1[^>]*>(?P<text>.*?)</h1>", re.IGNORECASE | re.DOTALL)
_TITLE_TAG_RE = re.compile(r"<title[^>]*>(?P<text>.*?)</title>", re.IGNORECASE | re.DOTALL)
_TITLE_SUFFIX_RE = re.compile(r"\s*[-|]\s*Microsoft Support\s*$", re.IGNORECASE)


def _parse_update_summary(html: str, kb_number: str, source_url: str) -> dict:
    """Parse a KB support page into the update-summary result contract.

    Pure and side-effect free; returns a ``published`` / ``none_published`` /
    ``unavailable`` dict as documented in the module docstring.
    """
    truncated = False

    title = ""
    title_match = _H1_RE.search(html) or _TITLE_TAG_RE.search(html)
    if title_match:
        title = _TITLE_SUFFIX_RE.sub("", _text(title_match.group("text")))

    heading = _SUMMARY_HEADING_RE.search(html)
    summary = ""
    if heading:
        tail = html[heading.end() :]
        end = _SUMMARY_REGION_END_RE.search(tail)
        summary = _text(tail[: end.start()] if end else tail)
        if len(summary) > _SUMMARY_MAX_CHARS:
            summary = summary[:_SUMMARY_MAX_CHARS].rstrip() + "..."
            truncated = True

    items: list[str] = []
    for imp in _IMPROVEMENTS_HEADING_RE.finditer(html):
        tail = html[imp.end() :]
        # Same level rule as known issues: a legacy <h2> region legitimately
        # contains <h3> expando blocks, a servicing <h3> ends at any heading.
        end_re = _REGION_END_RE if imp.group("level") == "2" else _REGION_END_NEW_RE
        end = end_re.search(tail)
        region = tail[: end.start()] if end else tail
        excluded = _SUMMARY_EXCLUDE_RE.search(region)
        if excluded:
            region = region[: excluded.start()]
        for li in _LI_RE.finditer(region):
            item_html = li.group("item")
            text = _text(item_html)
            if not text:
                continue
            # CU pages open the Improvements section with links to the prior
            # preview updates / release notes; an item that is nothing but
            # anchors (plus punctuation) is a reference, not an improvement.
            residue = _text(_ANCHOR_RE.sub(" ", item_html))
            if not re.sub(r"[\W_]+", "", residue):
                continue
            items.append(text)

    items = list(dict.fromkeys(items))  # SSU+LCU combined pages repeat sections
    if len(items) > _MAX_IMPROVEMENT_ITEMS:
        items = items[:_MAX_IMPROVEMENT_ITEMS]
        truncated = True
    for i, item in enumerate(items):
        if len(item) > _IMPROVEMENT_ITEM_MAX_CHARS:
            items[i] = item[:_IMPROVEMENT_ITEM_MAX_CHARS].rstrip() + "..."
            truncated = True

    if summary or items:
        result: dict = {"status": "published", "source_url": source_url}
        if title:
            result["title"] = title
        if summary:
            result["summary"] = summary
        if items:
            result["improvements"] = items
        if truncated:
            result["truncated"] = True
        return result
    if heading:
        return {
            "status": "unavailable",
            "note": (
                "A summary section exists on the Microsoft support page but could not "
                "be parsed (the page layout may have changed); consult the source "
                "page directly."
            ),
            "source_url": source_url,
        }
    return {
        "status": "none_published",
        "note": (
            f"The Microsoft support page for KB{kb_number} does not publish a "
            "summary or improvements section."
        ),
        "source_url": source_url,
    }


# --- Fetching ---


def _resolve_redirect(location: str | None) -> str:
    """Validate a Location header, allowing only the same support host."""
    if not location:
        raise KnownIssuesError("KB page redirect carried no Location header")
    if location.startswith("/"):
        return f"https://{SUPPORT_HOST}{location}"
    parts = urlsplit(location)
    if parts.scheme == "https" and parts.hostname == SUPPORT_HOST:
        return location
    raise KnownIssuesError(f"refusing KB page redirect off {SUPPORT_HOST}: {location!r}")


async def _fetch_kb_page(kb_number: str) -> tuple[str | None, str | None]:
    """Fetch the support page for a KB, following bounded validated redirects.

    The /help/{kb} resolver answers with a short same-host redirect chain to
    the canonical article (currently two hops: /topic/... then
    /servicing/os/...); each hop's target is validated before following and
    the hop count is capped at MAX_REDIRECT_HOPS. Returns (final_url, html),
    or (None, None) when Microsoft has no page for this KB. Raises
    KnownIssuesError for anything that is a retrieval failure rather than a
    definitive absence.
    """
    target = SUPPORT_KB_URL.format(kb=kb_number)
    try:
        for _ in range(MAX_REDIRECT_HOPS + 1):
            status, location = await http_client.get_location(target, timeout=30.0)
            if status == 404:
                return None, None
            if status == 200:
                break
            if status in _REDIRECT_STATUSES:
                target = _resolve_redirect(location)
                continue
            raise KnownIssuesError(f"KB page lookup returned HTTP {status}")
        else:
            raise KnownIssuesError(
                f"KB page redirected more than {MAX_REDIRECT_HOPS} times"
            )

        body_status, body = await http_client.get_bounded(
            target, timeout=30.0, max_bytes=MAX_RESPONSE_BYTES
        )
    except httpx.HTTPError as exc:
        raise KnownIssuesError(f"KB page request failed: {exc}") from exc
    if body_status != 200:
        raise KnownIssuesError(f"KB page returned HTTP {body_status}")
    return target, body.decode("utf-8", errors="replace")


def _page_matches_kb(final_url: str, html: str, kb_number: str) -> bool:
    """Whether the landing page provably belongs to the requested KB.

    The /help/{kb} resolver is fuzzy: unknown ids land on unrelated articles,
    and the page echoes the *requested* id in an analytics meta tag either
    way, so in-body digit matches prove nothing. Only the canonical URL slug
    (".../june-9-2026-kb5094126-...") or the page title count as proof.
    Pages that never self-reference (some .NET update pages) fail this check
    and are conservatively reported as having no per-KB page — never as a
    source of issues that might belong to a different update.
    """
    if f"kb{kb_number}" in final_url.lower():
        return True
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return bool(title and re.search(rf"(?<!\d){kb_number}(?!\d)", title.group(1)))


def _cache_get(kb_number: str) -> dict | None:
    cached = _cache.get(kb_number)
    if cached is None or time.monotonic() - cached[0] >= KNOWN_ISSUES_TTL_SECONDS:
        return None
    _cache[kb_number] = _cache.pop(kb_number)  # refresh LRU recency
    return cached[1]


def _cache_put(kb_number: str, result: dict) -> None:
    _cache.pop(kb_number, None)
    _cache[kb_number] = (time.monotonic(), result)
    while len(_cache) > MAX_CACHE_ENTRIES:
        del _cache[next(iter(_cache))]


async def _fetch_kb_record(kb_number: str) -> dict:
    """Fetch + parse the KB support page once, serving both response blocks.

    Returns ``{"known_issues": ..., "update_summary": ...}``; never raises.
    Cached only when neither block is ``unavailable`` — a transient failure
    (or partial layout drift) must not be pinned for a whole TTL.
    """
    cached = _cache_get(kb_number)
    if cached is not None:
        return cached

    start = time.perf_counter()
    try:
        async with _get_fetch_semaphore():
            final_url, html = await _fetch_kb_page(kb_number)
        if html is None or not _page_matches_kb(final_url, html, kb_number):
            # No page, or a landing page that cannot be verified as this KB's:
            # report "no per-KB page" rather than trust another article's data.
            no_page = (
                f"Microsoft publishes no per-KB support page for KB{kb_number}, so no "
                "{what} is available for this update."
            )
            record = {
                "known_issues": {
                    "status": "none_published",
                    "note": no_page.format(what="known-issues data"),
                },
                "update_summary": {
                    "status": "none_published",
                    "note": no_page.format(what="update summary"),
                },
            }
        else:
            record = {
                "known_issues": _parse_known_issues(html, kb_number, final_url),
                "update_summary": _parse_update_summary(html, kb_number, final_url),
            }
    except Exception as exc:  # fail open: enrichment must never break a lookup
        logger.warning("KB support-page fetch failed for KB%s: %s", kb_number, exc)
        telemetry.track_event(
            "enrichment_fetch",
            {"source": "known_issues", "ok": False, "duration_ms": _elapsed_ms(start)},
        )
        source_url = SUPPORT_KB_URL.format(kb=kb_number)
        return {
            "known_issues": {
                "status": "unavailable",
                "note": (
                    "The Microsoft support page for this KB could not be retrieved; "
                    "retry later or check the page directly. This does not mean no "
                    "issues exist."
                ),
                "source_url": source_url,
            },
            "update_summary": {
                "status": "unavailable",
                "note": (
                    "The Microsoft support page for this KB could not be retrieved; "
                    "retry later or check the page directly."
                ),
                "source_url": source_url,
            },
        }

    telemetry.track_event(
        "enrichment_fetch",
        {
            "source": "known_issues",
            "ok": True,
            "duration_ms": _elapsed_ms(start),
            "status": record["known_issues"]["status"],
            "summary_status": record["update_summary"]["status"],
        },
    )
    if all(block["status"] != "unavailable" for block in record.values()):
        _cache_put(kb_number, record)
    return record


async def fetch_known_issues(kb_number: str) -> dict:
    """Best-effort known-issues lookup for a numeric KB id ("5094123").

    Never raises: failures degrade to {"status": "unavailable", ...}. Results
    are cached in-process for KNOWN_ISSUES_TTL_SECONDS (failures are not).
    """
    return (await _fetch_kb_record(kb_number))["known_issues"]


async def fetch_update_summary(kb_number: str) -> dict:
    """Best-effort what-this-update-changes summary for a numeric KB id.

    Never raises. Shares its fetch, trust check, and cache record with
    fetch_known_issues — requesting both blocks costs one page retrieval.
    """
    return (await _fetch_kb_record(kb_number))["update_summary"]


async def prefetch(kb_numbers: list[str]) -> None:
    """Warm the cache for a KB batch; concurrency is semaphore-bounded and
    failures are swallowed (each lookup already fails open)."""
    await asyncio.gather(*(_fetch_kb_record(kb) for kb in kb_numbers))
