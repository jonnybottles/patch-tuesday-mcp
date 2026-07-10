"""End-to-end endpoint suite: MCP protocol + middleware over real HTTP.

Runs against an already-running server — a local container
(``docker run -p 8000:8000 ...`` then ``--endpoint-url=http://localhost:8000``)
or the hosted ACA endpoint. Business logic is covered offline by
test_tools.py; these tests prove that the transport, the composed middleware
stack, the container, and the deployment serve that logic correctly, so they
assert invariants (shapes, error kinds, version match), never exact live
values.

Marker map (see conftest.py):
- ``endpoint``          — every test here; needs ``--endpoint-url``
- ``endpoint_upstream`` — additionally triggers real MSRC/EPSS/KEV fetches
- ``endpoint_burst``    — rate-limit burst; needs ``--endpoint-burst``; must
  only run against local containers (the hosted per-IP bucket is shared)

The whole suite stays well under the default 60 req/min rate limit; upstream
results are cached in ``_cache`` so chained tests don't re-query. Back-to-back
runs against the same server within a minute can still trip the limiter
(especially after ``--endpoint-burst`` drains the bucket) — wait ~1 minute or
restart the container between runs.
"""

import json
import os
import re

import httpx
import pytest
from fastmcp import Client

from patch_tuesday_mcp import __version__

pytestmark = pytest.mark.endpoint

MONTH_RE = re.compile(r"^\d{4}-[A-Z][a-z]{2}$")
HTTP_TIMEOUT = 30.0

# Upstream responses shared across tests to keep the request budget low;
# populated lazily so each test still passes when run alone.
_cache: dict = {}


def _mcp_client(base_url: str) -> Client:
    return Client(f"{base_url}/mcp")


def _payload(result) -> dict:
    """Extract the msrc_search JSON dict from a CallToolResult."""
    data = getattr(result, "data", None)
    if isinstance(data, dict):
        return data
    return json.loads(result.content[0].text)


async def _default_search(client: Client) -> dict:
    if "default_search" not in _cache:
        _cache["default_search"] = _payload(await client.call_tool("msrc_search", {"limit": 3}))
    return _cache["default_search"]


# --- Transport and metadata (no upstream fetches) ---


def test_health_reports_expected_version(endpoint_url):
    response = httpx.get(f"{endpoint_url}/health", timeout=HTTP_TIMEOUT)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["server"] == "patch-tuesday-mcp"
    # The server under test must be the version this checkout expects
    # (override with PT_EXPECTED_VERSION when testing across versions).
    assert body["version"] == os.getenv("PT_EXPECTED_VERSION", __version__)


async def test_mcp_lists_msrc_search_tool(endpoint_url):
    async with _mcp_client(endpoint_url) as client:
        tools = await client.list_tools()
    tool = next(t for t in tools if t.name == "msrc_search")
    assert tool.title == "Search Microsoft Security Updates"
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.idempotentHint is True
    assert tool.inputSchema["properties"]["limit"]["maximum"] == 100


async def test_mcp_lists_monthly_triage_prompt(endpoint_url):
    async with _mcp_client(endpoint_url) as client:
        prompts = await client.list_prompts()
    prompt = next(p for p in prompts if p.name == "monthly_triage")
    assert prompt.title == "Monthly Patch Tuesday Triage"
    arg_names = {a.name for a in (prompt.arguments or [])}
    assert {"product_profile", "month"} <= arg_names


async def test_prompt_renders_whole_release_without_args(endpoint_url):
    async with _mcp_client(endpoint_url) as client:
        result = await client.get_prompt("monthly_triage", {})
    text = result.messages[0].content.text
    assert "msrc_search" in text
    assert "whole release" in text
    assert "product_profile=" not in text


async def test_prompt_threads_profile_and_month(endpoint_url):
    async with _mcp_client(endpoint_url) as client:
        result = await client.get_prompt(
            "monthly_triage", {"product_profile": "identity-core", "month": "2026-Jun"}
        )
    text = result.messages[0].content.text
    assert 'product_profile="identity-core"' in text
    assert 'month="2026-Jun"' in text


async def test_invalid_format_returns_invalid_input(endpoint_url):
    # Rejected by input validation before any upstream fetch (tools/search.py),
    # and proves the error contract survives the protocol round-trip.
    async with _mcp_client(endpoint_url) as client:
        result = await client.call_tool("msrc_search", {"format": "bogus"})
    payload = _payload(result)
    assert payload["error_kind"] == "invalid_input"
    assert "Invalid format" in payload["error"]


def test_oversized_body_is_rejected(endpoint_url):
    body = b"x" * (300 * 1024)  # default MCP_MAX_BODY_BYTES cap is 256 KiB
    try:
        response = httpx.post(
            f"{endpoint_url}/mcp",
            content=body,
            headers={"Content-Type": "application/json"},
            timeout=HTTP_TIMEOUT,
        )
    except (httpx.RemoteProtocolError, httpx.WriteError):
        # The server refuses early and closes the connection; ingress proxies
        # (ACA/Envoy) can surface that as a disconnect instead of relaying the
        # 413. Either way the oversized request was never processed.
        return
    assert response.status_code == 413


def test_cors_preflight_allows_post(endpoint_url):
    response = httpx.options(
        f"{endpoint_url}/mcp",
        headers={
            "Origin": "https://client.example",
            "Access-Control-Request-Method": "POST",
        },
        timeout=HTTP_TIMEOUT,
    )
    assert response.status_code == 200
    assert "access-control-allow-origin" in response.headers
    assert "POST" in response.headers["access-control-allow-methods"]


# --- Tool calls through the wire (real upstream fetches) ---


@pytest.mark.endpoint_upstream
async def test_default_search_shape(endpoint_url):
    async with _mcp_client(endpoint_url) as client:
        payload = await _default_search(client)
    assert "error" not in payload, payload.get("error")
    assert MONTH_RE.match(payload["month"])
    assert payload["total_found"] > 0
    vulns = payload["vulnerabilities"]
    assert 0 < len(vulns) <= 3
    for v in vulns:
        assert v["cve"].upper().startswith("CVE-")
        assert v["url"].startswith("https://msrc.microsoft.com/")
        # Broad summaries stay lean — CVSS/reference fields are opt-in.
        assert "cvss" not in v
        assert "references" not in v


@pytest.mark.endpoint_upstream
async def test_cve_fast_path_returns_detail(endpoint_url):
    async with _mcp_client(endpoint_url) as client:
        search = await _default_search(client)
        cve = search["vulnerabilities"][0]["cve"]
        detail = _payload(await client.call_tool("msrc_search", {"cve": cve}))
    vuln = detail["vulnerabilities"][0]
    assert vuln["cve"] == cve
    refs = vuln["references"]
    assert refs["msrc"].endswith(cve)
    assert refs["nvd"] == f"https://nvd.nist.gov/vuln/detail/{cve}"


@pytest.mark.endpoint_upstream
async def test_kb_fast_path_finds_fixing_cves(endpoint_url):
    async with _mcp_client(endpoint_url) as client:
        search = await _default_search(client)
        # MSRC's KB field also carries non-KB values like "Release Notes".
        kbs = [
            kb
            for v in search["vulnerabilities"]
            for kb in v.get("kb_articles", [])
            if str(kb).isdigit()
        ]
        if not kbs:
            pytest.skip("no numeric KB articles on the sampled vulnerabilities this month")
        payload = _payload(await client.call_tool("msrc_search", {"kb": kbs[0], "limit": 3}))
    assert "error" not in payload, payload.get("error")
    assert payload["total_found"] > 0
    assert payload["filters_applied"]["kb"] == f"KB{kbs[0]}"


@pytest.mark.endpoint_upstream
async def test_list_months_catalog(endpoint_url):
    async with _mcp_client(endpoint_url) as client:
        payload = _payload(await client.call_tool("msrc_search", {"list_months": True}))
    assert "error" not in payload, payload.get("error")
    assert payload["total_found"] > 0
    months = payload["available_months"]
    assert MONTH_RE.match(months[0]["id"])


@pytest.mark.endpoint_upstream
async def test_trend_search_shape(endpoint_url):
    async with _mcp_client(endpoint_url) as client:
        payload = _payload(
            await client.call_tool(
                "msrc_search",
                {"months_back": 2, "limit": 0, "include_stats": True},
            )
        )
    assert "error" not in payload, payload.get("error")
    assert "month" not in payload, "trend responses use a range, not a single month"
    assert 1 <= payload["months_searched"] <= 2
    assert len(payload["trend"]) == payload["months_searched"]
    assert payload["trend"][0]["month"] == payload["range"]["end"]


@pytest.mark.endpoint_upstream
async def test_markdown_triage_report(endpoint_url):
    async with _mcp_client(endpoint_url) as client:
        payload = _payload(
            await client.call_tool("msrc_search", {"format": "markdown", "limit": 5})
        )
    assert "error" not in payload, payload.get("error")
    assert payload["format"] == "markdown"
    assert payload["markdown"].startswith("# Patch Tuesday Triage")
    # JSON results ride along unchanged next to the rendering.
    assert payload["total_found"] >= len(payload["vulnerabilities"])


@pytest.mark.endpoint_upstream
async def test_absent_month_is_honest_not_found(endpoint_url):
    async with _mcp_client(endpoint_url) as client:
        result = await client.call_tool("msrc_search", {"month": "1999-Jan"})
    payload = _payload(result)
    assert payload["error_kind"] == "not_found"


# --- Rate limiting (keep last: it drains the shared per-IP bucket) ---


@pytest.mark.endpoint_burst
def test_rate_limit_burst_throttles(endpoint_url):
    throttled = None
    with httpx.Client(timeout=HTTP_TIMEOUT) as client:
        # Default bucket is 60/min; earlier tests consumed part of it.
        for _ in range(80):
            response = client.get(f"{endpoint_url}/missing")
            if response.status_code == 429:
                throttled = response
                break
    assert throttled is not None, "expected a 429 within the burst"
    assert "retry-after" in throttled.headers
