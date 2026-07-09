"""Tests for the EPSS / CISA KEV enrichment clients (mocked HTTP)."""

import pytest

from patch_tuesday_mcp.feeds import enrichment
from patch_tuesday_mcp.feeds.enrichment import (
    EnrichmentError,
    clear_cache,
    fetch_epss,
    fetch_kev,
)

KEV_RESPONSE = {
    "catalogVersion": "2026.07.07",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-99999",
            "vendorProject": "Microsoft",
            "dateAdded": "2026-06-15",
            "dueDate": "2026-07-06",
            "knownRansomwareCampaignUse": "Known",
            "shortDescription": "Synthetic exploited vulnerability.",
        },
        {
            "cveID": "CVE-2026-12345",
            "vendorProject": "Microsoft",
            "dateAdded": "2026-05-01",
            "dueDate": "2026-05-22",
            "knownRansomwareCampaignUse": "Unknown",
            "shortDescription": "Another one.",
        },
    ],
}


@pytest.fixture(autouse=True)
def reset_cache():
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def mock_api(monkeypatch):
    """Patch _get_json with canned responses and record calls."""
    calls = []

    async def fake_get_json(url, timeout=30.0):
        calls.append(url)
        if "api.first.org" in url:
            cves = url.split("cve=")[1].split(",")
            return {
                "status": "OK",
                # EPSS doesn't know CVE-2026-99999; scores are strings
                "data": [
                    {"cve": c, "epss": "0.500000000", "percentile": "0.900000000"}
                    for c in cves
                    if c != "CVE-2026-99999"
                ],
            }
        if "cisa.gov" in url:
            return KEV_RESPONSE
        raise EnrichmentError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(enrichment, "_get_json", fake_get_json)
    return calls


async def test_epss_batching_and_string_parsing(mock_api):
    cves = [f"CVE-2026-{10000 + i}" for i in range(150)]
    result = await fetch_epss(cves)

    epss_calls = [c for c in mock_api if "api.first.org" in c]
    assert len(epss_calls) == 2, "150 CVEs should need two batches of <=100"
    assert len(epss_calls[0].split(",")) == 100
    assert len(epss_calls[1].split(",")) == 50

    assert len(result) == 150
    score, percentile = result["CVE-2026-10000"]
    assert isinstance(score, float) and score == 0.5
    assert isinstance(percentile, float) and percentile == 0.9


async def test_epss_caching_no_new_requests(mock_api):
    # CVE-2026-99999 is unknown to EPSS: the miss must be cached too
    cves = ["CVE-2026-41108", "CVE-2026-99999"]
    first = await fetch_epss(cves)
    assert "CVE-2026-41108" in first
    assert "CVE-2026-99999" not in first

    second = await fetch_epss(cves)
    assert second == first
    epss_calls = [c for c in mock_api if "api.first.org" in c]
    assert len(epss_calls) == 1, "second call must be served from the cache"


async def test_kev_caching_and_parse(mock_api):
    catalog = await fetch_kev()
    assert catalog["CVE-2026-99999"] == {
        "date_added": "2026-06-15",
        "due_date": "2026-07-06",
        "ransomware_use": "Known",
        "vendor_project": "Microsoft",
    }
    assert set(catalog) == {"CVE-2026-99999", "CVE-2026-12345"}

    await fetch_kev()
    kev_calls = [c for c in mock_api if "cisa.gov" in c]
    assert len(kev_calls) == 1, "catalog is cached within the TTL"


async def test_fetch_failures_return_empty(monkeypatch):
    async def failing_get_json(url, timeout=30.0):
        raise EnrichmentError("boom")

    monkeypatch.setattr(enrichment, "_get_json", failing_get_json)
    assert await fetch_kev() == {}
    assert await fetch_epss(["CVE-2026-41108"]) == {}


async def test_epss_partial_batch_failure(monkeypatch):
    """A failing batch is skipped; other batches still return results."""
    calls = []

    async def flaky_get_json(url, timeout=30.0):
        calls.append(url)
        if len(calls) == 1:
            raise EnrichmentError("boom")
        cves = url.split("cve=")[1].split(",")
        return {
            "status": "OK",
            "data": [{"cve": c, "epss": "0.1", "percentile": "0.2"} for c in cves],
        }

    monkeypatch.setattr(enrichment, "_get_json", flaky_get_json)
    cves = [f"CVE-2026-{10000 + i}" for i in range(150)]
    result = await fetch_epss(cves)
    assert len(result) == 50, "second batch should still be returned"


# --- force_refresh + freshness metadata ---


async def test_force_refresh_bypasses_epss_cache(mock_api):
    cves = ["CVE-2026-41108"]
    await fetch_epss(cves)
    await fetch_epss(cves, force_refresh=True)
    epss_calls = [c for c in mock_api if "api.first.org" in c]
    assert len(epss_calls) == 2, "force_refresh must re-request even when cached"


async def test_force_refresh_bypasses_kev_cache(mock_api):
    await fetch_kev()
    await fetch_kev(force_refresh=True)
    kev_calls = [c for c in mock_api if "cisa.gov" in c]
    assert len(kev_calls) == 2, "force_refresh must re-fetch the KEV catalog"


async def test_kev_freshness_metadata(mock_api):
    assert enrichment.kev_freshness() == {
        "available": False,
        "ttl_seconds": enrichment.KEV_TTL_SECONDS,
    }
    await fetch_kev()
    meta = enrichment.kev_freshness()
    assert meta["available"] is True
    assert meta["ttl_seconds"] == enrichment.KEV_TTL_SECONDS
    assert meta["age_seconds"] >= 0
    assert meta["stale"] is False


async def test_epss_freshness_metadata(mock_api):
    cves = ["CVE-2026-41108", "CVE-2026-99999"]  # second is unknown to EPSS
    await fetch_epss(cves)
    meta = enrichment.epss_freshness(cves)
    assert meta["ttl_seconds"] == enrichment.EPSS_TTL_SECONDS
    assert meta["requested"] == 2
    assert meta["covered"] == 1  # only the known CVE has a score
    assert meta["age_seconds"] >= 0
    assert meta["stale"] is False

    empty = enrichment.epss_freshness(["CVE-2026-00000"])
    assert empty["available"] is False


# --- Cache bounds, fetch concurrency, telemetry ---


async def test_epss_cache_is_bounded(mock_api, monkeypatch):
    monkeypatch.setattr(enrichment, "MAX_EPSS_CACHE_ENTRIES", 3)
    await fetch_epss([f"CVE-2026-{20000 + i}" for i in range(5)])
    assert len(enrichment._epss_cache) <= 3, "EPSS cache must not grow unboundedly"


async def test_epss_batches_fetch_concurrently(monkeypatch):
    import asyncio

    active = 0
    peak = 0

    async def fake_get_json(url, timeout=30.0):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        cves = url.split("cve=")[1].split(",")
        return {
            "status": "OK",
            "data": [{"cve": c, "epss": "0.1", "percentile": "0.2"} for c in cves],
        }

    monkeypatch.setattr(enrichment, "_get_json", fake_get_json)
    monkeypatch.setattr(enrichment, "EPSS_BATCH_SIZE", 1)
    result = await fetch_epss([f"CVE-2026-{30000 + i}" for i in range(6)])
    assert len(result) == 6
    assert peak >= 2, "batches must be fetched concurrently"
    assert peak <= 3, "batch concurrency must stay bounded"


async def test_enrichment_fetch_emits_telemetry(mock_api, monkeypatch):
    events = []
    monkeypatch.setattr(
        enrichment.telemetry, "track_event", lambda name, props: events.append((name, props))
    )
    await fetch_kev()
    await fetch_epss(["CVE-2026-10000"])
    sources = [p["source"] for n, p in events if n == "enrichment_fetch"]
    assert "kev" in sources
    assert "epss" in sources

