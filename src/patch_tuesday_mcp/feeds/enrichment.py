"""EPSS and CISA KEV enrichment clients with in-process caching.

Both sources are fully public and keyless:
- EPSS (FIRST.org): daily exploitation probability per CVE
  https://www.first.org/epss/api
- CISA KEV: the Known Exploited Vulnerabilities catalog
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Enrichment is best-effort: fetch failures are logged and swallowed so the
tool layer always gets a dict back (possibly empty), never an exception.
"""

import asyncio
import json
import logging
import os
import time

import httpx

from .. import telemetry
from . import http_client

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# Cap on a single upstream response body. The KEV catalog is a few MiB and
# EPSS batches are small; well beyond that means a misbehaving upstream.
MAX_RESPONSE_BYTES = int(os.getenv("MCP_ENRICHMENT_MAX_RESPONSE_BYTES", str(32 * 1024 * 1024)))

EPSS_BATCH_SIZE = 100
EPSS_FETCH_CONCURRENCY = 3  # bounded parallelism for multi-batch (trend) fetches
EPSS_TTL_SECONDS = 24 * 3600  # EPSS scores update daily
KEV_TTL_SECONDS = 6 * 3600

# Every distinct CVE ever enriched leaves a cache entry (including negative-
# cached misses); cap it so a long-lived process can't grow without bound.
MAX_EPSS_CACHE_ENTRIES = 50_000

logger = logging.getLogger(__name__)

# Caches: cve -> (fetched_at, (score, percentile) | None for a known miss);
# KEV catalog -> [fetched_at, {cveID: {...}}] when populated
_epss_cache: dict[str, tuple[float, tuple[float, float] | None]] = {}
_kev_cache: list = []


class EnrichmentError(Exception):
    """Raised when an enrichment API returns an error or unexpected response."""


def clear_cache() -> None:
    """Reset all caches (used by tests)."""
    _epss_cache.clear()
    _kev_cache.clear()


def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


async def _get_json(url: str, timeout: float = 30.0) -> dict:
    """GET a URL and return parsed JSON, raising EnrichmentError on failure."""
    headers = {"Accept": "application/json"}
    try:
        status, body = await http_client.get_bounded(
            url, headers=headers, timeout=timeout, max_bytes=MAX_RESPONSE_BYTES
        )
    except httpx.HTTPError as exc:
        raise EnrichmentError(f"Enrichment request failed: {exc}") from exc

    if status != 200:
        raise EnrichmentError(f"Enrichment API returned HTTP {status}")

    try:
        return json.loads(body)
    except ValueError as exc:
        raise EnrichmentError("Enrichment API returned invalid JSON") from exc


async def fetch_kev(force_refresh: bool = False) -> dict[str, dict]:
    """Fetch the CISA KEV catalog keyed by CVE ID.

    Returns {} on failure — enrichment must never break a search. When
    force_refresh is True the in-process cache is bypassed and re-fetched.
    """
    now = time.monotonic()
    if not force_refresh and _kev_cache and now - _kev_cache[0] < KEV_TTL_SECONDS:
        return _kev_cache[1]

    start = time.perf_counter()
    try:
        data = await _get_json(KEV_CATALOG_URL, timeout=60.0)
    except EnrichmentError as exc:
        logger.warning("KEV catalog fetch failed: %s", exc)
        telemetry.track_event(
            "enrichment_fetch",
            {"source": "kev", "ok": False, "duration_ms": _elapsed_ms(start)},
        )
        return {}
    telemetry.track_event(
        "enrichment_fetch",
        {"source": "kev", "ok": True, "duration_ms": _elapsed_ms(start)},
    )

    catalog: dict[str, dict] = {}
    for entry in data.get("vulnerabilities", []):
        cve_id = entry.get("cveID")
        if not cve_id:
            continue
        fields = {
            "date_added": entry.get("dateAdded"),
            "due_date": entry.get("dueDate"),
            "ransomware_use": entry.get("knownRansomwareCampaignUse"),
            # Extra catalog fields, surfaced only via include_kev_details
            "required_action": entry.get("requiredAction"),
            "vendor_project": entry.get("vendorProject"),
            "product": entry.get("product"),
            "vulnerability_name": entry.get("vulnerabilityName"),
        }
        catalog[cve_id] = {k: v for k, v in fields.items() if v is not None}

    _kev_cache[:] = [now, catalog]
    return catalog


async def fetch_epss(
    cves: list[str], force_refresh: bool = False
) -> dict[str, tuple[float, float]]:
    """Fetch EPSS (score, percentile) for the given CVEs, batching and caching.

    CVEs unknown to EPSS are absent from the result (and negatively cached so
    they are not re-requested within the TTL). Partial results are returned
    when some batches fail. When force_refresh is True cached entries for the
    requested CVEs are ignored and re-fetched.
    """
    now = time.monotonic()
    results: dict[str, tuple[float, float]] = {}
    uncached: list[str] = []
    seen: set[str] = set()

    for cve in cves:
        if not cve or cve in seen:
            continue
        seen.add(cve)
        cached = _epss_cache.get(cve)
        if not force_refresh and cached and now - cached[0] < EPSS_TTL_SECONDS:
            if cached[1] is not None:
                results[cve] = cached[1]
        else:
            uncached.append(cve)

    if uncached:
        # Wide (trend) requests span many batches; fetch them with bounded
        # concurrency instead of paying serial round-trips.
        semaphore = asyncio.Semaphore(EPSS_FETCH_CONCURRENCY)

        async def fetch_batch(batch: list[str]) -> tuple[list[str], dict | None]:
            async with semaphore:
                batch_start = time.perf_counter()
                try:
                    data = await _get_json(f"{EPSS_API_URL}?cve={','.join(batch)}")
                except EnrichmentError as exc:
                    logger.warning("EPSS fetch failed for batch of %d CVEs: %s", len(batch), exc)
                    telemetry.track_event(
                        "enrichment_fetch",
                        {"source": "epss", "ok": False, "duration_ms": _elapsed_ms(batch_start)},
                    )
                    return batch, None
                telemetry.track_event(
                    "enrichment_fetch",
                    {"source": "epss", "ok": True, "duration_ms": _elapsed_ms(batch_start)},
                )
                return batch, data

        batches = [
            uncached[start : start + EPSS_BATCH_SIZE]
            for start in range(0, len(uncached), EPSS_BATCH_SIZE)
        ]
        for batch, data in await asyncio.gather(*(fetch_batch(b) for b in batches)):
            if data is None:
                continue

            fetched: dict[str, tuple[float, float]] = {}
            for entry in data.get("data", []):
                cve = entry.get("cve")
                try:
                    score = float(entry["epss"])
                    percentile = float(entry["percentile"])
                except (KeyError, TypeError, ValueError):
                    continue
                if cve:
                    fetched[cve] = (score, percentile)

            for cve in batch:
                # Absent CVEs are cached as misses so repeat calls stay cache-only
                _epss_cache[cve] = (now, fetched.get(cve))
                if cve in fetched:
                    results[cve] = fetched[cve]

        while len(_epss_cache) > MAX_EPSS_CACHE_ENTRIES:
            del _epss_cache[next(iter(_epss_cache))]

    return results


def kev_freshness() -> dict:
    """Freshness metadata for the KEV catalog cache.

    Returns age of the cached catalog (seconds since fetch), its TTL, and
    whether catalog data is currently available.
    """
    if not _kev_cache:
        return {"available": False, "ttl_seconds": KEV_TTL_SECONDS}
    age = time.monotonic() - _kev_cache[0]
    return {
        "available": True,
        "age_seconds": round(age, 1),
        "ttl_seconds": KEV_TTL_SECONDS,
        "stale": age >= KEV_TTL_SECONDS,
    }


def epss_freshness(cves: list[str]) -> dict:
    """Freshness metadata for EPSS scores covering the given CVEs.

    Reports the oldest cache age across the requested CVEs (the worst case),
    the TTL, and how many of the requested CVEs have a cached EPSS score.
    """
    now = time.monotonic()
    ages: list[float] = []
    covered = 0
    requested = 0
    seen: set[str] = set()
    for cve in cves:
        if not cve or cve in seen:
            continue
        seen.add(cve)
        requested += 1
        entry = _epss_cache.get(cve)
        if entry is None:
            continue
        ages.append(now - entry[0])
        if entry[1] is not None:
            covered += 1

    meta: dict = {
        "ttl_seconds": EPSS_TTL_SECONDS,
        "requested": requested,
        "covered": covered,
    }
    if ages:
        oldest = max(ages)
        meta["age_seconds"] = round(oldest, 1)
        meta["stale"] = oldest >= EPSS_TTL_SECONDS
    else:
        meta["available"] = False
    return meta
