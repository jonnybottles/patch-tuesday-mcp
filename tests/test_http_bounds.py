"""Tests for bounded upstream response reads and the redirect policy.

The hosted container has 0.5 GiB; an oversized upstream body (or a redirect
to one) must be rejected while streaming, never buffered whole.
"""

import pytest

from patch_tuesday_mcp.feeds import enrichment, http_client, msrc_api
from patch_tuesday_mcp.feeds.msrc_api import MsrcApiError


class FakeStreamResponse:
    def __init__(self, status_code=200, body=b"{}", headers=None, chunk_size=64):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body
        self._chunk_size = chunk_size
        self.body_consumed = False

    async def aiter_bytes(self):
        self.body_consumed = True
        for i in range(0, len(self._body), self._chunk_size):
            yield self._body[i : i + self._chunk_size]


class FakeClient:
    def __init__(self, response):
        self._response = response

    def stream(self, method, url, **kwargs):
        response = self._response

        class _StreamContext:
            async def __aenter__(self):
                return response

            async def __aexit__(self, *exc):
                return False

        return _StreamContext()


@pytest.fixture(autouse=True)
def reset_caches():
    msrc_api.clear_cache()
    enrichment.clear_cache()
    yield
    msrc_api.clear_cache()
    enrichment.clear_cache()


def _use_fake_client(monkeypatch, response):
    monkeypatch.setattr(http_client, "get_client", lambda: FakeClient(response))
    return response


async def test_msrc_oversized_body_raises_msrc_error(monkeypatch):
    monkeypatch.setattr(msrc_api, "MAX_RESPONSE_BYTES", 100)
    _use_fake_client(monkeypatch, FakeStreamResponse(body=b"x" * 200))
    with pytest.raises(MsrcApiError, match="byte cap"):
        await msrc_api._get_json("https://api.msrc.microsoft.com/test")


async def test_msrc_oversized_content_length_rejected_without_reading(monkeypatch):
    monkeypatch.setattr(msrc_api, "MAX_RESPONSE_BYTES", 100)
    response = FakeStreamResponse(body=b"{}", headers={"content-length": "5000"})
    _use_fake_client(monkeypatch, response)
    with pytest.raises(MsrcApiError, match="byte cap"):
        await msrc_api._get_json("https://api.msrc.microsoft.com/test")
    assert response.body_consumed is False, "declared-oversized body must not be read"


async def test_msrc_within_cap_parses_json(monkeypatch):
    _use_fake_client(monkeypatch, FakeStreamResponse(body=b'{"value": []}'))
    assert await msrc_api._get_json("https://api.msrc.microsoft.com/test") == {"value": []}


async def test_msrc_404_still_maps_to_not_found(monkeypatch):
    _use_fake_client(monkeypatch, FakeStreamResponse(status_code=404))
    with pytest.raises(MsrcApiError, match="not found"):
        await msrc_api._get_json("https://api.msrc.microsoft.com/test")


async def test_msrc_invalid_json_within_cap(monkeypatch):
    _use_fake_client(monkeypatch, FakeStreamResponse(body=b"not json"))
    with pytest.raises(MsrcApiError, match="invalid JSON"):
        await msrc_api._get_json("https://api.msrc.microsoft.com/test")


async def test_enrichment_oversized_kev_fails_open(monkeypatch):
    monkeypatch.setattr(enrichment, "MAX_RESPONSE_BYTES", 100)
    _use_fake_client(monkeypatch, FakeStreamResponse(body=b"x" * 200))
    assert await enrichment.fetch_kev() == {}


async def test_enrichment_within_cap_parses_json(monkeypatch):
    body = b'{"vulnerabilities": [{"cveID": "CVE-2026-1", "dateAdded": "2026-01-01"}]}'
    _use_fake_client(monkeypatch, FakeStreamResponse(body=body))
    catalog = await enrichment.fetch_kev()
    assert "CVE-2026-1" in catalog


async def test_shared_client_does_not_follow_redirects():
    client = http_client.get_client()
    assert client.follow_redirects is False, (
        "redirects could point off the hardcoded hosts; the client must not follow them"
    )


async def test_get_location_returns_redirect_without_following(monkeypatch):
    response = FakeStreamResponse(
        status_code=301, body=b"ignored", headers={"location": "/en-us/topic/some-slug"}
    )
    _use_fake_client(monkeypatch, response)
    status, location = await http_client.get_location("https://support.microsoft.com/x", timeout=5)
    assert (status, location) == (301, "/en-us/topic/some-slug")
    assert response.body_consumed is False, "get_location must not read the body"


async def test_get_location_returns_none_on_non_redirect(monkeypatch):
    _use_fake_client(monkeypatch, FakeStreamResponse(status_code=200, body=b"page"))
    status, location = await http_client.get_location("https://support.microsoft.com/x", timeout=5)
    assert (status, location) == (200, None)
