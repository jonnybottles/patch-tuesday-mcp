"""Tests for the rate-limit middleware and telemetry no-op behavior."""

from patch_tuesday_mcp import telemetry
from patch_tuesday_mcp.middleware.rate_limit import RateLimitMiddleware


async def _ok_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _http_scope(ip="1.2.3.4", forwarded=None):
    headers = []
    if forwarded:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    return {"type": "http", "headers": headers, "client": (ip, 12345)}


async def _call(middleware, scope):
    """Run one request through the middleware, returning the response status."""
    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b""}

    await middleware(scope, receive, send)
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


async def test_allows_within_budget():
    mw = RateLimitMiddleware(_ok_app, requests_per_minute=5)
    for _ in range(5):
        assert await _call(mw, _http_scope()) == 200


async def test_blocks_over_budget_with_429():
    mw = RateLimitMiddleware(_ok_app, requests_per_minute=3)
    for _ in range(3):
        await _call(mw, _http_scope())
    assert await _call(mw, _http_scope()) == 429


async def test_limits_are_per_ip():
    mw = RateLimitMiddleware(_ok_app, requests_per_minute=2)
    for _ in range(2):
        await _call(mw, _http_scope(ip="1.1.1.1"))
    assert await _call(mw, _http_scope(ip="1.1.1.1")) == 429
    assert await _call(mw, _http_scope(ip="2.2.2.2")) == 200


async def test_uses_x_forwarded_for_first_hop():
    mw = RateLimitMiddleware(_ok_app, requests_per_minute=2)
    scope = _http_scope(ip="10.0.0.1", forwarded="203.0.113.7, 10.0.0.1")
    for _ in range(2):
        await _call(mw, scope)
    assert await _call(mw, scope) == 429
    # Same proxy IP but different original client is not limited
    other = _http_scope(ip="10.0.0.1", forwarded="198.51.100.9, 10.0.0.1")
    assert await _call(mw, other) == 200


async def test_zero_rpm_disables_limiting():
    mw = RateLimitMiddleware(_ok_app, requests_per_minute=0)
    for _ in range(10):
        assert await _call(mw, _http_scope()) == 200


async def test_on_request_callback_gets_client_ip():
    seen = []
    mw = RateLimitMiddleware(_ok_app, requests_per_minute=5, on_request=seen.append)
    await _call(mw, _http_scope(ip="9.9.9.9"))
    assert seen == ["9.9.9.9"]


def test_telemetry_disabled_without_connection_string(monkeypatch):
    monkeypatch.delenv("APPLICATIONINSIGHTS_CONNECTION_STRING", raising=False)
    assert telemetry.setup_telemetry() is False
    assert telemetry.is_enabled() is False
    # Tracking calls are safe no-ops when disabled
    telemetry.track_event("test", {"a": 1})
    telemetry.track_request("1.2.3.4")
    telemetry.track_tool_call("msrc_search", {"query": "x"}, 5, 12.3)


def test_telemetry_requires_optional_package(monkeypatch):
    # Connection string set, but azure-monitor-opentelemetry is not installed
    # in the dev environment -> setup must fail gracefully
    monkeypatch.setenv(
        "APPLICATIONINSIGHTS_CONNECTION_STRING",
        "InstrumentationKey=00000000-0000-0000-0000-000000000000",
    )
    assert telemetry.setup_telemetry() is False


def test_hash_client_ip_is_stable_and_anonymous():
    h1 = telemetry.hash_client_ip("1.2.3.4")
    h2 = telemetry.hash_client_ip("1.2.3.4")
    assert h1 == h2
    assert "1.2.3.4" not in h1
    assert len(h1) == 16
