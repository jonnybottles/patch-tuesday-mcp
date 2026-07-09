"""Tests for the rate-limit/body-limit middleware and telemetry no-op behavior."""

from patch_tuesday_mcp import telemetry
from patch_tuesday_mcp.middleware import rate_limit
from patch_tuesday_mcp.middleware.body_limit import BodyLimitMiddleware
from patch_tuesday_mcp.middleware.rate_limit import RateLimitMiddleware


async def _ok_app(scope, receive, send):
    # Drain the request body like a real app would before responding
    while True:
        message = await receive()
        if message["type"] != "http.request" or not message.get("more_body"):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _http_scope(ip="1.2.3.4", forwarded=None, path="/mcp"):
    headers = []
    if forwarded:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    return {"type": "http", "headers": headers, "client": (ip, 12345), "path": path}


async def _call(middleware, scope, body_chunks=(b"",)):
    """Run one request through the middleware, returning the response status."""
    sent = []
    chunks = list(body_chunks)

    async def send(message):
        sent.append(message)

    async def receive():
        chunk = chunks.pop(0) if chunks else b""
        return {"type": "http.request", "body": chunk, "more_body": bool(chunks)}

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


async def test_uses_x_forwarded_for_rightmost_hop():
    """The rightmost XFF entry (appended by the trusted ingress) is the client."""
    mw = RateLimitMiddleware(_ok_app, requests_per_minute=2)
    scope = _http_scope(ip="10.0.0.1", forwarded="203.0.113.7, 198.51.100.1")
    for _ in range(2):
        await _call(mw, scope)
    assert await _call(mw, scope) == 429
    # Different ingress-observed client is not limited
    other = _http_scope(ip="10.0.0.1", forwarded="203.0.113.7, 198.51.100.2")
    assert await _call(mw, other) == 200


async def test_spoofed_forwarded_for_cannot_evade_limit():
    """Rotating the client-supplied first XFF hop must not reset the bucket."""
    mw = RateLimitMiddleware(_ok_app, requests_per_minute=2)
    for i in range(2):
        scope = _http_scope(ip="10.0.0.1", forwarded=f"1.2.3.{i}, 198.51.100.1")
        assert await _call(mw, scope) == 200
    scope = _http_scope(ip="10.0.0.1", forwarded="1.2.3.99, 198.51.100.1")
    assert await _call(mw, scope) == 429


async def test_xff_ignored_when_not_trusted():
    """With trust disabled, only the direct peer IP keys the bucket."""
    mw = RateLimitMiddleware(_ok_app, requests_per_minute=2, trust_x_forwarded_for=False)
    # Different XFF values but same direct peer -> same bucket
    for i in range(2):
        assert await _call(mw, _http_scope(ip="10.0.0.1", forwarded=f"203.0.113.{i}")) == 200
    assert await _call(mw, _http_scope(ip="10.0.0.1", forwarded="203.0.113.9")) == 429
    # A genuinely different peer is independent
    assert await _call(mw, _http_scope(ip="10.0.0.2", forwarded="203.0.113.9")) == 200


async def test_trusted_proxies_unwinds_to_real_client():
    """With a proxy allowlist, the client is the right-most non-proxy hop."""
    mw = RateLimitMiddleware(
        _ok_app,
        requests_per_minute=2,
        trusted_proxies=frozenset({"10.0.0.1", "198.51.100.1"}),
    )
    # Peer is a trusted proxy; both trailing hops are trusted proxies, so the
    # real client is 203.0.113.7
    scope = _http_scope(ip="10.0.0.1", forwarded="203.0.113.7, 198.51.100.1")
    for _ in range(2):
        assert await _call(mw, scope) == 200
    assert await _call(mw, scope) == 429
    # A different real client behind the same proxy chain is independent
    other = _http_scope(ip="10.0.0.1", forwarded="203.0.113.8, 198.51.100.1")
    assert await _call(mw, other) == 200


async def test_untrusted_peer_ignores_forwarded_for():
    """If the request did not arrive via a known proxy, XFF is not honored."""
    mw = RateLimitMiddleware(
        _ok_app,
        requests_per_minute=2,
        trusted_proxies=frozenset({"10.0.0.1"}),
    )
    # Peer 9.9.9.9 is NOT a trusted proxy -> XFF ignored, keyed on peer
    for i in range(2):
        assert await _call(mw, _http_scope(ip="9.9.9.9", forwarded=f"1.2.3.{i}")) == 200
    assert await _call(mw, _http_scope(ip="9.9.9.9", forwarded="1.2.3.99")) == 429


async def test_bucket_hard_cap_evicts_oldest(monkeypatch):
    """A flood of distinct client IPs must not grow the bucket table unboundedly."""
    monkeypatch.setattr(rate_limit, "PRUNE_THRESHOLD", 5)
    mw = RateLimitMiddleware(_ok_app, requests_per_minute=10)
    for i in range(50):
        await _call(mw, _http_scope(ip=f"10.1.1.{i}"))
    assert len(mw._buckets) <= 5


async def test_health_path_is_exempt():
    mw = RateLimitMiddleware(_ok_app, requests_per_minute=1)
    assert await _call(mw, _http_scope()) == 200
    assert await _call(mw, _http_scope()) == 429
    # /health bypasses the limiter entirely, even with the budget exhausted
    for _ in range(5):
        assert await _call(mw, _http_scope(path="/health")) == 200


async def test_zero_rpm_disables_limiting():
    mw = RateLimitMiddleware(_ok_app, requests_per_minute=0)
    for _ in range(10):
        assert await _call(mw, _http_scope()) == 200


async def test_on_request_callback_gets_client_ip_and_path():
    seen = []
    mw = RateLimitMiddleware(
        _ok_app, requests_per_minute=5, on_request=lambda ip, path: seen.append((ip, path))
    )
    await _call(mw, _http_scope(ip="9.9.9.9"))
    await _call(mw, _http_scope(ip="9.9.9.9", path="/health"))
    assert seen == [("9.9.9.9", "/mcp")], "exempt paths are not counted"


# --- Body size limiting ---


async def test_body_limit_rejects_declared_content_length():
    mw = BodyLimitMiddleware(_ok_app, max_bytes=10)
    scope = _http_scope()
    scope["headers"].append((b"content-length", b"11"))
    assert await _call(mw, scope) == 413


async def test_body_limit_rejects_streamed_oversize_body():
    mw = BodyLimitMiddleware(_ok_app, max_bytes=10)
    assert await _call(mw, _http_scope(), body_chunks=[b"x" * 8, b"y" * 8]) == 413


async def test_body_limit_allows_small_bodies():
    mw = BodyLimitMiddleware(_ok_app, max_bytes=10)
    scope = _http_scope()
    scope["headers"].append((b"content-length", b"4"))
    assert await _call(mw, scope, body_chunks=[b"ok!!"]) == 200


async def test_body_limit_zero_disables():
    mw = BodyLimitMiddleware(_ok_app, max_bytes=0)
    assert await _call(mw, _http_scope(), body_chunks=[b"x" * 1000]) == 200


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
