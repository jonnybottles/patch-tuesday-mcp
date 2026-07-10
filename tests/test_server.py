"""Tests for server wiring: tool registration metadata and the health route."""

import logging

import httpx
from fastmcp import Client

from patch_tuesday_mcp import __version__, server
from patch_tuesday_mcp.server import mcp


async def test_tool_metadata_and_schema():
    async with Client(mcp) as client:
        tools = await client.list_tools()
        tool = next(t for t in tools if t.name == "msrc_search")

        assert tool.title == "Search Microsoft Security Updates"
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.idempotentHint is True
        assert tool.annotations.openWorldHint is True

        limit_schema = tool.inputSchema["properties"]["limit"]
        assert limit_schema["maximum"] == 100
        assert limit_schema["minimum"] == 0
        assert tool.inputSchema["properties"]["offset"]["minimum"] == 0


async def test_health_route():
    app = mcp.http_app(stateless_http=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__


def test_cors_origins_defaults_to_all(monkeypatch):
    monkeypatch.delenv("MCP_CORS_ORIGINS", raising=False)
    assert server._cors_origins() == ["*"]


def test_cors_origins_parses_allowlist(monkeypatch):
    monkeypatch.setenv("MCP_CORS_ORIGINS", "https://a.example.com, https://b.example.com")
    assert server._cors_origins() == ["https://a.example.com", "https://b.example.com"]


def test_cors_origins_blank_falls_back_to_all(monkeypatch):
    monkeypatch.setenv("MCP_CORS_ORIGINS", "   ")
    assert server._cors_origins() == ["*"]


def test_trusted_proxies_parsing(monkeypatch):
    monkeypatch.delenv("MCP_TRUSTED_PROXIES", raising=False)
    assert server._trusted_proxies() == frozenset()
    monkeypatch.setenv("MCP_TRUSTED_PROXIES", "10.0.0.1, 10.0.0.2 ,")
    assert server._trusted_proxies() == frozenset({"10.0.0.1", "10.0.0.2"})


def test_env_flag_parsing(monkeypatch):
    monkeypatch.delenv("MCP_TRUST_X_FORWARDED_FOR", raising=False)
    assert server._env_flag("MCP_TRUST_X_FORWARDED_FOR", True) is True
    assert server._env_flag("MCP_TRUST_X_FORWARDED_FOR", False) is False
    for truthy in ("1", "true", "YES", "On"):
        monkeypatch.setenv("MCP_TRUST_X_FORWARDED_FOR", truthy)
        assert server._env_flag("MCP_TRUST_X_FORWARDED_FOR", False) is True
    for falsy in ("0", "false", "no", "off"):
        monkeypatch.setenv("MCP_TRUST_X_FORWARDED_FOR", falsy)
        assert server._env_flag("MCP_TRUST_X_FORWARDED_FOR", True) is False


def test_uvicorn_limits_defaults(monkeypatch):
    monkeypatch.delenv("MCP_LIMIT_CONCURRENCY", raising=False)
    monkeypatch.delenv("MCP_TIMEOUT_KEEP_ALIVE", raising=False)
    assert server._uvicorn_limits() == {"limit_concurrency": 40, "timeout_keep_alive": 15}


def test_uvicorn_limits_env_overrides(monkeypatch):
    monkeypatch.setenv("MCP_LIMIT_CONCURRENCY", "100")
    monkeypatch.setenv("MCP_TIMEOUT_KEEP_ALIVE", "5")
    assert server._uvicorn_limits() == {"limit_concurrency": 100, "timeout_keep_alive": 5}


def test_uvicorn_limits_zero_disables_concurrency_cap(monkeypatch):
    monkeypatch.setenv("MCP_LIMIT_CONCURRENCY", "0")
    assert server._uvicorn_limits()["limit_concurrency"] is None


def test_log_level_env(monkeypatch):
    monkeypatch.delenv("MCP_LOG_LEVEL", raising=False)
    assert server._log_level() == logging.WARNING
    monkeypatch.setenv("MCP_LOG_LEVEL", "debug")
    assert server._log_level() == logging.DEBUG
    monkeypatch.setenv("MCP_LOG_LEVEL", "bogus")
    assert server._log_level() == logging.WARNING


async def test_lifespan_shutdown_closes_shared_client(monkeypatch):
    closed = []

    async def fake_aclose():
        closed.append(True)

    monkeypatch.setattr(server.http_client, "aclose", fake_aclose)

    async def app(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    wrapped = server._ClientCleanup(app)
    messages = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    await wrapped({"type": "lifespan"}, receive, send)
    assert closed == [True], "shared httpx client must be closed on shutdown"
    assert {"type": "lifespan.shutdown.complete"} in sent


def _build_stack(monkeypatch, *, log_settings=False, **env):
    """Build the production middleware stack with a clean, overridable env."""
    for name in (
        "RATE_LIMIT_RPM",
        "MCP_MAX_BODY_BYTES",
        "MCP_CORS_ORIGINS",
        "MCP_TRUST_X_FORWARDED_FOR",
        "MCP_TRUSTED_PROXIES",
        "APPLICATIONINSIGHTS_CONNECTION_STRING",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return server.build_http_app(log_settings=log_settings)


def _stack_client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def test_stack_health_is_rate_limit_exempt(monkeypatch):
    app = _build_stack(monkeypatch, RATE_LIMIT_RPM="2")
    async with _stack_client(app) as client:
        responses = [await client.get("/health") for _ in range(5)]
    assert [r.status_code for r in responses] == [200] * 5
    assert responses[0].json()["version"] == __version__


async def test_stack_rate_limit_429_carries_cors_headers(monkeypatch):
    # NB: uses a 404 path, not /mcp — ASGITransport runs no lifespan, so the
    # streamable-HTTP session manager is uninitialized; the rate limiter counts
    # every non-/health path either way.
    app = _build_stack(monkeypatch, RATE_LIMIT_RPM="2")
    async with _stack_client(app) as client:
        headers = {"Origin": "https://client.example"}
        statuses = [
            (await client.get("/missing", headers=headers)).status_code for _ in range(2)
        ]
        throttled = await client.get("/missing", headers=headers)
    assert statuses == [404, 404]
    assert throttled.status_code == 429
    assert "retry-after" in throttled.headers
    # CORS is outermost, so even throttled responses are readable cross-origin.
    assert throttled.headers.get("access-control-allow-origin") == "*"


async def test_stack_body_limit_413(monkeypatch):
    app = _build_stack(monkeypatch, MCP_MAX_BODY_BYTES="100")
    async with _stack_client(app) as client:
        response = await client.post("/missing", content=b"x" * 200)
    assert response.status_code == 413


async def test_stack_cors_preflight(monkeypatch):
    app = _build_stack(monkeypatch, MCP_CORS_ORIGINS="https://allowed.example")
    async with _stack_client(app) as client:
        response = await client.options(
            "/mcp",
            headers={
                "Origin": "https://allowed.example",
                "Access-Control-Request-Method": "POST",
            },
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://allowed.example"
    assert "POST" in response.headers["access-control-allow-methods"]


async def test_stack_exposes_mcp_session_id(monkeypatch):
    app = _build_stack(monkeypatch)
    async with _stack_client(app) as client:
        response = await client.get("/health", headers={"Origin": "https://client.example"})
    assert response.status_code == 200
    assert "mcp-session-id" in response.headers.get("access-control-expose-headers", "").lower()


def test_startup_log_summarizes_trusted_proxies(monkeypatch, capsys):
    # The startup log must state how many proxies are pinned without echoing
    # the values — raw entries in logs re-trip CodeQL's sensitive-data check.
    _build_stack(monkeypatch, log_settings=True, MCP_TRUSTED_PROXIES="10.1.2.3,10.4.5.6")
    out = capsys.readouterr().out
    assert "Trusting X-Forwarded-For: via 2 pinned proxy entries (MCP_TRUSTED_PROXIES)" in out
    assert "10.1.2.3" not in out
    assert "10.4.5.6" not in out


async def test_triage_prompt_is_registered():
    async with Client(mcp) as client:
        prompts = await client.list_prompts()
        prompt = next((p for p in prompts if p.name == "monthly_triage"), None)
        assert prompt is not None
        assert prompt.title == "Monthly Patch Tuesday Triage"
        arg_names = {a.name for a in (prompt.arguments or [])}
        assert {"product_profile", "month"} <= arg_names


async def test_triage_prompt_renders_workflow_with_scope():
    async with Client(mcp) as client:
        result = await client.get_prompt(
            "monthly_triage", {"product_profile": "identity-core"}
        )
        text = result.messages[0].content.text
        # Single-tool workflow with the profile threaded into the example calls.
        assert "msrc_search" in text
        assert 'product_profile="identity-core"' in text
        # Covers the required analyst workflow sections.
        for needle in ("Publicly disclosed", "KEV", "exploited", "Endpoint"):
            assert needle in text


async def test_triage_prompt_defaults_to_whole_release():
    async with Client(mcp) as client:
        result = await client.get_prompt("monthly_triage", {})
        text = result.messages[0].content.text
        assert "whole release" in text
        # No dangling profile argument when none is supplied.
        assert "product_profile=" not in text
