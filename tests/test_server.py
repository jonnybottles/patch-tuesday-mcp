"""Tests for server wiring: tool registration metadata and the health route."""

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
