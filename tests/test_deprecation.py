"""Deprecation signalling: silent by default, declarative when configured.

The critical property under test is that an unconfigured deployment — every
local stdio/uvx install and the current hosted endpoint — is byte-for-byte
unchanged. The notice is opt-in via environment, and partial or malformed
configuration degrades to silence rather than half-announcing a migration or
raising into a search.
"""

import json

import httpx
import pytest

from patch_tuesday_mcp import deprecation
from patch_tuesday_mcp.middleware.deprecation_headers import DeprecationHeadersMiddleware

SUNSET = "2026-08-11"
REPLACEMENT = "https://patch-tuesday-mcp.example.net/mcp"


@pytest.fixture
def deprecated(monkeypatch):
    """Configure the process as a retiring deployment."""
    monkeypatch.setenv(deprecation.SUNSET_ENV, SUNSET)
    monkeypatch.setenv(deprecation.REPLACEMENT_ENV, REPLACEMENT)
    monkeypatch.delenv(deprecation.SINCE_ENV, raising=False)
    monkeypatch.delenv(deprecation.MESSAGE_ENV, raising=False)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Default every test to an unconfigured (non-deprecated) deployment."""
    for name in (
        deprecation.SUNSET_ENV,
        deprecation.REPLACEMENT_ENV,
        deprecation.SINCE_ENV,
        deprecation.MESSAGE_ENV,
    ):
        monkeypatch.delenv(name, raising=False)


# --- Off by default ---


def test_inactive_without_configuration():
    assert deprecation.is_active() is False
    assert deprecation.notice() is None
    assert deprecation.headers() == []
    assert deprecation.instructions_suffix() == ""
    assert deprecation.tool_description_suffix() == ""


@pytest.mark.parametrize(
    "env",
    [
        {deprecation.SUNSET_ENV: SUNSET},
        {deprecation.REPLACEMENT_ENV: REPLACEMENT},
        {deprecation.SUNSET_ENV: "", deprecation.REPLACEMENT_ENV: REPLACEMENT},
        {deprecation.SUNSET_ENV: SUNSET, deprecation.REPLACEMENT_ENV: "   "},
    ],
)
def test_partial_configuration_stays_silent(monkeypatch, env):
    # A half-set migration must not half-announce itself.
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert deprecation.is_active() is False
    assert deprecation.notice() is None


def test_malformed_sunset_date_degrades_to_silence(monkeypatch):
    monkeypatch.setenv(deprecation.SUNSET_ENV, "August 11th")
    monkeypatch.setenv(deprecation.REPLACEMENT_ENV, REPLACEMENT)
    assert deprecation.notice() is None
    assert deprecation.headers() == []


# --- Shape when active ---


def test_notice_reports_facts(deprecated):
    notice = deprecation.notice()
    assert notice["status"] == "deprecated"
    assert notice["sunset"] == SUNSET
    assert notice["replacement_url"] == REPLACEMENT
    assert SUNSET in notice["message"]
    assert REPLACEMENT in notice["message"]


def test_notice_never_instructs_the_model(deprecated):
    """The notice states facts; it must not direct the agent's behavior.

    Tool output that commands a model is indirect prompt injection, and this
    endpoint serves other people's agents.
    """
    text = " ".join(
        [
            deprecation.notice()["message"],
            deprecation.instructions_suffix(),
            deprecation.tool_description_suffix(),
        ]
    ).lower()
    for phrase in (
        "you must",
        "always tell",
        "at the beginning",
        "at the end of your response",
        "inform the user",
        "prepend",
        "append",
        "respond with",
        "your response",
        "ignore",
    ):
        assert phrase not in text, f"notice reads as an instruction to the model: {phrase!r}"


def test_custom_message_override(monkeypatch, deprecated):
    monkeypatch.setenv(deprecation.MESSAGE_ENV, "Moving house on the 11th.")
    assert deprecation.notice()["message"] == "Moving house on the 11th."


# --- HTTP headers ---


def test_headers_are_rfc_shaped(deprecated):
    headers = dict(deprecation.headers())
    assert headers[b"deprecation"] == b"true"
    assert headers[b"sunset"] == b"Tue, 11 Aug 2026 00:00:00 GMT"
    assert headers[b"link"] == f'<{REPLACEMENT}>; rel="successor-version"'.encode()


def test_since_date_becomes_structured_field_date(monkeypatch, deprecated):
    monkeypatch.setenv(deprecation.SINCE_ENV, "2026-07-26")
    headers = dict(deprecation.headers())
    # RFC 9745: an Item Structured Field Date, i.e. @<unix seconds>
    assert headers[b"deprecation"].startswith(b"@")
    assert int(headers[b"deprecation"][1:]) == 1785024000


def test_malformed_since_falls_back_to_true(monkeypatch, deprecated):
    monkeypatch.setenv(deprecation.SINCE_ENV, "yesterday")
    assert dict(deprecation.headers())[b"deprecation"] == b"true"


# --- Header middleware ---


async def _echo_app(scope, receive, send):
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": b'{"ok":true}'})


async def test_middleware_appends_without_replacing():
    app = DeprecationHeadersMiddleware(_echo_app, headers=[(b"sunset", b"someday")])
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.headers["sunset"] == "someday"


async def test_middleware_is_passthrough_without_headers():
    app = DeprecationHeadersMiddleware(_echo_app, headers=[])
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    assert "sunset" not in response.headers


# --- Integration with the tool response ---


async def test_search_response_has_no_deprecation_key_by_default():
    from patch_tuesday_mcp.tools.search import msrc_search

    result = await msrc_search(month="1999-Jan")
    assert "deprecation" not in result


async def test_search_response_carries_notice_when_configured(deprecated):
    from patch_tuesday_mcp.tools.search import msrc_search

    # An error path, to prove the notice rides along on every response shape.
    result = await msrc_search(month="1999-Jan")
    assert result["error_kind"] == "not_found"
    assert result["deprecation"]["sunset"] == SUNSET
    assert result["deprecation"]["replacement_url"] == REPLACEMENT


async def test_notice_survives_json_serialization(deprecated):
    from patch_tuesday_mcp.tools.search import msrc_search

    result = await msrc_search(month="1999-Jan")
    assert json.loads(json.dumps(result))["deprecation"]["status"] == "deprecated"
