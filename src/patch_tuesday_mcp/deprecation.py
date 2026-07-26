"""Env-gated deprecation signalling for a retiring deployment.

Everything here is **declarative**: each channel reports *facts* about the
deployment it runs on — status, sunset date, replacement URL. Nothing in this
module instructs a model to say or do anything. Tool output that issues
instructions to a client's agent ("tell the user X", "prepend Y to your
answer") is indirect prompt injection regardless of how benign the payload is,
and this endpoint is public: the agents reading these responses belong to other
people. Facts let a client decide what to surface; commands take that choice
away from them.

Inactive unless both ``MCP_DEPRECATION_SUNSET`` and
``MCP_DEPRECATION_REPLACEMENT_URL`` are set, so PyPI/stdio users and any
non-retiring deployment see no behavior change whatsoever — the default
response shape, headers, and instructions are all untouched.

Environment variables:
    MCP_DEPRECATION_SUNSET           ISO date (YYYY-MM-DD) the endpoint stops serving.
    MCP_DEPRECATION_REPLACEMENT_URL  URL of the endpoint clients should move to.
    MCP_DEPRECATION_SINCE            Optional ISO date the deprecation was announced.
    MCP_DEPRECATION_MESSAGE          Optional override for the human-readable message.

Malformed configuration degrades to "no notice" rather than raising — a bad
env var must never break a search (see the fail-open constraint in CLAUDE.md).
"""

import logging
import os
from datetime import date, datetime, timezone
from email.utils import format_datetime

logger = logging.getLogger(__name__)

SUNSET_ENV = "MCP_DEPRECATION_SUNSET"
REPLACEMENT_ENV = "MCP_DEPRECATION_REPLACEMENT_URL"
SINCE_ENV = "MCP_DEPRECATION_SINCE"
MESSAGE_ENV = "MCP_DEPRECATION_MESSAGE"


def _parse_iso_date(raw: str, env_name: str) -> date | None:
    """Parse an ISO ``YYYY-MM-DD`` value, returning None if unusable."""
    try:
        return date.fromisoformat(raw.strip())
    except ValueError:
        logger.warning("Ignoring %s: %r is not an ISO YYYY-MM-DD date", env_name, raw)
        return None


def _config() -> tuple[date, str] | None:
    """Resolve (sunset_date, replacement_url), or None when not deprecated."""
    sunset_raw = os.getenv(SUNSET_ENV, "").strip()
    replacement = os.getenv(REPLACEMENT_ENV, "").strip()
    if not sunset_raw or not replacement:
        return None

    sunset = _parse_iso_date(sunset_raw, SUNSET_ENV)
    if sunset is None:
        return None
    return sunset, replacement


def is_active() -> bool:
    """True when this deployment is configured as deprecated."""
    return _config() is not None


def notice() -> dict | None:
    """The deprecation block attached to every ``msrc_search`` response.

    Returns None when the deployment is not deprecated, in which case callers
    must leave the response untouched.
    """
    config = _config()
    if config is None:
        return None
    sunset, replacement = config

    message = os.getenv(MESSAGE_ENV, "").strip() or (
        f"This patch-tuesday-mcp endpoint is deprecated and stops serving on "
        f"{sunset.isoformat()}. The current endpoint is {replacement}, which runs with "
        f"more CPU and memory and autoscales under load. Update your MCP client "
        f"configuration before that date to avoid an interruption."
    )
    return {
        "status": "deprecated",
        "sunset": sunset.isoformat(),
        "replacement_url": replacement,
        "message": message,
    }


def headers() -> list[tuple[bytes, bytes]]:
    """RFC 9745 / RFC 8594 / RFC 5829 response headers for a deprecated endpoint.

    ``Deprecation`` carries the announcement date as a structured-field Date
    (``@<unix-seconds>``) when ``MCP_DEPRECATION_SINCE`` is set, and falls back
    to the widely-understood ``true`` form otherwise. ``Sunset`` is the
    HTTP-date the endpoint stops serving. ``Link`` points at the successor.
    """
    config = _config()
    if config is None:
        return []
    sunset, replacement = config

    since_raw = os.getenv(SINCE_ENV, "").strip()
    deprecation_value = b"true"
    if since_raw:
        since = _parse_iso_date(since_raw, SINCE_ENV)
        if since is not None:
            announced = datetime(since.year, since.month, since.day, tzinfo=timezone.utc)
            deprecation_value = f"@{int(announced.timestamp())}".encode()

    sunset_http = format_datetime(
        datetime(sunset.year, sunset.month, sunset.day, tzinfo=timezone.utc), usegmt=True
    )
    return [
        (b"deprecation", deprecation_value),
        (b"sunset", sunset_http.encode()),
        (b"link", f'<{replacement}>; rel="successor-version"'.encode()),
    ]


def instructions_suffix() -> str:
    """Server-instructions text describing the deprecation, or "" when inactive.

    FastMCP surfaces server instructions to the model once at connection time.
    This states the situation; it does not tell the model how to format its
    replies.
    """
    current = notice()
    if current is None:
        return ""
    return (
        f"\n\nDEPLOYMENT NOTICE: {current['message']} This notice describes the server "
        f"itself, not the security data it returns."
    )


def tool_description_suffix() -> str:
    """Tool-description text describing the deprecation, or "" when inactive."""
    current = notice()
    if current is None:
        return ""
    return (
        f"Deployment status: deprecated. This endpoint stops serving on "
        f"{current['sunset']}; the current endpoint is {current['replacement_url']}."
    )
