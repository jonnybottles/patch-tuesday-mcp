"""Patch Tuesday MCP Server - FastMCP server with stdio/HTTP transport."""

import logging
import os

from fastmcp import FastMCP

# Suppress FastMCP's INFO logs to reduce console noise
logging.getLogger("fastmcp").setLevel(logging.WARNING)

from . import __version__, telemetry  # noqa: E402
from .middleware.body_limit import DEFAULT_MAX_BODY_BYTES, BodyLimitMiddleware  # noqa: E402
from .middleware.rate_limit import RateLimitMiddleware  # noqa: E402
from .tools.search import msrc_search  # noqa: E402


def _env_flag(name: str, default: bool) -> bool:
    """Parse a boolean environment variable (accepts 1/true/yes/on)."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _cors_origins() -> list[str]:
    """Resolve the CORS allowlist from MCP_CORS_ORIGINS.

    Comma-separated list of allowed origins. When unset, defaults to ``["*"]``
    (permissive) to preserve current local-dev behavior; public deployments
    should set an explicit allowlist (see README deployment docs).
    """
    raw = os.getenv("MCP_CORS_ORIGINS", "").strip()
    if not raw:
        return ["*"]
    return [o.strip() for o in raw.split(",") if o.strip()]


def _trusted_proxies() -> frozenset[str]:
    """Resolve the trusted-proxy allowlist from MCP_TRUSTED_PROXIES."""
    raw = os.getenv("MCP_TRUSTED_PROXIES", "").strip()
    return frozenset(p.strip() for p in raw.split(",") if p.strip())

# Create the MCP server
mcp = FastMCP(
    "Patch Tuesday MCP",
    instructions=(
        "Query Microsoft security updates (Patch Tuesday) from the official "
        "MSRC Security Update Guide API. Use msrc_search to find, filter, and "
        "retrieve vulnerabilities and their fixes. Look up a specific CVE with "
        "cve='CVE-...' (full detail, works across all months), find what a KB "
        "fixes with kb='5094123', or filter the latest month by product, "
        "severity, exploited=True, or min_cvss. Results are enriched with "
        "EPSS exploitation probabilities and CISA KEV catalog status: filter "
        "with kev=True (confirmed exploited, federal due dates) or "
        "min_epss=0.5 (EPSS >= 50%). Add include_chain=True to a kb= lookup "
        "to walk Microsoft-stated supersedence links (which KBs it replaces). "
        "Set include_stats=True with limit=0 for a month overview (counts by "
        "severity, impact, product family, exploited, KEV). When no month is "
        "given, results default to the most recent release whose Patch "
        "Tuesday has occurred; the upcoming month's pre-release document "
        "(early/out-of-band entries only) is available via month=."
    ),
)

# Register tools. Annotations let clients auto-approve: the tool only reads
# public data from external APIs and is safe to retry.
mcp.tool(
    msrc_search,
    title="Search Microsoft Security Updates",
    annotations={
        "readOnlyHint": True,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)


@mcp.custom_route("/health", methods=["GET"])
async def health(request):
    """Liveness endpoint for container probes and uptime checks."""
    from starlette.responses import JSONResponse

    return JSONResponse({"status": "ok", "server": "patch-tuesday-mcp", "version": __version__})


def main():
    """Run the MCP server.

    Uses stdio transport by default (for MCP client auto-start).
    Set MCP_TRANSPORT=http to run as an HTTP server for remote access.

    HTTP mode extras (never active for stdio):
    - Stateless streamable HTTP (safe behind multi-replica ingress)
    - Per-IP rate limiting (RATE_LIMIT_RPM, default 60; 0 disables)
    - Request body size cap (MCP_MAX_BODY_BYTES, default 256 KiB; 0 disables)
    - Configurable CORS allowlist (MCP_CORS_ORIGINS; default "*" for local dev)
    - Trusted-proxy client-IP handling (MCP_TRUST_X_FORWARDED_FOR,
      MCP_TRUSTED_PROXIES) so rate limiting keys on the real client behind
      a reverse proxy without trusting spoofable headers when directly exposed
    - Optional Application Insights telemetry
      (APPLICATIONINSIGHTS_CONNECTION_STRING)
    """
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "http":
        import uvicorn
        from starlette.middleware.cors import CORSMiddleware

        host = os.getenv("MCP_HOST", "0.0.0.0")
        port = int(os.getenv("MCP_PORT", "8000"))
        rpm = int(os.getenv("RATE_LIMIT_RPM", "60"))
        max_body = int(os.getenv("MCP_MAX_BODY_BYTES", str(DEFAULT_MAX_BODY_BYTES)))
        cors_origins = _cors_origins()
        trust_xff = _env_flag("MCP_TRUST_X_FORWARDED_FOR", True)
        trusted_proxies = _trusted_proxies()

        telemetry_enabled = telemetry.setup_telemetry()

        # Stateless: every request is self-contained, so replicas behind
        # ingress without session affinity can serve any request
        app = mcp.http_app(stateless_http=True)
        app = BodyLimitMiddleware(app, max_bytes=max_body)
        app = RateLimitMiddleware(
            app,
            requests_per_minute=rpm,
            on_request=telemetry.track_request if telemetry_enabled else None,
            trust_x_forwarded_for=trust_xff,
            trusted_proxies=trusted_proxies,
        )
        # CORS outermost so preflights and 429/413 responses carry CORS headers
        app = CORSMiddleware(
            app,
            allow_origins=cors_origins,
            allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
            allow_headers=["*"],
            expose_headers=["Mcp-Session-Id"],
            max_age=86400,
        )

        print(f"Starting Patch Tuesday MCP server on {host}:{port}")
        print(f"MCP endpoint: http://{host}:{port}/mcp")
        print(f"Rate limit: {rpm} req/min per IP" if rpm > 0 else "Rate limit: disabled")
        cors_display = (
            "* (all — restrict for public deploy)"
            if cors_origins == ["*"]
            else ", ".join(cors_origins)
        )
        print(f"CORS origins: {cors_display}")
        if trust_xff:
            proxy_display = (
                f"via proxies {', '.join(sorted(trusted_proxies))}"
                if trusted_proxies
                else "rightmost hop"
            )
            print(f"Trusting X-Forwarded-For: {proxy_display}")
        else:
            print("Trusting X-Forwarded-For: no (direct peer IP only)")
        print(f"Telemetry: {'enabled' if telemetry_enabled else 'disabled'}")
        uvicorn.run(app, host=host, port=port, log_level="warning")
    else:
        # stdio transport (default for MCP client auto-start)
        mcp.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
