"""Patch Tuesday MCP Server - FastMCP server with stdio/HTTP transport."""

import logging
import os

from fastmcp import FastMCP

# Suppress FastMCP's INFO logs to reduce console noise
logging.getLogger("fastmcp").setLevel(logging.WARNING)

from . import telemetry  # noqa: E402
from .middleware.rate_limit import RateLimitMiddleware  # noqa: E402
from .tools.search import msrc_search  # noqa: E402

# Create the MCP server
mcp = FastMCP(
    "Patch Tuesday MCP",
    instructions=(
        "Query Microsoft security updates (Patch Tuesday) from the official "
        "MSRC Security Update Guide API. Use msrc_search to find, filter, and "
        "retrieve vulnerabilities and their fixes. Look up a specific CVE with "
        "cve='CVE-...' (full detail, works across all months), find what a KB "
        "fixes with kb='5094123', or filter the latest month by product, "
        "severity, exploited=True, or min_cvss. Set include_stats=True with "
        "limit=0 for a month overview (counts by severity, impact, product "
        "family, exploited)."
    ),
)

# Register tools
mcp.tool(msrc_search)


def main():
    """Run the MCP server.

    Uses stdio transport by default (for MCP client auto-start).
    Set MCP_TRANSPORT=http to run as an HTTP server for remote access.

    HTTP mode extras (never active for stdio):
    - Per-IP rate limiting (RATE_LIMIT_RPM, default 60; 0 disables)
    - Optional Application Insights telemetry
      (APPLICATIONINSIGHTS_CONNECTION_STRING)
    """
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "http":
        import uvicorn

        host = os.getenv("MCP_HOST", "0.0.0.0")
        port = int(os.getenv("MCP_PORT", "8000"))
        rpm = int(os.getenv("RATE_LIMIT_RPM", "60"))

        telemetry_enabled = telemetry.setup_telemetry()

        app = mcp.http_app()
        app = RateLimitMiddleware(
            app,
            requests_per_minute=rpm,
            on_request=telemetry.track_request if telemetry_enabled else None,
        )

        print(f"Starting Patch Tuesday MCP server on {host}:{port}")
        print(f"MCP endpoint: http://{host}:{port}/mcp")
        print(f"Rate limit: {rpm} req/min per IP" if rpm > 0 else "Rate limit: disabled")
        print(f"Telemetry: {'enabled' if telemetry_enabled else 'disabled'}")
        uvicorn.run(app, host=host, port=port, log_level="warning")
    else:
        # stdio transport (default for MCP client auto-start)
        mcp.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
