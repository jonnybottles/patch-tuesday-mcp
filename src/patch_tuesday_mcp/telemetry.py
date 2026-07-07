"""Optional Application Insights telemetry (HTTP mode only, opt-in).

Telemetry is only active when BOTH conditions hold:
1. The APPLICATIONINSIGHTS_CONNECTION_STRING environment variable is set
   (i.e., an operator deliberately configured their own App Insights resource).
2. The optional `azure-monitor-opentelemetry` extra is installed
   (`pip install patch-tuesday-mcp[telemetry]`).

Local stdio usage never sends telemetry: the server only calls
setup_telemetry() on the HTTP transport path, and without the connection
string every tracking call is a no-op.

Client IPs are never stored raw: they are hashed with a per-day salt, which
allows counting daily unique users without retaining addresses.
"""

import hashlib
import logging
import os
from datetime import date, datetime, timezone

_enabled = False
_logger = logging.getLogger("patch_tuesday_mcp.telemetry")


def setup_telemetry() -> bool:
    """Configure Azure Monitor OpenTelemetry when opted in. Returns enabled state."""
    global _enabled
    connection_string = os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING")
    if not connection_string:
        return False

    try:
        from azure.monitor.opentelemetry import configure_azure_monitor
    except ImportError:
        _logger.warning(
            "APPLICATIONINSIGHTS_CONNECTION_STRING is set but the telemetry extra "
            "is not installed; run: pip install patch-tuesday-mcp[telemetry]"
        )
        return False

    configure_azure_monitor(connection_string=connection_string)
    # Ensure our event logger's records are exported
    _logger.setLevel(logging.INFO)
    _enabled = True
    return True


def is_enabled() -> bool:
    return _enabled


def hash_client_ip(ip: str) -> str:
    """Hash an IP with a per-day salt for privacy-safe daily unique counts."""
    return hashlib.sha256(f"{date.today().isoformat()}:{ip}".encode()).hexdigest()[:16]


def track_event(name: str, properties: dict) -> None:
    """Emit a custom event as a structured log record (no-op unless enabled)."""
    if not _enabled:
        return
    _logger.info(
        "%s",
        name,
        extra={
            "event_name": name,
            **{f"custom_{k}": v for k, v in properties.items()},
        },
    )


def track_request(ip: str, path: str = "/mcp") -> None:
    """Record an allowed HTTP request with a hashed client IP."""
    if not _enabled:
        return
    track_event(
        "http_request",
        {
            "user_hash": hash_client_ip(ip),
            "path": path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


def track_tool_call(tool: str, filters_applied: dict, total_found: int,
                    duration_ms: float) -> None:
    """Record a tool invocation: which filters were used, result size, latency.

    Free-text query values are not recorded — only which parameter names were
    used, plus low-cardinality values (month, severity).
    """
    if not _enabled:
        return
    track_event(
        "tool_call",
        {
            "tool": tool,
            "params_used": ",".join(sorted(filters_applied.keys())),
            "month": filters_applied.get("month", ""),
            "severity": filters_applied.get("severity", ""),
            "total_found": total_found,
            "duration_ms": round(duration_ms, 1),
        },
    )
