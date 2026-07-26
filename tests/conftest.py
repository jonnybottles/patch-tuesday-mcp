"""Shared pytest configuration.

Adds a ``live`` marker for end-to-end tests that hit the real MSRC / FIRST EPSS
/ CISA KEV APIs. These are skipped by default (they need network and depend on
live data); enable them with ``--run-live`` or by setting ``PT_RUN_LIVE=1``.

Adds ``endpoint`` markers for the HTTP endpoint suite (tests/test_endpoint.py),
which runs against an already-running server — a local container or the hosted
ACA endpoint. Skipped by default; enable with ``--endpoint-url=<base URL>``.
The rate-limit burst test additionally requires ``--endpoint-burst`` and must
only be pointed at local containers (the hosted per-IP bucket is shared with
real users).
"""

import os

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="Run live end-to-end tests against real MSRC/EPSS/KEV APIs.",
    )
    parser.addoption(
        "--endpoint-url",
        action="store",
        default=None,
        help=(
            "Base URL of a running server for the endpoint suite, "
            "e.g. http://localhost:8000 or the hosted ACA URL."
        ),
    )
    parser.addoption(
        "--endpoint-burst",
        action="store_true",
        default=False,
        help="Also run the rate-limit burst test (local containers only).",
    )
    parser.addoption(
        "--aca-scale",
        action="store_true",
        default=False,
        help=(
            "Run the Azure Container Apps scale suite (tests/test_scale.py). "
            "Requires an authenticated `az` CLI with reader access to the app."
        ),
    )
    parser.addoption(
        "--aca-scale-load",
        action="store_true",
        default=False,
        help=(
            "Also run the load-driven scale-out test. This temporarily raises "
            "RATE_LIMIT_RPM on the live app (restored afterwards) and rolls "
            "revisions -- operator-run only, never CI."
        ),
    )
    parser.addoption(
        "--aca-app",
        action="store",
        default="patch-tuesday-mcp",
        help="Container App name for the scale suite.",
    )
    parser.addoption(
        "--aca-rg",
        action="store",
        default="patch-tuesday-rg",
        help="Resource group of the Container App for the scale suite.",
    )
    parser.addoption(
        "--aca-subscription",
        action="store",
        default=None,
        help="Subscription id for the scale suite (defaults to the az CLI's active one).",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "live: end-to-end test against real external APIs (needs network)"
    )
    config.addinivalue_line(
        "markers", "endpoint: HTTP endpoint test against a running server (needs --endpoint-url)"
    )
    config.addinivalue_line(
        "markers",
        "endpoint_upstream: endpoint test that triggers real MSRC/EPSS/KEV fetches "
        "through the server",
    )
    config.addinivalue_line(
        "markers",
        "endpoint_burst: rate-limit burst test (needs --endpoint-burst; local containers only)",
    )
    config.addinivalue_line(
        "markers",
        "scale: Azure Container Apps scale/capacity assertion (needs --aca-scale and the az CLI)",
    )
    config.addinivalue_line(
        "markers",
        "scale_load: load-driven scale-out test (needs --aca-scale-load; mutates the live app)",
    )


def pytest_collection_modifyitems(config, items):
    run_live = config.getoption("--run-live") or os.getenv("PT_RUN_LIVE")
    endpoint_url = config.getoption("--endpoint-url")
    run_burst = config.getoption("--endpoint-burst")
    run_scale = config.getoption("--aca-scale")
    run_scale_load = config.getoption("--aca-scale-load")

    skip_live = pytest.mark.skip(reason="live test; pass --run-live or set PT_RUN_LIVE=1")
    skip_endpoint = pytest.mark.skip(
        reason="endpoint test; pass --endpoint-url=<base URL of a running server>"
    )
    skip_burst = pytest.mark.skip(
        reason="burst test; pass --endpoint-burst (local containers only)"
    )
    skip_scale = pytest.mark.skip(reason="scale test; pass --aca-scale (needs the az CLI)")
    skip_scale_load = pytest.mark.skip(
        reason="scale load test; pass --aca-scale-load (mutates the live app)"
    )

    for item in items:
        if not run_live and "live" in item.keywords:
            item.add_marker(skip_live)
        if not endpoint_url and "endpoint" in item.keywords:
            item.add_marker(skip_endpoint)
        if not run_burst and "endpoint_burst" in item.keywords:
            item.add_marker(skip_burst)
        if not run_scale and "scale" in item.keywords:
            item.add_marker(skip_scale)
        if not run_scale_load and "scale_load" in item.keywords:
            item.add_marker(skip_scale_load)


@pytest.fixture(scope="session")
def endpoint_url(request):
    """Base URL of the server under test (from ``--endpoint-url``)."""
    url = request.config.getoption("--endpoint-url")
    assert url, "endpoint tests require --endpoint-url"
    return url.rstrip("/")


@pytest.fixture(scope="session")
def aca_target(request):
    """Container App coordinates for the scale suite (from ``--aca-*``)."""
    assert request.config.getoption("--aca-scale"), "scale tests require --aca-scale"
    return {
        "app": request.config.getoption("--aca-app"),
        "resource_group": request.config.getoption("--aca-rg"),
        "subscription": request.config.getoption("--aca-subscription"),
    }
