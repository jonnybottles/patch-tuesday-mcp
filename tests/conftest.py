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


def pytest_collection_modifyitems(config, items):
    run_live = config.getoption("--run-live") or os.getenv("PT_RUN_LIVE")
    endpoint_url = config.getoption("--endpoint-url")
    run_burst = config.getoption("--endpoint-burst")

    skip_live = pytest.mark.skip(reason="live test; pass --run-live or set PT_RUN_LIVE=1")
    skip_endpoint = pytest.mark.skip(
        reason="endpoint test; pass --endpoint-url=<base URL of a running server>"
    )
    skip_burst = pytest.mark.skip(
        reason="burst test; pass --endpoint-burst (local containers only)"
    )

    for item in items:
        if not run_live and "live" in item.keywords:
            item.add_marker(skip_live)
        if not endpoint_url and "endpoint" in item.keywords:
            item.add_marker(skip_endpoint)
        if not run_burst and "endpoint_burst" in item.keywords:
            item.add_marker(skip_burst)


@pytest.fixture(scope="session")
def endpoint_url(request):
    """Base URL of the server under test (from ``--endpoint-url``)."""
    url = request.config.getoption("--endpoint-url")
    assert url, "endpoint tests require --endpoint-url"
    return url.rstrip("/")
