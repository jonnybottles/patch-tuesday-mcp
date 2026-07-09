"""Shared pytest configuration.

Adds a ``live`` marker for end-to-end tests that hit the real MSRC / FIRST EPSS
/ CISA KEV APIs. These are skipped by default (they need network and depend on
live data); enable them with ``--run-live`` or by setting ``PT_RUN_LIVE=1``.
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


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "live: end-to-end test against real external APIs (needs network)"
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-live") or os.getenv("PT_RUN_LIVE"):
        return
    skip_live = pytest.mark.skip(reason="live test; pass --run-live or set PT_RUN_LIVE=1")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)
