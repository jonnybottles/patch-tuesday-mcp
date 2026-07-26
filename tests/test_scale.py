"""Azure Container Apps capacity and autoscaling assertions.

The endpoint suite (test_endpoint.py) proves the deployment serves the right
*answers*; this suite proves it has the *capacity* to keep doing so under load
and never parks at zero replicas. It reads live deployment state through the
``az`` CLI rather than an SDK, so it adds no dependency to the package.

Marker map (see conftest.py):
- ``scale``      -- every test here; needs ``--aca-scale`` and an authenticated az CLI
- ``scale_load`` -- additionally drives real load and mutates the live app's
  RATE_LIMIT_RPM (restored afterwards). Operator-run only, never CI.

Run the config assertions::

    pytest -m scale --aca-scale --aca-subscription <sub-id>

Run everything including the load-driven scale-out proof::

    pytest -m scale --aca-scale --aca-scale-load --aca-subscription <sub-id> \\
        --endpoint-url=https://<app>.<region>.azurecontainerapps.io
"""

import asyncio
import json
import shutil
import statistics
import subprocess
import time

import pytest
from fastmcp import Client

pytestmark = pytest.mark.scale

# Capacity floors the deployment must satisfy. These encode the sizing
# decision, so drifting back to the old 0.25 vCPU / min-1 shape fails loudly.
MIN_REPLICA_FLOOR = 2
MAX_REPLICA_FLOOR = 6
MIN_CPU = 0.5
MIN_MEMORY_GIB = 1.0

# The container caps concurrent connections at MCP_LIMIT_CONCURRENCY and
# returns 503 past it. The autoscale trigger has to fire well before that, or
# ACA adds replicas only after the pod has already started refusing work.
# The deployment's real value is read from the app; this is the fallback for
# an app that leaves it unset. See server.py::_uvicorn_limits.
DEFAULT_UVICORN_CONCURRENCY_CAP = 40

# The trigger must leave room for the autoscaler's reaction time: KEDA polls
# on an interval and a new pod still has to start, so a replica keeps taking
# traffic well past the trigger point before help arrives.
MIN_TRIGGER_HEADROOM_RATIO = 2.0

# --- Load test tuning (scale_load only) ---
LOAD_SESSIONS = 60
LOAD_CALLS_PER_SESSION = 8
LOAD_RAISED_RPM = "6000"
LOAD_CALL_TIMEOUT = 120.0
LOAD_P95_CEILING_S = 45.0
# Sessions join in waves rather than all at once: an instantaneous herd
# outruns any autoscaler (poll interval + pod start), which measures cold
# burst capacity, not whether scaling works. Real traffic ramps.
LOAD_WAVE_SIZE = 10
LOAD_WAVE_INTERVAL_S = 25
SCALE_OUT_POLL_INTERVAL_S = 15
# Burst test: a hard slam is expected to degrade. What must hold is that it
# degrades in a bounded way and recovers.
BURST_SESSIONS = 60
BURST_MAX_FAILURE_RATIO = 0.5


def _az_binary() -> str:
    """Resolve the az CLI, skipping the suite when it isn't usable.

    ``shutil.which`` returns the full path including the extension, which
    matters on Windows: az ships as ``az.cmd`` and CreateProcess will not
    apply PATHEXT to a bare ``"az"`` argv[0].
    """
    binary = shutil.which("az")
    if binary is None:
        pytest.skip("az CLI not on PATH")
    return binary


def _az(*args: str, subscription: str | None = None) -> dict | list:
    """Run an az CLI command returning JSON, skipping the suite if unusable."""
    cmd = [_az_binary(), *args, "--output", "json"]
    if subscription:
        cmd += ["--subscription", subscription]
    completed = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        if "az login" in stderr or "AADSTS" in stderr:
            pytest.skip(f"az CLI not authenticated: {stderr.splitlines()[0] if stderr else ''}")
        pytest.fail(f"az {' '.join(args)} failed: {stderr}")
    return json.loads(completed.stdout or "null")


def _parse_memory_gib(raw: str) -> float:
    """Parse an ACA memory string ('0.5Gi', '1Gi', '512Mi') into GiB."""
    value = str(raw).strip()
    if value.endswith("Gi"):
        return float(value[:-2])
    if value.endswith("Mi"):
        return float(value[:-2]) / 1024
    return float(value)


@pytest.fixture(scope="session")
def app_state(aca_target) -> dict:
    """Live Container App definition, fetched once per session."""
    return _az(
        "containerapp",
        "show",
        "--name",
        aca_target["app"],
        "--resource-group",
        aca_target["resource_group"],
        subscription=aca_target["subscription"],
    )


@pytest.fixture(scope="session")
def scale_config(app_state) -> dict:
    return app_state["properties"]["template"]["scale"]


def _replicas(aca_target, revision: str) -> list[dict]:
    return _az(
        "containerapp",
        "replica",
        "list",
        "--name",
        aca_target["app"],
        "--resource-group",
        aca_target["resource_group"],
        "--revision",
        revision,
        subscription=aca_target["subscription"],
    )


def _latest_revision(aca_target) -> str:
    state = _az(
        "containerapp",
        "show",
        "--name",
        aca_target["app"],
        "--resource-group",
        aca_target["resource_group"],
        subscription=aca_target["subscription"],
    )
    return state["properties"]["latestRevisionName"]


# --- The no-scale-to-zero contract ---


def test_never_scales_to_zero(scale_config):
    """A cold start on a public endpoint is a user-visible failure mode."""
    assert scale_config["minReplicas"] is not None, "minReplicas unset -- ACA defaults to zero"
    assert scale_config["minReplicas"] >= 1, "endpoint would scale to zero and cold-start"
    assert scale_config["minReplicas"] >= MIN_REPLICA_FLOOR, (
        f"minReplicas {scale_config['minReplicas']} is below the HA floor {MIN_REPLICA_FLOOR}; "
        "a single replica means no redundancy during node drains or revision rolls"
    )


def test_has_headroom_to_scale_out(scale_config):
    assert scale_config["maxReplicas"] >= MAX_REPLICA_FLOOR
    assert scale_config["maxReplicas"] > scale_config["minReplicas"], (
        "maxReplicas equals minReplicas -- the app cannot scale out at all"
    )


# --- Provisioned capacity ---


def test_container_resources_meet_floor(app_state):
    resources = app_state["properties"]["template"]["containers"][0]["resources"]
    assert float(resources["cpu"]) >= MIN_CPU
    assert _parse_memory_gib(resources["memory"]) >= MIN_MEMORY_GIB


def test_http_scale_rule_fires_before_the_container_saturates(app_state, scale_config):
    """The autoscale trigger must sit well below the per-replica connection cap.

    With concurrentRequests at or near MCP_LIMIT_CONCURRENCY, uvicorn starts
    returning 503 before ACA can react -- the app refuses traffic it had the
    headroom to serve. The gap has to cover the autoscaler's reaction time
    (KEDA poll interval plus pod startup), during which the existing replicas
    keep absorbing everything.
    """
    rules = scale_config.get("rules") or []
    http_rules = [r for r in rules if r.get("http")]
    assert http_rules, "no HTTP scale rule: ACA cannot react to request volume"

    concurrency = http_rules[0]["http"]["metadata"].get("concurrentRequests")
    assert concurrency, "HTTP scale rule has no concurrentRequests value"
    concurrency = int(concurrency)
    assert concurrency > 0

    configured_cap = _env_value(app_state, "MCP_LIMIT_CONCURRENCY")
    cap = int(configured_cap) if configured_cap else DEFAULT_UVICORN_CONCURRENCY_CAP
    assert concurrency < cap, (
        f"scale trigger ({concurrency}) is at or above the container's connection cap "
        f"({cap}): replicas would 503 before scaling out"
    )
    assert cap / concurrency >= MIN_TRIGGER_HEADROOM_RATIO, (
        f"scale trigger ({concurrency}) leaves only {cap / concurrency:.1f}x headroom below "
        f"the connection cap ({cap}); needs >= {MIN_TRIGGER_HEADROOM_RATIO}x to absorb "
        "the autoscaler's reaction time"
    )


# --- Deployment health ---


def test_app_is_provisioned_and_ingress_is_public(app_state):
    assert app_state["properties"]["provisioningState"] == "Succeeded"
    ingress = app_state["properties"]["configuration"]["ingress"]
    assert ingress["external"] is True
    assert ingress["targetPort"] == 8000
    assert ingress["allowInsecure"] is False


def test_latest_revision_is_healthy_and_taking_all_traffic(aca_target, app_state):
    latest = app_state["properties"]["latestRevisionName"]
    revisions = _az(
        "containerapp",
        "revision",
        "list",
        "--name",
        aca_target["app"],
        "--resource-group",
        aca_target["resource_group"],
        subscription=aca_target["subscription"],
    )
    current = next((r for r in revisions if r["name"] == latest), None)
    assert current is not None, f"latest revision {latest} missing from revision list"
    assert current["properties"]["active"] is True
    assert current["properties"]["healthState"] == "Healthy"
    assert current["properties"]["runningState"] == "Running"
    assert current["properties"]["trafficWeight"] == 100


def test_running_replica_census_meets_the_minimum(aca_target, app_state, scale_config):
    """Configuration promising two replicas means nothing if one is dead."""
    latest = app_state["properties"]["latestRevisionName"]
    replicas = _replicas(aca_target, latest)
    running = [r for r in replicas if r["properties"]["runningState"] == "Running"]
    assert len(running) >= scale_config["minReplicas"], (
        f"only {len(running)} running replica(s) for {latest}, "
        f"expected >= {scale_config['minReplicas']}: "
        f"{[(r['name'], r['properties']['runningState']) for r in replicas]}"
    )


def test_endpoint_url_matches_the_app_under_test(request, app_state):
    """Guard against asserting capacity on a different app than you're testing."""
    endpoint = request.config.getoption("--endpoint-url")
    if not endpoint:
        pytest.skip("no --endpoint-url given; nothing to cross-check")
    fqdn = app_state["properties"]["configuration"]["ingress"]["fqdn"]
    assert fqdn in endpoint, (
        f"--endpoint-url ({endpoint}) is not the app named by --aca-app ({fqdn}); "
        "the scale assertions would describe a different deployment"
    )


# --- Load-driven scale-out proof ---


def _env_value(app_state: dict, name: str) -> str | None:
    env = app_state["properties"]["template"]["containers"][0].get("env") or []
    return next((e.get("value") for e in env if e.get("name") == name), None)


def _set_rate_limit(aca_target, value: str) -> None:
    _az(
        "containerapp",
        "update",
        "--name",
        aca_target["app"],
        "--resource-group",
        aca_target["resource_group"],
        "--set-env-vars",
        f"RATE_LIMIT_RPM={value}",
        subscription=aca_target["subscription"],
    )


def _wait_for_healthy(aca_target, timeout_s: int = 300) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        revision = _latest_revision(aca_target)
        replicas = _replicas(aca_target, revision)
        running = [r for r in replicas if r["properties"]["runningState"] == "Running"]
        if running:
            return revision
        time.sleep(10)
    pytest.fail(f"no running replicas within {timeout_s}s")


@pytest.fixture
def raised_rate_limit(aca_target, app_state):
    """Lift the per-IP rate limit for the load window, then put it back.

    A single load generator shares one client IP, so the 60 req/min bucket
    would throttle long before ACA saw enough concurrency to react. Restored
    in a finalizer so an aborted run cannot leave the endpoint wide open.
    """
    original = _env_value(app_state, "RATE_LIMIT_RPM") or "60"
    _set_rate_limit(aca_target, LOAD_RAISED_RPM)
    revision = _wait_for_healthy(aca_target)
    try:
        yield revision
    finally:
        _set_rate_limit(aca_target, original)
        _wait_for_healthy(aca_target)


async def _load_session(url: str, results: list, errors: list, start_delay: float = 0.0) -> None:
    """One full MCP session: handshake plus repeated tool calls."""
    if start_delay:
        await asyncio.sleep(start_delay)
    try:
        async with Client(f"{url}/mcp", timeout=LOAD_CALL_TIMEOUT) as client:
            for _ in range(LOAD_CALLS_PER_SESSION):
                started = time.monotonic()
                # months_back keeps the server doing real aggregation work so
                # requests stay in flight long enough to build concurrency,
                # while the month cache keeps upstream load low.
                await client.call_tool(
                    "msrc_search",
                    {"months_back": 2, "include_stats": True, "limit": 0},
                )
                results.append(time.monotonic() - started)
    except Exception as exc:  # noqa: BLE001 - recorded, asserted on below
        errors.append(f"{type(exc).__name__}: {exc}")


async def _watch_replicas(aca_target, revision: str, peak: dict, stop: asyncio.Event) -> None:
    """Sample the running replica count until told to stop."""
    while not stop.is_set():
        replicas = await asyncio.to_thread(_replicas, aca_target, revision)
        running = [r for r in replicas if r["properties"]["runningState"] == "Running"]
        peak["count"] = max(peak["count"], len(running))
        try:
            await asyncio.wait_for(stop.wait(), timeout=SCALE_OUT_POLL_INTERVAL_S)
        except TimeoutError:
            continue


@pytest.mark.scale_load
async def test_scales_out_under_concurrent_mcp_sessions(
    aca_target, endpoint_url, scale_config, raised_rate_limit
):
    """Ramping concurrent MCP sessions must drive ACA past its minimum replicas.

    Sessions join in waves so the autoscaler gets the reaction window real
    traffic would give it. Under that ramp the deployment must both add
    replicas and serve every request -- no dropped sessions.
    """
    revision = raised_rate_limit
    min_replicas = scale_config["minReplicas"]
    latencies: list[float] = []
    errors: list[str] = []
    peak = {"count": 0}
    stop = asyncio.Event()

    poller = asyncio.create_task(_watch_replicas(aca_target, revision, peak, stop))
    try:
        await asyncio.gather(
            *(
                _load_session(
                    endpoint_url,
                    latencies,
                    errors,
                    start_delay=(index // LOAD_WAVE_SIZE) * LOAD_WAVE_INTERVAL_S,
                )
                for index in range(LOAD_SESSIONS)
            )
        )
    finally:
        stop.set()
        await poller

    assert not errors, (
        f"{len(errors)} of {LOAD_SESSIONS} ramped sessions failed "
        f"(peak replicas {peak['count']}): {errors[:3]}"
    )
    assert latencies, "no successful tool calls recorded"

    p95 = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)
    assert p95 < LOAD_P95_CEILING_S, (
        f"p95 tool-call latency {p95:.1f}s exceeded {LOAD_P95_CEILING_S}s under "
        f"{LOAD_SESSIONS} ramped sessions (peak replicas {peak['count']})"
    )
    assert peak["count"] > min_replicas, (
        f"replica count never rose above the {min_replicas}-replica minimum "
        f"(peak {peak['count']}) under {LOAD_SESSIONS} ramped sessions -- "
        "the HTTP scale rule is not reacting to load"
    )


@pytest.mark.scale_load
async def test_survives_and_recovers_from_an_instant_burst(
    aca_target, endpoint_url, raised_rate_limit
):
    """A thundering herd may shed load, but must degrade bounded and recover.

    No autoscaler beats an instantaneous slam: KEDA's poll interval plus pod
    startup is ~a minute, during which existing replicas absorb everything and
    shed the overflow as 503s. This pins the two properties that actually
    matter -- the shedding is bounded, and the endpoint is healthy afterwards.
    """
    latencies: list[float] = []
    errors: list[str] = []

    await asyncio.gather(
        *(_load_session(endpoint_url, latencies, errors) for _ in range(BURST_SESSIONS))
    )

    failure_ratio = len(errors) / BURST_SESSIONS
    assert failure_ratio <= BURST_MAX_FAILURE_RATIO, (
        f"{len(errors)}/{BURST_SESSIONS} sessions failed under an instant burst "
        f"({failure_ratio:.0%} > {BURST_MAX_FAILURE_RATIO:.0%}): {errors[:3]}"
    )
    assert latencies, "the burst was shed entirely -- no request succeeded"

    # Recovery: once the herd disperses, a plain session must work again.
    recovery_latencies: list[float] = []
    recovery_errors: list[str] = []
    await asyncio.sleep(10)
    await _load_session(endpoint_url, recovery_latencies, recovery_errors)
    assert not recovery_errors, f"endpoint did not recover after the burst: {recovery_errors}"


@pytest.mark.scale_load
def test_replicas_never_fall_below_minimum_after_load(aca_target, scale_config):
    """Scale-in must floor at minReplicas, never drain to zero."""
    revision = _latest_revision(aca_target)
    running = [
        r for r in _replicas(aca_target, revision) if r["properties"]["runningState"] == "Running"
    ]
    assert len(running) >= scale_config["minReplicas"], (
        f"after load, only {len(running)} replica(s) running for {revision}; "
        f"scale-in floor is {scale_config['minReplicas']}"
    )
