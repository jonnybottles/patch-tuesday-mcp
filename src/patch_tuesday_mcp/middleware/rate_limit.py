"""Per-IP token-bucket rate limiting for the HTTP transport.

Only used when the server runs with MCP_TRANSPORT=http (a public remote
endpoint). Local stdio usage never passes through this middleware.
"""

import json
import time

# Buckets older than this are pruned to bound memory usage
STALE_BUCKET_SECONDS = 600
PRUNE_THRESHOLD = 10_000


class RateLimitMiddleware:
    """ASGI middleware implementing a per-client-IP token bucket.

    Args:
        app: The wrapped ASGI application.
        requests_per_minute: Sustained request budget per client IP. The
            bucket capacity equals this value, refilled continuously.
        on_request: Optional callback invoked with (client IP, path) for each
            allowed request (used for telemetry).
        exempt_paths: Paths that bypass rate limiting and the on_request
            callback (health probes must not consume budget or be counted).
        trust_x_forwarded_for: When True, the ``X-Forwarded-For`` header is
            consulted to determine the client IP (the server is behind a
            reverse proxy / ingress). When False, only the direct TCP peer is
            used and the header is ignored — the correct choice when the
            server is directly exposed, since anyone could otherwise spoof the
            header to evade or poison the limiter.
        trusted_proxies: Optional set of proxy IPs. When non-empty,
            ``X-Forwarded-For`` is only honored if the direct peer is one of
            these proxies, and the resolved client is the right-most hop that
            is *not* itself a trusted proxy (so chained proxies are unwound
            correctly). When empty, the right-most hop appended by the single
            ingress proxy in front of us is trusted.
    """

    def __init__(
        self,
        app,
        requests_per_minute: int = 60,
        on_request=None,
        exempt_paths: frozenset[str] = frozenset({"/health"}),
        trust_x_forwarded_for: bool = True,
        trusted_proxies: frozenset[str] = frozenset(),
    ):
        self.app = app
        self.rpm = requests_per_minute
        self.on_request = on_request
        self.exempt_paths = exempt_paths
        self.trust_x_forwarded_for = trust_x_forwarded_for
        self.trusted_proxies = trusted_proxies
        # ip -> [tokens, last_refill_monotonic]
        self._buckets: dict[str, list[float]] = {}

    def _client_ip(self, scope) -> str:
        client = scope.get("client")
        direct = client[0] if client else "unknown"

        # Directly exposed (or explicitly told not to trust proxy headers):
        # the header is attacker-controlled, so ignore it entirely.
        if not self.trust_x_forwarded_for:
            return direct

        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])
        }
        forwarded = headers.get("x-forwarded-for")
        if not forwarded:
            return direct
        hops = [h.strip() for h in forwarded.split(",") if h.strip()]
        if not hops:
            return direct

        # No explicit proxy allowlist: trust the right-most hop, which is the
        # one appended by the single ingress proxy in front of us. Earlier
        # entries are client-supplied and spoofable.
        if not self.trusted_proxies:
            return hops[-1]

        # With an allowlist, only honor the header when the request actually
        # reached us via a known proxy; otherwise the peer forged it.
        if direct not in self.trusted_proxies:
            return direct
        # Unwind trusted proxies from the right: the first hop that is not a
        # trusted proxy is the real client.
        for hop in reversed(hops):
            if hop not in self.trusted_proxies:
                return hop
        return hops[0]

    def _allow(self, ip: str) -> bool:
        now = time.monotonic()
        bucket = self._buckets.get(ip)
        if bucket is None:
            self._prune_if_needed(now)
            self._buckets[ip] = [self.rpm - 1.0, now]
            return True

        tokens, last = bucket
        tokens = min(self.rpm, tokens + (now - last) * (self.rpm / 60.0))
        if tokens < 1.0:
            bucket[0] = tokens
            bucket[1] = now
            return False
        bucket[0] = tokens - 1.0
        bucket[1] = now
        return True

    def _prune_if_needed(self, now: float) -> None:
        if len(self._buckets) < PRUNE_THRESHOLD:
            return
        stale = [ip for ip, (_, last) in self._buckets.items() if now - last > STALE_BUCKET_SECONDS]
        for ip in stale:
            del self._buckets[ip]
        # Hard cap: still full of fresh buckets means a flood of distinct
        # client IPs — evict the least recently seen so memory stays bounded
        if len(self._buckets) >= PRUNE_THRESHOLD:
            excess = len(self._buckets) - PRUNE_THRESHOLD + 1
            oldest = sorted(self._buckets, key=lambda ip: self._buckets[ip][1])[:excess]
            for ip in oldest:
                del self._buckets[ip]

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.rpm <= 0:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        ip = self._client_ip(scope)
        if not self._allow(ip):
            body = json.dumps({"error": "rate limit exceeded"}).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"retry-after", b"60"),
                        (b"content-length", str(len(body)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        if self.on_request is not None:
            self.on_request(ip, path)
        await self.app(scope, receive, send)
