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
        on_request: Optional callback invoked with the client IP for each
            allowed request (used for telemetry).
    """

    def __init__(self, app, requests_per_minute: int = 60, on_request=None):
        self.app = app
        self.rpm = requests_per_minute
        self.on_request = on_request
        # ip -> [tokens, last_refill_monotonic]
        self._buckets: dict[str, list[float]] = {}

    def _client_ip(self, scope) -> str:
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        forwarded = headers.get("x-forwarded-for")
        if forwarded:
            # First hop is the original client (ACA ingress appends its own)
            return forwarded.split(",")[0].strip()
        client = scope.get("client")
        return client[0] if client else "unknown"

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
        stale = [
            ip for ip, (_, last) in self._buckets.items()
            if now - last > STALE_BUCKET_SECONDS
        ]
        for ip in stale:
            del self._buckets[ip]

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.rpm <= 0:
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
            self.on_request(ip)
        await self.app(scope, receive, send)
