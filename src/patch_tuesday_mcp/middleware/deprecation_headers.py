"""Standards-based deprecation headers for a retiring HTTP deployment.

Adds ``Deprecation`` (RFC 9745), ``Sunset`` (RFC 8594), and a
``rel="successor-version"`` ``Link`` (RFC 5829) to every HTTP response, so
clients, proxies, and monitoring can detect the migration without any model
involvement at all.

Only mounted when :mod:`patch_tuesday_mcp.deprecation` is configured, so a
normal deployment pays nothing — not even a pass-through call.
"""


class DeprecationHeadersMiddleware:
    """ASGI middleware appending deprecation headers to every HTTP response.

    Headers are resolved once at construction (deployment config does not
    change mid-process) and appended rather than replacing the response's own
    headers, so existing behavior is untouched.
    """

    def __init__(self, app, headers: list[tuple[bytes, bytes]]):
        self.app = app
        self.headers = headers

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.headers:
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + self.headers
            await send(message)

        await self.app(scope, receive, send_with_headers)
