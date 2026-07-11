"""Shared httpx AsyncClient so feeds reuse connections.

Supersedence chain walks issue up to ~30 sequential requests to the same
hosts; a per-request client would pay a fresh TLS handshake for each.

Redirects are not followed: every upstream URL is hardcoded to a known host,
and following a redirect could send the (unbounded) fetch anywhere.
"""

import asyncio

import httpx

_client: httpx.AsyncClient | None = None
_client_loop: asyncio.AbstractEventLoop | None = None


class ResponseTooLarge(httpx.HTTPError):
    """Raised when an upstream response exceeds the caller's byte cap."""


def get_client() -> httpx.AsyncClient:
    """Return the shared client, creating it lazily.

    Recreated if the running event loop changed (connections are bound to the
    loop they were opened on), which only happens across test cases.
    """
    global _client, _client_loop
    loop = asyncio.get_running_loop()
    if _client is None or _client.is_closed or _client_loop is not loop:
        _client = httpx.AsyncClient(
            follow_redirects=False,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
        _client_loop = loop
    return _client


async def aclose() -> None:
    """Close the shared client (called on HTTP server shutdown)."""
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None


async def get_location(url: str, *, timeout: float) -> tuple[int, str | None]:
    """GET a URL without reading the body; return (status, Location header or None).

    Lets a caller resolve one redirect hop manually — validating the target
    itself — while the shared client keeps follow_redirects=False.
    """
    client = get_client()
    async with client.stream("GET", url, timeout=timeout) as response:
        return response.status_code, response.headers.get("location")


async def get_bounded(
    url: str,
    *,
    headers: dict | None = None,
    timeout: float,
    max_bytes: int,
) -> tuple[int, bytes]:
    """GET a URL, reading at most max_bytes of the body.

    Returns (status_code, body). Non-200 responses return an empty body (the
    callers only need the status). Raises ResponseTooLarge — an httpx.HTTPError
    subclass, so callers' existing handlers catch it — when the declared or
    streamed body exceeds the cap, without buffering the excess.
    """
    client = get_client()
    async with client.stream("GET", url, headers=headers, timeout=timeout) as response:
        if response.status_code != 200:
            return response.status_code, b""

        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > max_bytes:
            raise ResponseTooLarge(
                f"response declared {declared} bytes, over the {max_bytes}-byte cap: {url}"
            )

        received = bytearray()
        async for chunk in response.aiter_bytes():
            received += chunk
            if len(received) > max_bytes:
                raise ResponseTooLarge(
                    f"response exceeded the {max_bytes}-byte cap: {url}"
                )
        return response.status_code, bytes(received)
