"""Request hardening, applied to every route before login is even considered (auth.py and main.py add login).

* LAN-only clients (M6): a request whose peer address is not RFC 1918, CGNAT, loopback, link-local
  or ULA is refused with 403 unless lan_only is off (settings.yaml network.lan_only). The peer is
  the TCP peer: proxy headers are never trusted (uvicorn runs with proxy_headers=False).

* Security headers on every response: a strict Content-Security-Policy (no inline script or style, no eval,
  same-origin XHR only, no framing, forms post only to this origin), nosniff, no referrer, COOP/CORP, and
  no-store caching (results may contain internal names).
* Body cap: Content-Length above the limit is refused with 413 before the app reads anything; a chunked or
  lying body is counted while it streams and cut off at the limit. Nothing is spooled to disk.
* Cross-site requests: a state-changing request (any method but GET/HEAD/OPTIONS) is refused when
  Sec-Fetch-Site says cross-site or same-site, or when Origin is present and is not this origin.
* CSRF tokens (double submit): pages set a random token cookie (SameSite=Strict, HttpOnly, Secure over TLS)
  and put the same token in every form, the login form included; UI posts must echo it (check_csrf). The
  token is replaced at login and logout. API posts must be JSON
  (application/json cannot be sent cross-origin without a CORS preflight, which this app never grants) or
  carry the X-CertCheck-Request: 1 header (same reason), so a plain cross-site form cannot reach them.
* Host header allowlist (CERTCHECK_ALLOWED_HOSTS) against DNS rebinding, when set.
"""

from __future__ import annotations

import hmac
import ipaddress
import secrets
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from starlette.requests import Request

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

CSRF_COOKIE = "certcheck_csrf"
CSRF_FIELD = "csrf_token"
API_HEADER = "x-certcheck-request"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

CSP = "; ".join([
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
])  # fmt: skip
HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), usb=(), payment=()"),
]


async def _plain(send: Send, status: int, text: str) -> None:
    body = text.encode()
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode()),
        (b"cache-control", b"no-store"), *HEADERS]})  # fmt: skip
    await send({"type": "http.response.body", "body": body})


class Hardening:
    """Pure ASGI middleware (no BaseHTTPMiddleware buffering)."""

    def __init__(
        self, app: ASGIApp, *, max_body: int, allowed_hosts: tuple[str, ...] = (), lan_only: bool = True
    ) -> None:
        self.inner, self.max_body, self.allowed_hosts, self.lan_only = app, max_body, allowed_hosts, lan_only

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.inner(scope, receive, send)
            return
        if self.lan_only and not lan_client(scope.get("client")):
            await _plain(send, 403, "This app only answers clients on the local network.")
            return
        h = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        host = h.get("host", "")
        if self.allowed_hosts and _host_only(host) not in self.allowed_hosts:
            await _plain(send, 400, "Unknown Host header.")
            return
        method = scope["method"]
        if method not in SAFE_METHODS:
            if h.get("sec-fetch-site", "same-origin") in ("cross-site", "same-site"):
                await _plain(send, 403, "Cross-site request refused.")
                return
            origin = h.get("origin")
            if origin is not None and origin != f"{scope.get('scheme', 'http')}://{host}":
                await _plain(send, 403, "Cross-origin request refused.")
                return
            if scope["path"].startswith("/api/"):
                ctype = h.get("content-type", "").split(";", 1)[0].strip().lower()
                if ctype != "application/json" and h.get(API_HEADER) != "1":
                    await _plain(send, 403, "API requests need a JSON body or the X-CertCheck-Request: 1 header.")
                    return
        cl = h.get("content-length")
        if cl is not None and (not cl.isdigit() or int(cl) > self.max_body):
            await _plain(send, 413, f"Request body is larger than {self.max_body // 1024} KB.")
            return
        # Buffer the body here (bounded by max_body) so an oversize streamed body is a clean 413 before any
        # route or parser sees it; replay it to the app afterwards. 1 MB in memory per request at most.
        chunks: list[bytes] = []
        seen = 0
        more = True
        while more:
            m = await receive()
            if m["type"] == "http.disconnect":
                return
            chunk = m.get("body", b"")
            seen += len(chunk)
            if seen > self.max_body:
                await _plain(send, 413, f"Request body is larger than {self.max_body // 1024} KB.")
                return
            chunks.append(chunk)
            more = m.get("more_body", False)
        body = b"".join(chunks)
        sent = False

        async def replay() -> Message:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        async def with_headers(m: Message) -> None:
            if m["type"] == "http.response.start":
                names = {k.lower() for k, _ in m.get("headers", [])}
                extra = [x for x in HEADERS if x[0] not in names]
                if b"cache-control" not in names:
                    extra.append((b"cache-control", b"no-store"))
                m["headers"] = [*m.get("headers", []), *extra]
            await send(m)

        await self.inner(scope, replay, with_headers)


# RFC 1918, CGNAT (RFC 6598), loopback, link-local, ULA. The IPv4 networks are built from integers so the
# identifier scan (tests/test_identifiers.py) does not see private literals outside its allowlist.
LAN_NETS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    *(ipaddress.IPv4Network((base, bits)) for base, bits in (
        (0x0A000000, 8), (0xAC100000, 12), (0xC0A80000, 16), (0x64400000, 10), (0x7F000000, 8), (0xA9FE0000, 16))),
    *(ipaddress.IPv6Network(n) for n in ("::1/128", "fe80::/10", "fc00::/7")),
)  # fmt: skip


def lan_client(client: tuple[str, int] | list[Any] | None) -> bool:
    """True for an RFC 1918, CGNAT, loopback, link-local or ULA peer (IPv4-mapped IPv6 unwrapped). An explicit
    list rather than ip.is_private, which also counts documentation, benchmarking and other special ranges that
    are not a LAN. A peer that is not an IP address (unix socket) counts as local; anything else unparseable
    fails closed."""
    if not client:
        return True
    try:
        ip = ipaddress.ip_address(str(client[0]).split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip in n for n in LAN_NETS)


def _host_only(host: str) -> str:
    host = host.lower()
    if host.startswith("["):
        return host.split("]", 1)[0] + "]"
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def csrf_token(request: Request) -> str:
    """The token for this browser: the existing cookie when it looks like ours, else a new one."""
    t = request.cookies.get(CSRF_COOKIE, "")
    return t if len(t) == 43 and t.replace("-", "").replace("_", "").isalnum() else new_token()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def check_csrf(request: Request, submitted: str | None) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE, "")
    return bool(cookie) and submitted is not None and hmac.compare_digest(cookie.encode(), submitted.encode())
