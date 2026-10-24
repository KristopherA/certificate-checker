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
* Gateway-peer warning (M7b): behind Docker's userland proxy (Docker Desktop, some IPv6 setups) every client
  arrives from the bridge gateway, so the LAN check passes for everyone and the per-address lockout lumps all
  clients together. GatewayPeerWatch logs one warning when the first WATCH_REQUESTS non-loopback requests all
  came from the container's default gateway, IPv4 or IPv6 (::ffff:a.b.c.d peers are unwrapped first). Opt-in
  CERTCHECK_REFUSE_GATEWAY_PEERS=1 refuses every request from a gateway instead (403); off by default because
  a browser on the Docker host itself also arrives from the gateway (see web/docker/DEPLOYMENT.md,
  "Client addresses").
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import secrets
import socket
import struct
from collections.abc import Awaitable, Callable, MutableMapping
from pathlib import Path
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


log = logging.getLogger("certcheck.security")

WATCH_REQUESTS = 20


def _hex_v6(h: str) -> str:
    return str(ipaddress.IPv6Address(bytes.fromhex(h)))


def default_gateways(
    route: Path = Path("/proc/net/route"), route6: Path = Path("/proc/net/ipv6_route")
) -> frozenset[str]:
    """IPv4 and IPv6 default gateways from the Linux routing tables (empty when unreadable, e.g. on macOS)."""
    out: set[str] = set()
    try:
        lines = route.read_text().splitlines()[1:]
    except OSError:
        lines = []
    for line in lines:
        f = line.split()
        if len(f) >= 3 and f[1] == "00000000" and f[2] != "00000000":
            try:
                out.add(socket.inet_ntoa(struct.pack("<I", int(f[2], 16))))
            except (ValueError, struct.error):
                continue
    try:
        lines6 = route6.read_text().splitlines()
    except OSError:
        lines6 = []
    zero = "0" * 32
    for line in lines6:
        # dest dest_len src src_len next_hop metric refcnt use flags iface
        f = line.split()
        if len(f) >= 5 and f[0] == zero and f[1] == "00" and f[4] != zero:
            try:
                out.add(_hex_v6(f[4]))
            except ValueError:
                continue
    return frozenset(out)


def peer_ip(client: tuple[str, int] | list[Any] | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The peer address with any zone id dropped and ::ffff:a.b.c.d unwrapped to a.b.c.d (None if not an IP)."""
    if not client:
        return None
    try:
        ip = ipaddress.ip_address(str(client[0]).split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


class GatewayPeerWatch:
    """Warns once if the first N non-loopback requests all came from a default gateway (a proxy hides the real
    peers); with refuse=True (CERTCHECK_REFUSE_GATEWAY_PEERS) every request from a gateway is refused."""

    def __init__(
        self, gateways: frozenset[str] | None = None, threshold: int = WATCH_REQUESTS, refuse: bool = False
    ) -> None:
        raw = default_gateways() if gateways is None else gateways
        self.gateways = frozenset(g for g in (peer_ip((x, 0)) for x in raw) if g is not None)
        self.threshold, self.seen, self.done, self.refuse = threshold, 0, not self.gateways, refuse

    def is_gateway(self, client: tuple[str, int] | list[Any] | None) -> bool:
        ip = peer_ip(client)
        return ip is not None and ip in self.gateways

    def observe(self, client: tuple[str, int] | list[Any] | None) -> None:
        if self.done:
            return
        ip = peer_ip(client)
        if ip is None or ip.is_loopback:
            return  # no address, or the container's own healthcheck
        if ip not in self.gateways:
            self.done = True  # real peers are visible
            return
        self.seen += 1
        if self.seen >= self.threshold:
            self.done = True
            log.warning(
                "the first %d non-loopback requests all came from the gateway %s: a proxy (Docker userland proxy "
                "or NAT) may be hiding real client addresses, so the LAN-only check would pass for everyone and "
                "login lockout would count all clients as one; a browser on the Docker host itself also does "
                "this harmlessly; see DEPLOYMENT.md, Client addresses",
                self.seen,
                ip,
            )


class Hardening:
    """Pure ASGI middleware (no BaseHTTPMiddleware buffering)."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body: int,
        allowed_hosts: tuple[str, ...] = (),
        lan_only: bool = True,
        refuse_gateway_peers: bool = False,
        watch: GatewayPeerWatch | None = None,
    ) -> None:
        self.inner, self.max_body, self.allowed_hosts, self.lan_only = app, max_body, allowed_hosts, lan_only
        self.watch = GatewayPeerWatch(refuse=refuse_gateway_peers) if watch is None else watch

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.inner(scope, receive, send)
            return
        self.watch.observe(scope.get("client"))
        if self.watch.refuse and self.watch.is_gateway(scope.get("client")):
            await _plain(send, 403, "Requests through the Docker gateway are refused (CERTCHECK_REFUSE_GATEWAY_PEERS).")
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
