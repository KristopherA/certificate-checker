"""Outbound HTTP for AIA, OCSP and CRL (M4): the only code that contacts a URL taken from a certificate.

Every request goes through probe.TargetPolicy (the same resolve-once, policy-checked addresses as the TLS probe),
is http or https only (no userinfo, no other schemes), follows at most MAX_REDIRECTS redirects (each one
re-checked from scratch), and is capped in size (per purpose) and in time (one deadline for the whole fetch,
redirects included). https verifies the server against the system store; the payloads are signed anyway.
Nothing is cached beyond one call, and every URL attempted is recorded so results can list it.
"""

from __future__ import annotations

import functools
import http.client
import socket
import ssl
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field

from . import probe

FETCH_TIMEOUT_S = 5.0
MAX_REDIRECTS = 3
MAX_BYTES = {"aia": 256 * 1024, "ocsp": 64 * 1024, "crl": 10 * 1024 * 1024}
SCHEMES = {"http": 80, "https": 443}
USER_AGENT = "certificate-checker-web"


class FetchError(Exception):
    """A fetch that could not complete; the message is safe to show (no response bodies)."""


@dataclass
class Fetched:
    url: str
    status: int
    body: bytes
    contacted: list[str] = field(default_factory=list)


def _split(url: str) -> tuple[str, str, int, str]:
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError as e:
        raise FetchError(f"Bad URL {url!r}: {e}") from None
    scheme = u.scheme.lower()
    if scheme not in SCHEMES:
        raise FetchError(f"Refused {scheme or 'scheme-less'} URL (only http and https are fetched)")
    if u.username is not None or u.password is not None or "@" in u.netloc:
        raise FetchError("Refused URL with user information")
    host = u.hostname or ""
    if not host:
        raise FetchError("URL has no host")
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    return scheme, host, port or SCHEMES[scheme], path


def fetch(
    url: str,
    *,
    purpose: str,
    policy: probe.TargetPolicy | None = None,
    method: str = "GET",
    body: bytes | None = None,
    content_type: str | None = None,
    timeout: float = FETCH_TIMEOUT_S,
    contacted: list[str] | None = None,
    blocked: list[str] | None = None,
) -> Fetched:
    """GET (or POST) url; returns the final 2xx response. Raises FetchError or probe.TargetDenied."""
    limit = MAX_BYTES[purpose]
    policy = policy or probe.TargetPolicy.from_env()
    seen = contacted if contacted is not None else []
    deadline = time.monotonic() + timeout

    def left() -> float:
        rest = deadline - time.monotonic()
        if rest <= 0:
            raise FetchError(f"Timed out after {timeout:g} s")
        return rest

    for _ in range(MAX_REDIRECTS + 1):
        scheme, host, port, path = _split(url)
        try:
            status, location, data = _one(
                scheme,
                host,
                port,
                path,
                method,
                body,
                content_type,
                policy,
                left,
                limit,
                functools.partial(seen.append, url),
            )
        except probe.TargetDenied:
            if blocked is not None:  # review M4 S1: refused by TargetPolicy, so never contacted
                blocked.append(url)
            raise
        if status in (301, 302, 303, 307, 308):
            if not location:
                raise FetchError(f"HTTP {status} without a Location from {host}")
            url = urllib.parse.urljoin(url, location)
            if status == 303:
                method, body, content_type = "GET", None, None
            continue
        if not 200 <= status < 300:
            raise FetchError(f"HTTP {status} from {host}")
        return Fetched(url, status, data, seen)
    raise FetchError(f"More than {MAX_REDIRECTS} redirects")


def _one(
    scheme: str,
    host: str,
    port: int,
    path: str,
    method: str,
    body: bytes | None,
    content_type: str | None,
    policy: probe.TargetPolicy,
    remaining: Callable[[], float],
    limit: int,
    resolved: Callable[[], None],
) -> tuple[int, str | None, bytes]:
    try:
        addrs, _ = probe.resolve(probe.Target(host, port), policy, timeout=min(remaining(), probe.RESOLVE_TIMEOUT_S))
    except ValueError as e:  # TargetDenied is a ValueError; bad host names too
        if isinstance(e, probe.TargetDenied):
            raise
        raise FetchError(str(e)) from None
    except OSError as e:
        raise FetchError(str(e)) from None
    resolved()  # only now, after the policy check on every resolved address, is the URL "contacted"
    sock: socket.socket | None = None
    last: OSError | None = None
    for i, ip in enumerate(addrs):
        try:
            sock = socket.create_connection((ip, port), timeout=remaining() / (len(addrs) - i))
            break
        except OSError as e:
            last = e
    if sock is None:
        raise FetchError(f"Could not connect to {host}:{port}: {last}")
    conn = http.client.HTTPConnection(host, port, timeout=remaining())
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            sock.settimeout(remaining())
            sock = ctx.wrap_socket(sock, server_hostname=None if probe._is_ip(host) else host)
        conn.sock = sock
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}
        if content_type:
            headers["Content-Type"] = content_type
        sock.settimeout(remaining())
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        location = resp.getheader("Location")
        if resp.status in (301, 302, 303, 307, 308):
            return resp.status, location, b""
        declared = resp.getheader("Content-Length")
        if declared and declared.strip().isdigit() and int(declared) > limit:
            raise FetchError(f"Response from {host} is larger than the {limit // 1024} KB limit")
        data = bytearray()
        while not resp.isclosed():
            if sock.fileno() >= 0:  # http.client closes the socket once the body is read
                sock.settimeout(remaining())
            chunk = resp.read(min(65_536, limit + 1 - len(data)))
            if not chunk:
                break
            data += chunk
            if len(data) > limit:
                raise FetchError(f"Response from {host} is larger than the {limit // 1024} KB limit")
        return resp.status, location, bytes(data)
    except (OSError, http.client.HTTPException) as e:
        raise FetchError(f"{host}: {e or type(e).__name__}") from None
    finally:
        conn.close()
        sock.close()
