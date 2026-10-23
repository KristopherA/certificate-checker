"""Core TLS probe: one connection, one handshake, then the same analysis as offline files.

Port of the plain-TLS path of Probe.runSync (Source/Sources/Core/Probe.swift). STARTTLS, MySQL,
RDP and the appliance/vendor adjustments arrive in M2; legacy TLS 1.0/1.1 in M4 (separate module).

Safety: resolves once (5 s lookup timeout) and connects only to the addresses that lookup returned
(or the resolve override), each checked by TargetPolicy. One TCP attempt per address in resolver
order (Target.family picks IPv4/IPv6 only); the first successful connect is the one probed, and a TLS
failure there is final. No retries, short timeouts, sends no application data and reads none.
Certificate validation is off in the handshake so the chain can be inspected; trust.verify does the
real evaluation afterwards.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import socket
import ssl
import threading
import time
from collections.abc import Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import analysis, trust
from .model import Finding, Purpose, Severity, Topic, sort_findings
from .x509info import Cert, parse_cert

DEFAULT_TIMEOUT_S = 10.0


@dataclass(frozen=True)
class Target:
    host: str
    port: int = 443
    sni: str | None = None  # defaults to host (not sent for an IP literal)
    verify_name: str | None = None  # name the certificate must cover; defaults to sni/host
    connect_ip: str | None = None  # like curl --resolve host:port:ip
    family: str = "any"  # "any" | "ipv4" | "ipv6"

    @property
    def server_name(self) -> str:
        return self.sni or self.host

    @property
    def expected_name(self) -> str:
        return self.verify_name or self.server_name

    @property
    def endpoint(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"

    def validate(self) -> None:
        if not self.host or len(self.host) > 253 or any(c.isspace() or c in "/\\@" for c in self.host):
            raise ValueError("Host must be a DNS name or IP address.")
        if not 1 <= self.port <= 65535:
            raise ValueError("Port must be 1-65535.")
        if self.connect_ip is not None:
            ipaddress.ip_address(self.connect_ip)  # raises ValueError
        if self.family not in FAMILIES:
            raise ValueError("Address family must be any, ipv4 or ipv6.")


@dataclass
class ProbeResult:
    target: Target
    connected_ip: str | None = None
    resolver: str = "system"
    tls_version: str | None = None
    cipher: str | None = None
    chain: list[Cert] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    transcript: list[str] = field(default_factory=list)
    error: str | None = None
    duration_s: float = 0.0
    trust: trust.TrustResult | None = None

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)


def default_context() -> ssl.SSLContext:
    """Context for every normal probe: TLS 1.2+, OpenSSL's default security level (2 on Ubuntu).
    Legacy TLS 1.0/1.1 never uses this context (tests/test_probe.py asserts it refuses TLS 1.0)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inspect first; trust.verify evaluates afterwards
    return ctx


FAMILIES = {"any": socket.AF_UNSPEC, "ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}
RESOLVE_TIMEOUT_S = 5.0
RESOLVER_THREADS = 4
_resolver_pool = ThreadPoolExecutor(max_workers=RESOLVER_THREADS, thread_name_prefix="certcheck-dns")
# One slot per resolver thread, held until the lookup really finishes (not when the caller gives up),
# so hung lookups cannot queue unbounded work behind the pool: when all slots are busy, a new lookup
# fails fast with "resolver busy" instead of waiting.
_resolver_slots = threading.BoundedSemaphore(RESOLVER_THREADS)


class TargetDenied(ValueError):
    """The resolved address is refused by the probe target policy."""


METADATA = frozenset(
    ipaddress.ip_address(a)
    for a in (
        "169.254.169.254",
        "169.254.170.2",
        "fd00:ec2::254",
    )  # AWS/GCP/Azure/OCI IMDS, ECS task metadata, AWS IPv6 IMDS
) | {
    ipaddress.IPv4Address(0x646464C8)
}  # Alibaba Cloud metadata (CGNAT range; an integer so the address scan stays clean)
THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")  # RFC 1122 "this network"; 0.x.x.x can reach the host
NAT64 = ipaddress.ip_network("64:ff9b::/96")


def embedded_ipv4(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """The IPv4 address an IPv6 address stands for, so the policy judges what is really reached:
    IPv4-mapped ::ffff:a.b.c.d, NAT64 64:ff9b::/96, 6to4 2002::/16 and IPv4-compatible ::a.b.c.d
    (:: and ::1 are left alone). Anything else is returned unchanged."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return ip
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour is not None:
        return ip.sixtofour
    if int(ip) >> 32 == 0 and int(ip) > 1:
        return ipaddress.IPv4Address(int(ip))
    return ip


def judged_addresses(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """The addresses the policy judges for one connect address: a Teredo address (2001::/32) is judged
    as both its embedded server and client IPv4 (either could be what is reached); anything else as
    embedded_ipv4(ip)."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.teredo is not None:
        return ip.teredo
    return (embedded_ipv4(ip),)


def container_addresses() -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """This container's own addresses (its hostname's local lookup, /etc/hosts in Docker). Best effort:
    an empty set if the lookup fails; loopback and unspecified are covered separately."""
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, 0, socket.SOCK_STREAM)
    except OSError:
        return frozenset()
    return frozenset(ipaddress.ip_address(str(i[4][0]).split("%", 1)[0]) for i in infos)


@dataclass(frozen=True)
class TargetPolicy:
    """Which resolved addresses a probe may connect to. Checked after resolution (and for connect_ip),
    on the address actually used, with embedded IPv4 unwrapped first (judged_addresses: mapped, NAT64,
    6to4, IPv4-compatible, and both Teredo server and client), so DNS cannot sidestep it.

    Defaults (any host may be probed, per the spec, except): cloud metadata endpoints, link-local
    (169.254/16, fe80::/10), unspecified (::), 0.0.0.0/8 and multicast are denied; loopback is denied
    (it reaches the container itself); the app's own port is denied on loopback, unspecified and the
    container's own addresses (own_addresses), so it stays probeable on any other host. Private ranges
    are allowed (internal servers are the point of the tool). Tests set allow_loopback=True."""

    allow_loopback: bool = False
    allow_link_local: bool = False
    allow_metadata: bool = False
    own_ports: frozenset[int] = frozenset()
    own_addresses: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset()
    extra_denied: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> TargetPolicy:
        """CERTCHECK_PROBE_ALLOW_LOOPBACK / _ALLOW_LINK_LOCAL / _ALLOW_METADATA = 1, CERTCHECK_PORT (own port),
        CERTCHECK_PROBE_DENY = comma-separated CIDRs. Fails closed: an invalid CERTCHECK_PORT or CIDR
        raises ValueError, so no probe runs on a policy that could not be read."""
        e = os.environ if env is None else env

        def on(k: str) -> bool:
            return e.get(k, "").strip().lower() in ("1", "true", "yes")

        raw = e.get("CERTCHECK_PORT", "8080").strip()
        if not (raw.isascii() and raw.isdigit() and 1 <= int(raw) <= 65535):
            raise ValueError(f"CERTCHECK_PORT={raw!r} is not a port number; probing is disabled")
        deny = tuple(
            ipaddress.ip_network(x.strip(), strict=False)
            for x in e.get("CERTCHECK_PROBE_DENY", "").split(",")
            if x.strip()
        )
        return cls(
            allow_loopback=on("CERTCHECK_PROBE_ALLOW_LOOPBACK"),
            allow_link_local=on("CERTCHECK_PROBE_ALLOW_LINK_LOCAL"),
            allow_metadata=on("CERTCHECK_PROBE_ALLOW_METADATA"),
            own_ports=frozenset({int(raw)}),
            own_addresses=container_addresses(),
            extra_denied=deny,
        )

    def check(self, address: str, port: int) -> None:
        raw = ipaddress.ip_address(address.split("%", 1)[0])
        judged = judged_addresses(raw)
        if port in self.own_ports and any(
            ip.is_loopback or ip.is_unspecified or ip in self.own_addresses for ip in (raw, *judged)
        ):
            raise TargetDenied(f"port {port} is this app's own port on {address} (this container)")
        for ip in judged:
            self._check_address(address, ip)

    def _check_address(self, address: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        if ip in METADATA and not self.allow_metadata:
            raise TargetDenied(f"{address} is a cloud metadata address; probing it is disabled")
        if ip.is_link_local and not self.allow_link_local:
            raise TargetDenied(f"{address} is link-local; probing it is disabled")
        if ip.is_unspecified or ip.is_multicast or ip in THIS_NETWORK:
            raise TargetDenied(f"{address} is not a unicast host address")
        if ip.is_loopback and not self.allow_loopback:
            raise TargetDenied(f"{address} is loopback (this container); probing it is disabled")
        for n in self.extra_denied:
            if ip.version == n.version and ip in n:
                raise TargetDenied(f"{address} is in the denied range {n}")


def _release_slot(_: Future[Any]) -> None:
    _resolver_slots.release()


def resolve(t: Target, policy: TargetPolicy | None = None, timeout: float = RESOLVE_TIMEOUT_S) -> tuple[list[str], str]:
    """One lookup with a timeout; returns (addresses in resolver order, source), filtered by the policy.

    Never re-resolved during the probe. Addresses the policy refuses are dropped; if none remain the
    first refusal is raised."""
    policy = policy or TargetPolicy.from_env()
    if t.connect_ip:
        addrs, source = [t.connect_ip], "override"
    elif _is_ip(t.host):
        addrs, source = [str(ipaddress.ip_address(t.host))], "literal"
    else:
        if not _resolver_slots.acquire(blocking=False):
            raise OSError(f"Name lookup for {t.host} not started: resolver busy with earlier lookups")
        try:
            fut = _resolver_pool.submit(socket.getaddrinfo, t.host, t.port, FAMILIES[t.family], socket.SOCK_STREAM)
        except BaseException:  # e.g. RuntimeError after interpreter shutdown: the slot was never handed over
            _resolver_slots.release()
            raise
        fut.add_done_callback(_release_slot)
        try:
            infos = fut.result(timeout=timeout)
        except FutureTimeout:
            raise OSError(f"Name lookup for {t.host} timed out after {timeout:g} s") from None
        addrs = list(dict.fromkeys(str(i[4][0]) for i in infos))
        source = "system"
        if not addrs:
            raise OSError(f"{t.host} did not resolve")
    if t.family == "ipv4":
        addrs = [a for a in addrs if ipaddress.ip_address(a.split("%")[0]).version == 4]
    elif t.family == "ipv6":
        addrs = [a for a in addrs if ipaddress.ip_address(a.split("%")[0]).version == 6]
    if not addrs:
        raise OSError(f"{t.host} has no {t.family} address")
    allowed, denied = [], []
    for a in addrs:
        try:
            policy.check(a, t.port)
            allowed.append(a)
        except TargetDenied as e:
            denied.append(e)
    if not allowed:
        raise denied[0]
    return allowed, source


def presented_chain(s: ssl.SSLSocket) -> list[bytes]:
    """DER certificates as sent by the server, in order. Python 3.13 has a public API; 3.12 a private one."""
    get = getattr(s, "get_unverified_chain", None)
    if get is None:
        get = s._sslobj.get_unverified_chain  # type: ignore[attr-defined]
    chain = get() or []
    return [c if isinstance(c, bytes) else c.public_bytes(ssl._ssl.ENCODING_DER) for c in chain]  # type: ignore[attr-defined]


def run(
    t: Target,
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
    now: dt.datetime | None = None,
    anchors: Path | None = None,
    context: ssl.SSLContext | None = None,
    policy: TargetPolicy | None = None,
) -> ProbeResult:
    r = ProbeResult(target=t)
    start = time.monotonic()
    try:
        t.validate()
        addrs, r.resolver = resolve(t, policy, timeout=min(timeout, RESOLVE_TIMEOUT_S))
        sni = None if _is_ip(t.server_name) else t.server_name
        ders: list[bytes] = []
        last: Exception | None = None
        # One attempt per resolved address, in resolver order; stop at the first TCP connect that
        # succeeds. A TLS failure after connecting is final (no retry on the next address).
        for ip in addrs:
            r.connected_ip = ip
            try:
                raw = socket.create_connection((ip, t.port), timeout=timeout)
            except OSError as e:
                r.transcript.append(f"Connect to {ip}:{t.port} failed: {e}")
                last = e
                continue
            with raw:
                r.transcript.append(f"Connected to {ip}:{t.port} ({r.resolver})")
                with (context or default_context()).wrap_socket(raw, server_hostname=sni) as s:
                    r.transcript.append(f"TLS handshake complete (SNI {sni or 'none'})")
                    r.tls_version = s.version()
                    c = s.cipher()
                    r.cipher = c[0] if c else None
                    ders = presented_chain(s)
            last = None
            break
        if last is not None:
            raise last
        if not ders:
            raise ssl.SSLError("No certificate received.")
        r.chain = [parse_cert(d) for d in ders]
        r.duration_s = time.monotonic() - start
        when = now or dt.datetime.now(dt.UTC)
        f = analysis.evaluate(r.chain, t.expected_name, Purpose.TLS_SERVER, now=when)
        r.trust = trust.verify(
            analysis.ordered_chain(r.chain),
            hostname=t.expected_name,
            purpose=Purpose.TLS_SERVER,
            now=when,
            anchors=anchors,
        )
        f.append(trust.finding(r.trust, "as presented by server"))
        if r.tls_version is None:
            f.append(Finding("tlsver", Severity.INFO, Topic.GENERAL, "TLS version not determined"))
        elif r.tls_version in ("TLSv1", "TLSv1.1"):
            f.append(
                Finding(
                    "tlsver",
                    Severity.WARNING,
                    Topic.GENERAL,
                    f"Server negotiated {r.tls_version}",
                    "Disable TLS 1.0/1.1 on the service.",
                )
            )
        f += address_findings(r)
        r.findings = sort_findings(f)
    except (OSError, ValueError, ssl.SSLError) as e:
        r.duration_s = time.monotonic() - start
        r.error = str(e) or type(e).__name__
        r.findings = [
            Finding("probe", Severity.FAIL, Topic.CONNECTION, f"Could not complete TLS to {t.endpoint}", r.error),
            *address_findings(r),
        ]
    return r


def address_findings(r: ProbeResult) -> list[Finding]:
    t = r.target
    if not r.connected_ip:
        return []
    return [
        Finding(
            "connected-ip",
            Severity.INFO,
            Topic.CONNECTION,
            f"Connected to {r.connected_ip}",
            f"Address used for {t.host}: {r.connected_ip} ({r.resolver}). "
            f"SNI and the expected name stay {t.server_name} / {t.expected_name}.",
        )
    ]


def openssl_command(t: Target) -> str:
    """Copy-only equivalent command. Never executed."""
    import shlex

    ep = f"{t.connect_ip or t.host}:{t.port}"
    return (
        f"openssl s_client -connect {shlex.quote(ep)} -servername {shlex.quote(t.server_name)} "
        f"-showcerts -verify_hostname {shlex.quote(t.expected_name)} </dev/null"
    )


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
    except ValueError:
        return False
    return True
