"""Core TLS probe: one connection, one handshake, then the same analysis as offline files.

Port of Probe.runSync (Source/Sources/Core/Probe.swift): plain TLS, the STARTTLS dialogues (SMTP,
IMAP, POP3, LDAP), the MySQL SSLRequest and the RDP X.224 negotiation, then the Remote / Appliance /
Stack / Vendor adjustments and the split-DNS / firewall hints. Legacy TLS 1.0/1.1, AIA, CT and revocation
are layered on top by certcheck.check (opt-in, M4); run() itself never uses them.

Safety: resolves once (5 s lookup timeout) and connects only to the addresses that lookup returned
(or the resolve override), each checked by TargetPolicy. One TCP attempt per address in resolver
order (Target.family picks IPv4/IPv6 only); the first successful connect is the one probed, and a TLS
failure there is final. No retries, short timeouts. Upgrade services send only the fixed pre-TLS
dialogue (EHLO/STARTTLS, a1 STARTTLS, STLS, the LDAP ExtendedRequest, SSLRequest, X.224); no
credentials and no application data after the handshake.
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

from . import adjust, analysis, hints, trust, wire
from .model import Finding, Purpose, Severity, Topic, sort_findings
from .services import Service
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
    service: Service = Service.HTTPS
    fingerprint_pin: str | None = None  # Proxmox VE / PBS only

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
        if self.fingerprint_pin and not self.service.accepts_fingerprint_pin:
            raise ValueError("A fingerprint pin applies to Proxmox VE and Proxmox Backup Server only.")


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
    negotiation: list[Finding] = field(default_factory=list)  # RDP negotiation findings
    legacy: bool = False  # result came from the legacy TLS 1.0/1.1 context (UI badge), set by certcheck.check
    contacted: list[str] = field(default_factory=list)  # outbound AIA/OCSP/CRL URLs (certcheck.check)
    blocked: list[str] = field(default_factory=list)  # AIA/OCSP/CRL URLs refused by TargetPolicy, never contacted

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


_own_addresses: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] | None = None
_own_addresses_lock = threading.Lock()


def container_addresses() -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """This container's own addresses (its hostname's local lookup, /etc/hosts in Docker), looked up once
    per process and cached; the app calls it at startup so no probe pays for the lookup. Best effort: a
    failed lookup returns an empty set and is not cached (the next call retries); loopback and
    unspecified are covered separately."""
    global _own_addresses
    with _own_addresses_lock:
        if _own_addresses is not None:
            return _own_addresses
        try:
            infos = socket.getaddrinfo(socket.gethostname(), None, 0, socket.SOCK_STREAM)
        except OSError:
            return frozenset()
        _own_addresses = frozenset(ipaddress.ip_address(str(i[4][0]).split("%", 1)[0]) for i in infos)
        return _own_addresses


def forget_container_addresses() -> None:
    """Drop the cached addresses (tests; or after the container's network changes)."""
    global _own_addresses
    with _own_addresses_lock:
        _own_addresses = None


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


class ProbeError(Exception):
    """Pre-TLS dialogue failure (Swift Probe.ProbeError): reported under the startTLS topic."""


MAX_LINE = 65_536


class _Reader:
    """Buffered reads on the plain socket before the TLS upgrade, each bounded by one overall deadline."""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self.sock, self.deadline, self.buffer = sock, deadline, bytearray()

    def _fill(self) -> None:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("Timed out waiting for the server")
        self.sock.settimeout(left)
        chunk = self.sock.recv(4096)
        if not chunk:
            raise ConnectionError("Server closed the connection")
        self.buffer += chunk

    def read_line(self) -> str:
        while b"\n" not in self.buffer:
            if len(self.buffer) > MAX_LINE:
                raise ProbeError("Server line too long")
            self._fill()
        i = self.buffer.index(b"\n")
        line = bytes(self.buffer[:i]).decode("utf-8", "replace").strip("\r")
        del self.buffer[: i + 1]
        return line

    def read(self, n: int) -> bytes:
        while len(self.buffer) < n:
            self._fill()
        out = bytes(self.buffer[:n])
        del self.buffer[:n]
        return out

    def write(self, b: bytes | str) -> None:
        self.sock.settimeout(max(0.001, self.deadline - time.monotonic()))
        self.sock.sendall(b.encode() if isinstance(b, str) else b)

    def pending(self) -> int:
        """Bytes buffered or already waiting on the socket (non-blocking peek)."""
        # Called once the server has said "go ahead with TLS". Anything already read past that reply (our
        # buffer) or already queued in the kernel would be fed into the TLS handshake as if it were protected
        # data: the CVE-2011-0411 STARTTLS command-injection class. MSG_PEEK leaves the bytes in place and the
        # socket goes back to blocking mode, so the handshake that follows is unaffected. This only sees bytes
        # that have already arrived; a later injection is caught by the TLS handshake failing.
        n = len(self.buffer)
        try:
            self.sock.setblocking(False)
            n += len(self.sock.recv(4096, socket.MSG_PEEK))
        except (BlockingIOError, InterruptedError):
            pass
        finally:
            self.sock.setblocking(True)
        return n


def upgrade(c: _Reader, t: Target, r: ProbeResult) -> None:
    """The pre-TLS dialogue for STARTTLS-style services (Probe.upgrade)."""

    def log(d: str, s: str) -> None:
        r.transcript.append(f"{d} {wire.sanitize(s)}")

    def smtp_read() -> tuple[int, list[str]]:
        lines: list[str] = []
        while True:
            line = c.read_line()
            log("S:", line)
            lines.append(line)
            rep = wire.smtp_reply(lines)
            if rep is not None:
                return rep
            if len(lines) > 100:
                raise ProbeError("SMTP reply too long")

    s = t.service
    if s == Service.SMTP_STARTTLS:
        banner, _ = smtp_read()
        if banner == -1:
            raise ProbeError("SMTP greeting is malformed: its continuation lines carry different reply codes.")
        if banner != 220:
            raise ProbeError(f"SMTP banner was {banner}, expected 220.")
        c.write("EHLO certificate-checker.invalid\r\n")
        log("C:", "EHLO certificate-checker.invalid")
        code, lines = smtp_read()
        if code == -1:
            raise ProbeError("EHLO reply is malformed: its continuation lines carry different reply codes.")
        if code != 250:
            raise ProbeError(f"EHLO returned {code}.")
        if not any(ln.upper()[4:].startswith("STARTTLS") for ln in lines):
            raise ProbeError("Server does not advertise STARTTLS.")
        c.write("STARTTLS\r\n")
        log("C:", "STARTTLS")
        st, _ = smtp_read()
        if st == -1:
            raise ProbeError(
                "STARTTLS reply is malformed: its continuation lines carry different reply codes, so the upgrade "
                "was not attempted."
            )
        if st != 220:
            raise ProbeError(f"STARTTLS returned {st}.")
    elif s == Service.IMAP_STARTTLS:
        greeting = c.read_line()
        log("S:", greeting)
        if not greeting.startswith("* OK"):
            raise ProbeError("Unexpected IMAP greeting.")
        c.write("a1 STARTTLS\r\n")
        log("C:", "a1 STARTTLS")
        for _ in range(100):
            line = c.read_line()
            log("S:", line)
            if line.upper().startswith("* BYE"):
                raise ProbeError(f"IMAP server closed the session: {wire.sanitize(line)}")
            if line.startswith("a1 "):
                if not line.upper().startswith("A1 OK"):
                    raise ProbeError(f"IMAP STARTTLS refused: {wire.sanitize(line)}")
                break
        else:
            raise ProbeError("IMAP reply too long")
    elif s == Service.POP3_STARTTLS:
        greeting = c.read_line()
        log("S:", greeting)
        if not greeting.startswith("+OK"):
            raise ProbeError("Unexpected POP3 greeting.")
        c.write("STLS\r\n")
        log("C:", "STLS")
        line = c.read_line()
        log("S:", line)
        if not line.startswith("+OK"):
            raise ProbeError(f"POP3 STLS refused: {wire.sanitize(line)}")
    elif s == Service.LDAP_STARTTLS:
        c.write(wire.ldap_starttls_request())
        log("C:", f"ExtendedRequest StartTLS ({wire.LDAP_STARTTLS_OID})")
        head = c.read(2)
        n, len_bytes = head[1], b""
        if n & 0x80:
            k = n & 0x7F
            if k > 4:
                raise ProbeError("Bad LDAP response")
            len_bytes = c.read(k)
            n = int.from_bytes(len_bytes, "big")
        if n >= 65_536:
            raise ProbeError("LDAP response too large")
        result = wire.ldap_extended_result_code(head + len_bytes + c.read(n))
        if result is None:
            raise ProbeError("Server did not return an LDAP ExtendedResponse.")
        log("S:", f"ExtendedResponse resultCode {result}")
        if result != 0:
            raise ProbeError(
                f"LDAP StartTLS refused (resultCode {result}). Port 389 may require LDAPS on 636, or the DC has no "
                "certificate."
            )
    elif s == Service.MYSQL:
        h = c.read(4)
        n = h[0] | h[1] << 8 | h[2] << 16
        if n >= 65_536:
            raise ProbeError("MySQL greeting too large")
        try:
            g = wire.parse_mysql_greeting(c.read(n))
        except wire.WireError as e:
            raise ProbeError(str(e)) from None
        log("S:", f"MySQL greeting, server {g.version}, TLS {'supported' if g.supports_tls else 'not offered'}")
        if not g.supports_tls:
            raise ProbeError(f"MySQL server {g.version} does not offer TLS (CLIENT_SSL not set).")
        c.write(wire.mysql_ssl_request())
        log("C:", "SSLRequest")
    elif s == Service.RDP:
        c.write(wire.rdp_connection_request())
        log("C:", "X.224 Connection Request, RDP_NEG_REQ PROTOCOL_SSL|PROTOCOL_HYBRID (no cookie, no credentials)")
        try:
            neg = wire.rdp_parse_confirm(c.read(wire.tpkt_length(c.read(4))))
        except wire.WireError as e:
            raise ProbeError(str(e)) from None
        log("S:", wire.rdp_describe(neg))
        r.negotiation = wire.rdp_findings(neg)
        if not wire.rdp_starts_tls(neg):
            raise ProbeError(wire.rdp_describe(neg))


def run(
    t: Target,
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
    now: dt.datetime | None = None,
    anchors: Path | None = None,
    context: ssl.SSLContext | None = None,
    policy: TargetPolicy | None = None,
    nameservers: list[str] | None = None,
) -> ProbeResult:
    r = ProbeResult(target=t)
    start = time.monotonic()
    deadline = start + timeout  # one overall budget: lookup, every connect attempt, upgrade and handshake

    def left() -> float:
        rest = deadline - time.monotonic()
        if rest <= 0:
            raise TimeoutError(f"Timed out after {timeout:g} s")
        return rest

    when = now or dt.datetime.now(dt.UTC)
    try:
        t.validate()
        addrs, r.resolver = resolve(t, policy, timeout=min(left(), RESOLVE_TIMEOUT_S))
        sni = None if _is_ip(t.server_name) else t.server_name
        ders: list[bytes] = []
        last: Exception | None = None
        # One attempt per resolved address, in resolver order; stop at the first TCP connect that
        # succeeds. A TLS or upgrade failure after connecting is final (no retry on the next address).
        # The connect budget is split across the addresses still to try (review S9), so one black-holed
        # address cannot use up the whole deadline before a working fallback gets its turn. Whatever a
        # successful connect leaves unused stays available to the upgrade and handshake.
        for i, ip in enumerate(addrs):
            r.connected_ip = ip
            try:
                raw = socket.create_connection((ip, t.port), timeout=left() / (len(addrs) - i))
            except OSError as e:
                r.transcript.append(f"Connect to {ip}:{t.port} failed: {e}")
                last = e
                continue
            with raw:
                r.transcript.append(f"Connected to {ip}:{t.port} ({r.resolver})")
                if t.service.uses_upgrade:
                    c = _Reader(raw, deadline)
                    upgrade(c, t, r)
                    # CVE-2011-0411 class: plaintext sent after the go-ahead would be read as protected data.
                    if n := c.pending():
                        raise ProbeError(
                            f"Server sent {n} unexpected bytes before the TLS handshake (possible STARTTLS injection)."
                        )
                raw.settimeout(left())
                with (context or default_context()).wrap_socket(raw, server_hostname=sni) as s:
                    r.transcript.append(f"TLS handshake complete (SNI {sni or 'none'})")
                    r.tls_version = s.version()
                    ci = s.cipher()
                    r.cipher = ci[0] if ci else None
                    ders = presented_chain(s)
            last = None
            break
        if last is not None:
            raise last
        if not ders:
            raise ssl.SSLError("No certificate received.")
        r.chain = [parse_cert(d) for d in ders]
        r.duration_s = time.monotonic() - start
        r.trust, f = assess(r.chain, t, tls_version=r.tls_version, now=when, anchors=anchors)
        f += address_findings(r, f, nameservers)
        r.findings = sort_findings(r.negotiation + f)
    except (OSError, ValueError, ssl.SSLError, ProbeError) as e:
        r.duration_s = time.monotonic() - start
        r.error = str(e) or type(e).__name__
        if isinstance(e, ProbeError):
            probe = Finding("probe", Severity.FAIL, Topic.START_TLS, "TLS upgrade failed", r.error)
        else:
            title = f"Could not complete TLS to {t.endpoint}"
            probe = Finding("probe", Severity.FAIL, Topic.CONNECTION, title, r.error)
        if any(n.severity == Severity.FAIL for n in r.negotiation):
            out = list(r.negotiation)
        else:
            out = [*r.negotiation, probe, *adjust.handshake_failure_notes(t)]
        r.findings = out + address_findings(r, out, nameservers)
    return r


def assess(
    chain: list[Cert], t: Target, *, tls_version: str | None, now: dt.datetime, anchors: Path | None = None
) -> tuple[trust.TrustResult, list[Finding]]:
    """The post-handshake verdict (Probe.runSync): analysis, trust, tlsver, then the service adjusters."""
    f = analysis.evaluate(chain, t.expected_name, Purpose.TLS_SERVER, now=now)
    tr = trust.verify(
        analysis.ordered_chain(chain),
        hostname=t.expected_name,
        purpose=Purpose.TLS_SERVER,
        now=now,
        anchors=anchors,
    )
    f.append(trust.finding(tr, "as presented by server"))
    if tls_version is None:
        f.append(Finding("tlsver", Severity.INFO, Topic.GENERAL, "TLS version not determined"))
    elif tls_version in ("TLSv1", "TLSv1.1"):
        f.append(
            Finding(
                "tlsver",
                Severity.WARNING,
                Topic.GENERAL,
                f"Server negotiated {tls_version}",
                "Disable TLS 1.0/1.1 on the service.",
            )
        )
    f = adjust.apply_all(f, chain, t, tls_version=tls_version, now=now, anchors=anchors)
    return tr, f


def address_findings(r: ProbeResult, existing: list[Finding], ns: list[str] | None = None) -> list[Finding]:
    """Connected-address note, the split-DNS warning and the firewall hint (Probe.addressFindings)."""
    t = r.target
    out: list[Finding] = []
    if r.connected_ip:
        out.append(
            Finding(
                "connected-ip",
                Severity.INFO,
                Topic.CONNECTION,
                f"Connected to {r.connected_ip}",
                f"Address used for {t.host}: {r.connected_ip} ({r.resolver}). "
                f"SNI and the expected name stay {t.server_name} / {t.expected_name}.",
            )
        )
    addrs = [r.connected_ip] if r.connected_ip else []
    warn = None
    if addrs:
        warn = hints.split_dns_warning(t.host, addrs, r.resolver, hints.nameservers() if ns is None else ns)
    if warn:
        out.append(warn)
    if h := hints.firewall_hint(existing, warn):
        out.append(h)
    return out


def openssl_command(t: Target) -> str:
    """Copy-only equivalent command. Never executed."""
    import shlex

    q = shlex.quote
    if t.service == Service.RDP:  # openssl s_client cannot do the X.224 negotiation; nmap's ssl-cert can
        cmd = f"nmap -Pn -p {t.port} --script rdp-enum-encryption,ssl-cert {q(t.connect_ip or t.host)}"
        return cmd + (f" --script-args tls.servername={q(t.server_name)}" if t.connect_ip else "")
    ep = f"{t.connect_ip or t.host}:{t.port}"
    cmd = (
        f"openssl s_client -connect {q(ep)} -servername {q(t.server_name)} "
        f"-showcerts -verify_hostname {q(t.expected_name)}"
    )
    if st := t.service.openssl_starttls:
        cmd += f" -starttls {st}"
    return cmd + " </dev/null"


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
    except ValueError:
        return False
    return True
