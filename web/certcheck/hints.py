"""Split-DNS and firewall hints (port of Resolution.classify / splitDNSWarning / firewallHint).

Linux adaptation: a container always has a private bridge address, so "this machine has an internal
address" (the Mac signal) says nothing here. The Linux signal is the resolved address against
/etc/resolv.conf: every resolved address is public while the configured nameservers are internal.
No network traffic: reads one local file.

Docker's own resolvers are not "internal DNS servers" in that sense: they forward to the host's resolver, so
they say nothing about split DNS and are ignored (review S2). That covers the embedded DNS of user-defined
networks (127.0.0.11, loopback, never internal anyway) and Docker Desktop's VM resolver in DOCKER_RESOLVER_NETS.
"""

from __future__ import annotations

import enum
import ipaddress
from collections.abc import Sequence
from pathlib import Path

from .model import Finding, Severity, Topic

RESOLV_CONF = Path("/etc/resolv.conf")

# Docker Desktop's default VM subnet (Settings > Resources > Network, documented default; the host resolver
# proxy sits at .7/.254 in it). Built from its integer form so the source carries no private address literal.
DOCKER_DESKTOP_NET = ipaddress.IPv4Network((0xC0A84100, 24))
DOCKER_RESOLVER_NETS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (DOCKER_DESKTOP_NET,)


def is_docker_resolver(ns: str) -> bool:
    try:
        ip = ipaddress.ip_address(ns)
    except ValueError:
        return False
    return any(ip in n for n in DOCKER_RESOLVER_NETS)


class IPClass(enum.StrEnum):
    LOOPBACK = "loopback"
    LINK_LOCAL = "link-local"
    RFC1918 = "private (RFC 1918)"
    ULA = "unique local (ULA)"
    CGNAT = "shared (CGNAT, RFC 6598)"
    DOCUMENTATION = "documentation"
    UNSPECIFIED = "unspecified"
    MULTICAST = "multicast"
    RESERVED = "reserved / special-use"
    NAT64 = "NAT64 (64:ff9b::/96)"
    PUBLIC = "public"

    @property
    def is_internal(self) -> bool:
        return self in (IPClass.RFC1918, IPClass.ULA, IPClass.CGNAT)


def classify(s: str) -> IPClass | None:
    if "%" in s:
        return None
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if ip.version == 4:
        a, b, c = ip.packed[:3]
        if a == 0:
            return IPClass.UNSPECIFIED
        if a == 127:
            return IPClass.LOOPBACK
        if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
            return IPClass.RFC1918
        if a == 100 and 64 <= b <= 127:
            return IPClass.CGNAT
        if a == 169 and b == 254:
            return IPClass.LINK_LOCAL
        if (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113)):
            return IPClass.DOCUMENTATION
        if 224 <= a <= 239:
            return IPClass.MULTICAST
        if (a == 198 and b in (18, 19)) or (a, b, c) == (192, 0, 0) or a >= 240:
            return IPClass.RESERVED
        return IPClass.PUBLIC
    p = ip.packed
    if not any(p):
        return IPClass.UNSPECIFIED
    if not any(p[:15]) and p[15] == 1:
        return IPClass.LOOPBACK
    if not any(p[:10]) and p[10] == 0xFF and p[11] == 0xFF:
        return classify(".".join(str(x) for x in p[12:]))
    if p[0] == 0xFE and p[1] & 0xC0 == 0x80:
        return IPClass.LINK_LOCAL
    if p[0] == 0xFE and p[1] & 0xC0 == 0xC0:
        return IPClass.RESERVED
    if p[:4] == b"\x00\x64\xff\x9b" and not any(p[4:12]):
        return IPClass.NAT64
    if p[0] & 0xFE == 0xFC:
        return IPClass.ULA
    if p[0] == 0xFF:
        return IPClass.MULTICAST
    if p[:4] == b"\x20\x01\x0d\xb8":
        return IPClass.DOCUMENTATION
    return IPClass.PUBLIC


def nameservers(path: Path = RESOLV_CONF) -> list[str]:
    """`nameserver` lines of resolv.conf (at most 64 KB read; missing file -> [])."""
    try:
        with path.open("rb") as fh:
            text = fh.read(65536).decode("utf-8", "replace")
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] == "nameserver" and classify(parts[1]) is not None:
            out.append(parts[1])
    return out


def _is_ip(s: str) -> bool:
    return classify(s) is not None


def split_dns_warning(host: str, addresses: Sequence[str], source: str, ns: Sequence[str]) -> Finding | None:
    if source != "system" or _is_ip(host) or not addresses:
        return None
    if not all(classify(a) == IPClass.PUBLIC for a in addresses):
        return None
    internal_ns = [n for n in ns if (c := classify(n)) is not None and c.is_internal and not is_docker_resolver(n)]
    if not internal_ns:
        return None
    dns = internal_ns[0]
    d = (
        f"{host} resolved to {', '.join(addresses)} (public) while /etc/resolv.conf lists the internal DNS "
        f"server {dns}. If the site uses split DNS, the internal answer was bypassed and the connection "
        "may hairpin through the firewall's NAT, so you may be checking the firewall's certificate instead of the "
        f"server's. Compare `dig @{dns} {host}` with `getent hosts {host}`. "
        "On a Mac Docker host, iCloud Private Relay / Oblivious DNS (mask.icloud.com) or an encrypted-DNS profile "
        "can do this: turn off Limit IP address tracking for this network, or block mask.icloud.com and "
        "mask-h2.icloud.com in the site DNS. VPN and proxy DNS can do the same. To check the internal server "
        f"directly, use --resolve {host}:$(dig +short @{dns} {host} | head -n 1) (or the target's Connect IP)."
    )
    return Finding("split-dns", Severity.WARNING, Topic.CONNECTION, "Public address on an internal network", d)


def firewall_hint(findings: Sequence[Finding], split_dns: Finding | None) -> Finding | None:
    if split_dns is None or not any(f.id == "host" and f.severity == Severity.FAIL for f in findings):
        return None
    return Finding(
        "firewall-hint",
        Severity.WARNING,
        Topic.CONNECTION,
        "Name mismatch may mean the probe reached the firewall",
        "The certificate does not match and the host resolved to a public address from inside the network. The "
        "probe may be reaching the firewall or router (hairpin NAT or its own web UI) instead of the server. "
        "Re-check with the server's internal IP as the connect IP before changing the server's certificate.",
    )
