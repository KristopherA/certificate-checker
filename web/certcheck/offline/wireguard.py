"""Offline WireGuard configuration checks (WireGuard.swift): wg-quick .conf and pfSense config.xml.

Private keys are decoded only to derive the public key; the secret is never stored in these types, never placed in
findings and never printed."""

from __future__ import annotations

import base64
import binascii
import dataclasses
import enum
import socket
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from xml.parsers import expat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from ..model import Finding, Severity, Topic, sort_findings
from ..radius import valid_host

MAX_FILE_SIZE = 20 * 1024 * 1024
OPTIONAL_FIELDS = frozenset({"DNS", "MTU", "PersistentKeepalive"})
CANONICAL = {
    "privatekey": "PrivateKey", "address": "Address", "dns": "DNS", "listenport": "ListenPort", "mtu": "MTU",
    "publickey": "PublicKey", "presharedkey": "PresharedKey", "allowedips": "AllowedIPs", "endpoint": "Endpoint",
    "persistentkeepalive": "PersistentKeepalive",
}  # fmt: skip
XML_REFUSED = "XML with a DOCTYPE or ENTITY declaration is refused (pfSense exports never contain one)."


class Kind(enum.StrEnum):
    KEY = "key"
    PEER = "peer"
    ALLOWED = "allowed"
    ENDPOINT = "endpoint"
    CONSISTENCY = "consistency"
    INFO = "info"


@dataclass(frozen=True)
class KeyStatus:
    """valid / notBase64 / wrongLength(n) / nonCanonical."""

    name: str
    length: int = 0

    def describe(self) -> str:
        return {
            "valid": "valid",
            "notBase64": "not valid base64",
            "wrongLength": f"decodes to {self.length} bytes, not 32",
            "nonCanonical": "is not canonical base64 (44 characters ending in '=')",
        }[self.name]


VALID = KeyStatus("valid")


def decode(s: str) -> tuple[KeyStatus, bytes | None]:
    t = s.strip(" \t")
    try:
        d = base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return KeyStatus("notBase64"), None
    if len(d) != 32:
        return KeyStatus("wrongLength", len(d)), None
    if base64.b64encode(d).decode() != t:
        return KeyStatus("nonCanonical"), None
    return VALID, d


def public_key(private: str) -> tuple[KeyStatus, str | None]:
    """Base64 public key derived from a private key string; the private value is not retained."""
    st, raw = decode(private)
    if st != VALID or raw is None:
        return st, None
    pub = x25519.X25519PrivateKey.from_private_bytes(raw).public_key()
    return VALID, base64.b64encode(
        pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()


@dataclass
class WGPeer:
    name: str
    public_key: str | None = None
    preshared_key_status: KeyStatus | None = None  # None = no PSK; the PSK itself is not kept
    allowed_ips: list[str] = field(default_factory=list)
    endpoint: str | None = None
    empty_fields: list[str] = field(default_factory=list)


@dataclass
class WGConfig:
    name: str
    source: str
    private_key_status: KeyStatus | None = None
    derived_public_key: str | None = None
    stated_public_key: str | None = None
    addresses: list[str] = field(default_factory=list)
    listen_port: str | None = None
    peers: list[WGPeer] = field(default_factory=list)
    empty_fields: list[str] = field(default_factory=list)


def _strip(s: str) -> str:
    return s.strip(" \t")


def wg_quick(text: str, name: str) -> WGConfig:
    """wg-quick INI format. Unknown keys are ignored; key names are case-insensitive."""
    c = WGConfig(name, "wg-quick")
    section = ""
    peer: WGPeer | None = None
    peer_count = 0
    pending: str | None = None
    for raw in text.splitlines():
        line = _strip(raw)
        if line.startswith("#"):
            body = _strip(line[1:])
            if "=" in body and _strip(body.split("=", 1)[0]).lower() == "name":
                v = _strip(body.split("=", 1)[1])
                if section == "peer" and peer is not None and peer.name.startswith("Peer "):
                    peer.name = v
                else:
                    pending = v
            continue
        if "#" in line:
            line = _strip(line.split("#", 1)[0])
        if not line:
            continue
        if line.startswith("["):
            if peer is not None:
                c.peers.append(peer)
            peer = None
            section = line.lower().strip("[]")
            if section == "peer":
                peer_count += 1
                peer = WGPeer(pending or f"Peer {peer_count}")
                pending = None
            continue
        if "=" not in line:
            continue
        k, value = line.split("=", 1)
        key, value = _strip(k).lower(), _strip(value)
        if not value and key in CANONICAL:
            if section == "interface":
                c.empty_fields.append(CANONICAL[key])
            elif section == "peer" and peer is not None:
                peer.empty_fields.append(CANONICAL[key])
            continue
        items = [x for x in (_strip(v) for v in value.split(",")) if x]
        if section == "interface":
            if key == "privatekey":
                c.private_key_status, c.derived_public_key = public_key(value)
            elif key == "address":
                c.addresses += items
            elif key == "listenport":
                c.listen_port = value
        elif section == "peer" and peer is not None:
            if key == "publickey":
                peer.public_key = value
            elif key == "presharedkey":
                peer.preshared_key_status = decode(value)[0]
            elif key == "allowedips":
                peer.allowed_ips += items
            elif key == "endpoint":
                peer.endpoint = value
    if peer is not None:
        c.peers.append(peer)
    return c


def _info(fid: str, title: str, detail: str = "", sev: Severity = Severity.INFO) -> Finding:
    return Finding(fid, sev, Topic.WIREGUARD, title, detail, kind="info")


MAX_XML_DEPTH = 1000  # pfSense config.xml nests about 10 deep; anything far deeper is refused (review B2)


def parse_xml(data: bytes) -> ET.Element:
    """pfSense XML parsed by expat directly into an ElementTree, failing closed.

    DOCTYPE/ENTITY are refused twice: by a text check up front, and at the expat level (a doctype or entity
    declaration handler that raises, parameter entities never parsed; review S5), so no DTD reaches the tree.
    Nesting deeper than MAX_XML_DEPTH and any RecursionError are refused too (review B2)."""
    lower = data.decode("utf-8", "replace").lower()
    if "<!doctype" in lower or "<!entity" in lower:
        raise ValueError(XML_REFUSED)
    tb = ET.TreeBuilder()
    depth = 0

    def refuse(*_: object) -> None:
        raise ValueError(XML_REFUSED)

    def start(tag: str, attrs: dict[str, str]) -> None:
        nonlocal depth
        depth += 1
        if depth > MAX_XML_DEPTH:
            raise ValueError(f"The XML nests deeper than {MAX_XML_DEPTH} levels and is refused.")
        tb.start(tag, attrs)

    def end(tag: str) -> None:
        nonlocal depth
        depth -= 1
        tb.end(tag)

    px = expat.ParserCreate()
    px.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    px.StartDoctypeDeclHandler = refuse
    px.EntityDeclHandler = refuse
    px.UnparsedEntityDeclHandler = refuse
    px.NotationDeclHandler = refuse
    px.ExternalEntityRefHandler = refuse  # type: ignore[assignment]
    px.StartElementHandler = start
    px.EndElementHandler = end
    px.CharacterDataHandler = tb.data
    try:
        px.Parse(data, True)
        return tb.close()
    except expat.ExpatError as e:
        raise ValueError(f"The XML could not be parsed: {e}.") from None
    except RecursionError:
        raise ValueError("The XML nests too deeply and is refused.") from None


def xml_text(n: ET.Element, path: str) -> str | None:
    """First match's string value, trimmed; None when missing or empty (XMLNode.stringValue)."""
    m = n.find(path)
    if m is None:
        return None
    v = "".join(m.itertext()).strip()
    return v or None


def pfsense(data: bytes, name: str) -> tuple[list[WGConfig], list[Finding]]:
    """One WGConfig per enabled tunnel, peers grouped by <tun>; disabled or unassigned entries are info notes."""
    root = parse_xml(data)

    def all_(path: str) -> list[ET.Element]:
        # XPath //wireguard/tunnels/item: the root itself may be <wireguard>.
        hits = root.findall(f".//{path}")
        head, _, rest = path.partition("/")
        if root.tag == head:
            hits = root.findall(rest) + hits
        return hits

    def enabled(n: ET.Element) -> bool:
        return (xml_text(n, "enabled") or "").lower() == "yes"

    def rows(n: ET.Element, path: str) -> list[str]:
        out = []
        for r in n.findall(path):
            a = xml_text(r, "address")
            if a is not None:
                m = xml_text(r, "mask")
                out.append(a + (f"/{m}" if m is not None else ""))
        return out

    configs: list[WGConfig] = []
    notes: list[Finding] = []
    tunnels = all_("wireguard/tunnels/item")
    peers = all_("wireguard/peers/item")
    active: set[str] = set()
    for t in tunnels:
        tun = xml_text(t, "name") or "tun_wg?"
        if not enabled(t):
            notes.append(_info(f"wg-disabled-{tun}", f"{name} › {tun} is disabled; skipped"))
            continue
        active.add(tun)
        c = WGConfig(f"{name} › {tun}", "pfSense config.xml")
        if (pk := xml_text(t, "privatekey")) is not None:
            c.private_key_status, c.derived_public_key = public_key(pk)
        c.stated_public_key = xml_text(t, "publickey")
        c.listen_port = xml_text(t, "listenport")
        c.addresses = rows(t, "addresses/row")
        configs.append(c)
    names = {xml_text(t, "name") for t in tunnels}
    for pi, p in enumerate(peers):
        descr = xml_text(p, "descr") or f"peer #{pi + 1}"
        tun = xml_text(p, "tun") or "unassigned"
        if tun == "unassigned" or tun not in names:
            notes.append(
                _info(
                    f"wg-unassigned-{pi}",
                    f"{name}: peer {descr} is not assigned to a tunnel",
                    "Assign it in VPN › WireGuard › Peers or delete it.",
                )
            )
            continue
        if tun not in active:
            continue
        if not enabled(p):
            notes.append(_info(f"wg-disabled-peer-{pi}", f"{name} › {tun}: peer {descr} is disabled; skipped"))
            continue
        peer = WGPeer(descr, xml_text(p, "publickey"))
        if (psk := xml_text(p, "presharedkey")) is not None:
            peer.preshared_key_status = decode(psk)[0]
        peer.allowed_ips = rows(p, "allowedips/row")
        if (host := xml_text(p, "endpoint")) is not None:
            port = xml_text(p, "port") or "51820"
            peer.endpoint = f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"
        for c in configs:
            if c.name == f"{name} › {tun}":
                c.peers.append(peer)
                break
    if not configs and not notes:
        raise ValueError(
            "No WireGuard tunnels found in this pfSense configuration (expected installedpackages › wireguard › tunnels)."
        )
    return configs, notes


def load(name: str, data: bytes) -> tuple[list[WGConfig], list[Finding]]:
    text = data.decode("utf-8", "replace")
    low = text.lower()
    if "<pfsense" in text or "<wireguard" in text or "<!doctype" in low or "<!entity" in low:
        return pfsense(data, name)
    if "[interface]" not in low and "[peer]" not in low:
        raise ValueError("Not a wg-quick configuration or pfSense config.xml.")
    return [wg_quick(text, name)], []


@dataclass(frozen=True)
class CIDR:
    raw: bytes
    bits: int

    @staticmethod
    def parse(s: str) -> CIDR | None:
        parts = _strip(s).split("/")
        if len(parts) > 2 or not parts[0]:
            return None
        ip = parts[0]
        raw = None
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                raw = socket.inet_pton(fam, ip)
                break
            except (OSError, ValueError):
                continue
        if raw is None:
            return None
        mx = len(raw) * 8
        if len(parts) == 2:
            m = parts[1]
            if not m or len(m) > 3 or not all(c.isascii() and c.isdigit() for c in m) or not 0 <= int(m) <= mx:
                return None
            return CIDR(raw, int(m))
        return CIDR(raw, mx)

    def bit(self, i: int) -> int:
        return (self.raw[i // 8] >> (7 - i % 8)) & 1

    @property
    def is_full_length(self) -> bool:
        return self.bits == len(self.raw) * 8

    @property
    def is_default_route(self) -> bool:
        return self.bits == 0

    @property
    def host_bits_set(self) -> bool:
        return any(self.bit(i) for i in range(self.bits, len(self.raw) * 8))

    def overlaps(self, o: CIDR) -> bool:
        return len(self.raw) == len(o.raw) and all(self.bit(i) == o.bit(i) for i in range(min(self.bits, o.bits)))

    def same_network(self, o: CIDR) -> bool:
        return self.bits == o.bits and self.overlaps(o)

    def same_address(self, o: CIDR) -> bool:
        return self.raw == o.raw


def _wg(fid: str, s: Severity, kind: Kind, title: str, detail: str = "") -> Finding:
    return Finding(fid, s, Topic.WIREGUARD, title, detail, kind=kind.value)


def short(k: str) -> str:
    return k[:8] + "…"


def _digits(s: str) -> bool:
    return all(c.isascii() and c.isdigit() for c in s)


def endpoint_problem(e: str) -> str | None:
    if e.startswith("["):
        close = e.find("]")
        if close < 0:
            return "IPv6 endpoint is missing ']'"
        host, rest = e[1:close], e[close + 1 :]
        if not rest.startswith(":"):
            return f"Endpoint needs a port, e.g. [{host}]:51820"
        port = rest[1:]
        try:
            socket.inet_pton(socket.AF_INET6, host)
        except (OSError, ValueError):
            return f"'{host}' is not an IPv6 address"
    else:
        colon = e.rfind(":")
        if colon < 0:
            return f"Endpoint needs a port, e.g. {e}:51820"
        host, port = e[:colon], e[colon + 1 :]
        if ":" in host:
            return f"IPv6 endpoints must use brackets, e.g. [{host}]:{port}"
        if not valid_host(host):
            return f"'{host}' is not a valid host name or address"
    if not port or len(port) > 5 or not _digits(port) or not 1 <= int(port) <= 65535:
        return f"Port '{port}' must be digits only, 1–65535"
    return None


def evaluate(configs: list[WGConfig], expected_public_key: str | None = None) -> list[Finding]:
    """All checks (WGCheck.evaluate). `expected_public_key` optionally pins the local interface key."""
    out: list[Finding] = []
    many = len(configs) > 1
    for ci, c in enumerate(configs):
        p = f"wg{ci}-"
        label = f"{c.name}: " if many else ""
        for fl in c.empty_fields:
            kind = Kind.KEY if fl == "PrivateKey" else Kind.ALLOWED if fl == "Address" else Kind.CONSISTENCY
            out.append(
                _wg(
                    p + f"empty-{fl}",
                    Severity.WARNING if fl in OPTIONAL_FIELDS else Severity.FAIL,
                    kind,
                    f"{label}[Interface] {fl} is empty",
                    f"The line '{fl} =' has no value. Fill it in, or remove the line if the setting is not needed.",
                )
            )
        st = c.private_key_status
        if st is None:
            out.append(
                _wg(
                    p + "key-priv",
                    Severity.INFO,
                    Kind.KEY,
                    f"{label}No interface private key in this file",
                    "Only peer checks can run. Public-key derivation needs the private key, which stays in memory.",
                )
            )
        elif st == VALID:
            out.append(
                _wg(
                    p + "key-priv",
                    Severity.PASS,
                    Kind.KEY,
                    f"{label}Interface private key is a valid Curve25519 key",
                    f"Derived public key: {c.derived_public_key or '?'}",
                )
            )
        else:
            out.append(
                _wg(
                    p + "key-priv",
                    Severity.FAIL,
                    Kind.KEY,
                    f"{label}Interface private key {st.describe()}",
                    "A WireGuard key is 32 bytes encoded as 44 base64 characters.",
                )
            )
        if (stated := c.stated_public_key) is not None:
            sst = decode(stated)[0]
            if sst != VALID:
                out.append(_wg(p + "key-pub", Severity.FAIL, Kind.KEY, f"{label}Stated public key {sst.describe()}"))
            elif (d := c.derived_public_key) is not None:
                if d == stated:
                    out.append(
                        _wg(p + "key-pub", Severity.PASS, Kind.KEY, f"{label}Stated public key matches the private key")
                    )
                else:
                    out.append(
                        _wg(
                            p + "key-pub",
                            Severity.FAIL,
                            Kind.KEY,
                            f"{label}Stated public key does not match the private key",
                            f"Stated {short(stated)}, derived {short(d)}. Peers configured with the stated key will fail the handshake.",
                        )
                    )
        exp = _strip(expected_public_key or "")
        if exp:
            derived_ok = c.derived_public_key if c.private_key_status == VALID else None
            stated_ok = (
                c.stated_public_key
                if c.stated_public_key is not None and decode(c.stated_public_key)[0] == VALID
                else None
            )
            ref = derived_ok or stated_ok
            if ref is not None:
                source = "derived" if derived_ok is not None else "stated"
                if public_key(exp)[1] == ref:
                    # The supplied value is this interface's PRIVATE key. Never echo it.
                    out.append(
                        _wg(
                            p + "key-expected",
                            Severity.FAIL,
                            Kind.KEY,
                            f"{label}The expected key looks like a private key",
                            "It derives this interface's public key. Pass the public key instead, and treat the value you entered as exposed if it was shared.",
                        )
                    )
                elif ref == exp:
                    out.append(
                        _wg(
                            p + "key-expected",
                            Severity.PASS,
                            Kind.KEY,
                            f"{label}Interface key matches the expected public key",
                            "Compared with the stated public key; the file has no private key to derive from."
                            if source == "stated"
                            else "",
                        )
                    )
                else:
                    out.append(
                        _wg(
                            p + "key-expected",
                            Severity.FAIL,
                            Kind.KEY,
                            f"{label}Interface key does not match the expected public key",
                            f"Expected {short(exp)}, {source} {short(ref)}.",
                        )
                    )
            else:
                out.append(
                    _wg(
                        p + "key-expected",
                        Severity.INFO,
                        Kind.KEY,
                        f"{label}Expected public key not checked",
                        "This file has no valid private or stated public key for the interface, so --expect-public cannot be compared.",
                    )
                )
        if_addrs = [x for x in (CIDR.parse(a) for a in c.addresses) if x is not None]
        for a in c.addresses:
            if CIDR.parse(a) is None:
                out.append(
                    _wg(
                        p + f"addr-{a}",
                        Severity.FAIL,
                        Kind.ALLOWED,
                        f"{label}Interface Address '{a}' is not a valid IP/prefix",
                    )
                )
        if not c.peers:
            out.append(_wg(p + "peer-none", Severity.WARNING, Kind.PEER, f"{label}No peers configured"))
        seen: dict[str, str] = {}
        nets: list[tuple[int, str, str, CIDR]] = []
        for pi, peer in enumerate(c.peers):
            who = f"{label}{peer.name}"
            pp = p + f"peer{pi}-"
            for fl in peer.empty_fields:
                k = (
                    Kind.PEER
                    if fl in ("PublicKey", "PresharedKey")
                    else Kind.ALLOWED
                    if fl == "AllowedIPs"
                    else Kind.ENDPOINT
                    if fl == "Endpoint"
                    else Kind.CONSISTENCY
                )
                out.append(
                    _wg(
                        pp + f"empty-{fl}",
                        Severity.WARNING if fl in OPTIONAL_FIELDS else Severity.FAIL,
                        k,
                        f"{who}: [Peer] {fl} is empty",
                        f"The line '{fl} =' has no value. Fill it in, or remove the line if the setting is not needed.",
                    )
                )
            if (pk := peer.public_key) is not None:
                kst = decode(pk)[0]
                if kst != VALID:
                    out.append(_wg(pp + "key", Severity.FAIL, Kind.PEER, f"{who}: public key {kst.describe()}"))
                else:
                    if pk in seen:
                        out.append(
                            _wg(
                                pp + "dup",
                                Severity.FAIL,
                                Kind.PEER,
                                f"{who}: duplicate peer key",
                                f"Same public key as {seen[pk]} ({short(pk)}). WireGuard keeps only one; remove the duplicate.",
                            )
                        )
                    seen[pk] = peer.name
                    if pk in (c.derived_public_key, c.stated_public_key):
                        out.append(
                            _wg(
                                pp + "self",
                                Severity.FAIL,
                                Kind.PEER,
                                f"{who}: peer key equals this interface's own key",
                                "A peer must be the remote side's public key. Copy the key from the other end.",
                            )
                        )
            else:
                out.append(_wg(pp + "key", Severity.FAIL, Kind.PEER, f"{who}: no PublicKey"))
            ps = peer.preshared_key_status
            if ps is not None and ps != VALID:
                out.append(
                    _wg(
                        pp + "psk",
                        Severity.FAIL,
                        Kind.PEER,
                        f"{who}: PresharedKey {ps.describe()}",
                        "Generate one with wg genpsk; both ends must use the same value.",
                    )
                )
            if not peer.allowed_ips and "AllowedIPs" not in peer.empty_fields:
                out.append(
                    _wg(
                        pp + "allowed",
                        Severity.WARNING,
                        Kind.ALLOWED,
                        f"{who}: no AllowedIPs",
                        "No traffic will be routed to or accepted from this peer.",
                    )
                )
            for a in peer.allowed_ips:
                cidr = CIDR.parse(a)
                if cidr is None:
                    out.append(
                        _wg(
                            pp + f"allowed-{a}",
                            Severity.FAIL,
                            Kind.ALLOWED,
                            f"{who}: AllowedIPs entry '{a}' is not a valid IP/prefix",
                        )
                    )
                    continue
                if cidr.host_bits_set:
                    out.append(
                        _wg(
                            pp + f"hostbits-{a}",
                            Severity.WARNING,
                            Kind.ALLOWED,
                            f"{who}: AllowedIPs {a} has host bits set",
                            "WireGuard masks this to the network address; write the network form to avoid confusion.",
                        )
                    )
                if cidr.is_full_length and any(x.same_address(cidr) for x in if_addrs):
                    out.append(
                        _wg(
                            pp + f"ownaddr-{a}",
                            Severity.FAIL,
                            Kind.ALLOWED,
                            f"{who}: AllowedIPs {a} is this interface's own address",
                            "Traffic to the local tunnel address would be sent to the peer. Use the peer's own tunnel address.",
                        )
                    )
                for npeer, nname, ntext, ncidr in nets:
                    if npeer == pi or not ncidr.overlaps(cidr):
                        continue
                    same = ncidr.same_network(cidr)
                    full = not same and (ncidr.is_default_route or cidr.is_default_route)
                    sev = Severity.FAIL if same else Severity.INFO if full else Severity.WARNING
                    detail = (
                        "Cryptokey routing assigns a prefix to one peer only; the later peer silently takes it over." if same
                        else "One peer carries the full tunnel; more specific prefixes on other peers take precedence, which is usually intended." if full
                        else "The more specific prefix wins for routing; confirm this is intended."
                    )  # fmt: skip
                    out.append(
                        _wg(
                            pp + f"overlap-{a}-{npeer}-{ntext}",
                            sev,
                            Kind.ALLOWED,
                            f"{who}: AllowedIPs {a} {'duplicates' if same else 'overlaps'} {nname}'s {ntext}",
                            detail,
                        )
                    )
                nets.append((pi, peer.name, a, cidr))
            if peer.endpoint is not None and (problem := endpoint_problem(peer.endpoint)) is not None:
                out.append(_wg(pp + "endpoint", Severity.FAIL, Kind.ENDPOINT, f"{who}: invalid Endpoint", problem))
        if c.peers and not any(x.id.startswith(p + "peer") and x.severity >= Severity.WARNING for x in out):
            n = len(c.peers)
            out.append(
                _wg(
                    p + "peers-ok",
                    Severity.PASS,
                    Kind.PEER,
                    f"{label}{n} peer{'' if n == 1 else 's'}: keys, AllowedIPs and endpoints are consistent",
                )
            )
    if many:
        for i, ca in enumerate(configs):
            for j, cb in enumerate(configs):
                if i >= j:
                    continue
                ka = ca.derived_public_key or ca.stated_public_key
                kb = cb.derived_public_key or cb.stated_public_key
                if ka is None or kb is None:
                    continue
                a_b = any(x.public_key == kb for x in ca.peers)
                b_a = any(x.public_key == ka for x in cb.peers)
                if a_b and b_a:
                    out.append(
                        _wg(
                            f"x-{i}-{j}",
                            Severity.PASS,
                            Kind.CONSISTENCY,
                            f"{ca.name} and {cb.name} list each other's public keys",
                        )
                    )
                elif a_b or b_a:
                    missing, key = (cb.name, ka) if a_b else (ca.name, kb)
                    out.append(
                        _wg(
                            f"x-{i}-{j}",
                            Severity.FAIL,
                            Kind.CONSISTENCY,
                            f"Peer key mismatch between {ca.name} and {cb.name}",
                            f"{missing} does not list the other side's public key {short(key)}. One side was probably re-keyed.",
                        )
                    )
    return sort_findings(out)


def inspect_data(
    items: list[tuple[str, bytes]], expected_public_key: str | None = None
) -> tuple[list[WGConfig], list[Finding]]:
    configs: list[WGConfig] = []
    notes: list[Finding] = []
    for name, data in items:
        try:
            if len(data) > MAX_FILE_SIZE:
                raise ValueError("File is larger than 20 MB.")
            cs, ns = load(name, data)
            configs += cs
            notes += ns
        except (ValueError, RecursionError) as e:  # RecursionError: fail closed on any too-deep input (review B2)
            why = "The file nests too deeply and is refused." if isinstance(e, RecursionError) else str(e)
            notes.append(_info(f"wg-read-{name}", f"Could not read {name}", why, Severity.FAIL))
    return configs, sort_findings(notes + evaluate(configs, expected_public_key))


def inspect(paths: list[Path], expected_public_key: str | None = None) -> tuple[list[WGConfig], list[Finding]]:
    from ..radius import read_files

    items, pre = read_files(paths, MAX_FILE_SIZE, "20 MB", Topic.WIREGUARD)
    notes = [dataclasses.replace(n, id="wg-" + n.id) for n in pre]  # wg-read-NAME, as on the Mac
    configs, findings = inspect_data(items, expected_public_key)
    return configs, sort_findings(notes + findings)
