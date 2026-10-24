"""IKEv2 IPsec certificate checks for pfSense mobile/site-to-site VPNs (IPsec.swift). Offline: no IKE packets.

Private keys (PEM files or config.xml <prv>) are parsed in memory only to derive the public half for matching.
Deviation: srvN-chain PASS needs an anchored top certificate (chaincheck.verify); the Mac passes when the top's
issuer was never supplied. See shared/known-differences.yaml."""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import ipaddress
import re
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .. import analysis, chaincheck
from ..filecheck import FileReport, pem_blocks
from ..filecheck import load as file_load
from ..model import Finding, Severity, Topic, sort_findings, unique_by
from ..radius import read_files
from ..x509info import Cert, KeyInfo, oid_name, parse_cert, private_key_facts
from .wireguard import parse_xml, xml_text

APPLE_MAX_DAYS = 825
MAX_FILE_SIZE = 20 * 1024 * 1024
SHA2_SIGNATURES = frozenset(
    {
        "1.2.840.113549.1.1.11",
        "1.2.840.113549.1.1.12",
        "1.2.840.113549.1.1.13",
        "1.2.840.10045.4.3.2",
        "1.2.840.10045.4.3.3",
        "1.2.840.10045.4.3.4",
    }
)
PSS = "1.2.840.113549.1.1.10"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
IKE_INTERMEDIATE = "1.3.6.1.5.5.8.2.2"
_B64_ALPHABET = re.compile(rb"[^A-Za-z0-9+/=]")


@dataclass(frozen=True)
class Entry:
    label: str
    cert: Cert
    refid: str | None = None
    own_key: KeyInfo | None = None  # public half of the <prv> stored with this entry


@dataclass(frozen=True)
class P1:
    index: int
    descr: str
    certref: str | None
    caref: str | None
    mobile: bool


@dataclass
class Loaded:
    entries: list[Entry] = field(default_factory=list)
    keys: list[KeyInfo] = field(default_factory=list)
    notes: list[Finding] = field(default_factory=list)
    phase1: list[P1] = field(default_factory=list)


@dataclass
class Report:
    sources: list[str] = field(default_factory=list)
    servers: list[Entry] = field(default_factory=list)
    cas: list[Entry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def f(fid: str, s: Severity, kind: str, title: str, detail: str = "") -> Finding:
    return Finding(fid, s, Topic.IPSEC, title, detail, kind=kind)


def _pem(b64: str) -> bytes | None:
    """Data(base64Encoded:options:.ignoreUnknownCharacters): drop non-alphabet bytes, then decode."""
    try:
        return base64.b64decode(_B64_ALPHABET.sub(b"", b64.encode()), validate=True)
    except (binascii.Error, ValueError):
        return None


def load(name: str, data: bytes, into: Loaded) -> None:
    head = data[:4096].decode("utf-8", "replace").lower()
    utf16 = data[:2] in (b"\xff\xfe", b"\xfe\xff")  # BOM: let expat decode it (and refuse any DTD)
    if utf16 or any(t in head for t in ("<?xml", "<pfsense", "<!doctype", "<cert>", "<ca>")):
        pfsense(data, name, into)
        return
    r = FileReport()
    file_load(name, data, r)
    into.entries += [Entry(c.display_name, c) for c in r.certificates]
    into.keys += r.keys
    into.notes += r.notes


def _with_ancestors(root: ET.Element, tag: str, excluded: str) -> list[ET.Element]:
    """XPath //tag[not(ancestor::excluded)] in document order. Iterative (review B2): no recursion depth."""
    out: list[ET.Element] = []
    stack: list[tuple[ET.Element, bool]] = [(root, False)]
    while stack:
        n, inside = stack.pop()
        if n.tag == tag and not inside:
            out.append(n)
        below = inside or n.tag == excluded
        stack.extend((ch, below) for ch in reversed(list(n)))
    return out


def _descendants(root: ET.Element, parent: str, child: str) -> list[ET.Element]:
    """XPath //parent/child in document order."""
    return [c for n in root.iter(parent) for c in n if c.tag == child]


def pfsense(data: bytes, name: str, into: Loaded) -> None:
    """<cert>/<ca> entries (base64 PEM in <crt>, key in <prv>) and the IPsec phase 1 certref/caref."""
    root = parse_xml(data)
    found = 0
    for tag in ("ca", "cert"):
        for i, n in enumerate(_with_ancestors(root, tag, "ipsec")):
            descr = xml_text(n, "descr") or f"{tag} #{i + 1}"
            crt = xml_text(n, "crt")
            if crt is None:
                if xml_text(n, "csr") is not None:
                    into.notes.append(
                        f(f"ipsec-csr-{tag}{i}", Severity.INFO, "info", f"{descr}: pending CSR, no certificate yet")
                    )
                continue
            p = _pem(crt)
            block = next((b for lab, b in pem_blocks(p) if lab.endswith("CERTIFICATE")), None) if p else None
            if block is None:
                into.notes.append(
                    f(f"ipsec-bad-{tag}{i}", Severity.FAIL, "chain", f"{descr}: <crt> is not a base64 PEM certificate")
                )
                continue
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives.serialization import Encoding

                cert = parse_cert(x509.load_pem_x509_certificate(block).public_bytes(Encoding.DER))
            except ValueError as e:
                into.notes.append(
                    f(
                        f"ipsec-bad-{tag}{i}",
                        Severity.FAIL,
                        "chain",
                        f"{descr}: certificate could not be parsed",
                        str(e),
                    )
                )
                continue
            own: KeyInfo | None = None
            prv = xml_text(n, "prv")
            if prv is not None:
                kp = _pem(prv)
                kb = next(((lab, b) for lab, b in pem_blocks(kp) if lab.endswith("PRIVATE KEY")), None) if kp else None
                if kb is None:
                    into.notes.append(
                        f(
                            f"ipsec-prv-{tag}{i}",
                            Severity.WARNING,
                            "keymatch",
                            f"{descr}: <prv> is not a base64 PEM private key",
                        )
                    )
                else:
                    try:
                        own = private_key_facts(*kb)[0]
                    except Exception as e:  # noqa: BLE001 - any unreadable key is a finding, as in the Swift catch
                        into.notes.append(
                            f(
                                f"ipsec-prv-{tag}{i}",
                                Severity.WARNING,
                                "keymatch",
                                f"{descr}: stored private key could not be read",
                                str(e),
                            )
                        )
            into.entries.append(Entry(descr, cert, xml_text(n, "refid"), own))
            found += 1
    for i, p1 in enumerate(_descendants(root, "ipsec", "phase1")):
        ike = (xml_text(p1, "iketype") or "").lower()
        descr = (xml_text(p1, "descr") or f"Phase 1 #{i + 1}") + (" (IKEv1)" if ike == "ikev1" else "")
        if p1.find("disabled") is not None:  # pfSense writes <disabled/>: test presence, not text
            into.notes.append(f(f"ipsec-p1-disabled-{i}", Severity.INFO, "info", f"{descr} is disabled; skipped"))
            continue
        certref = xml_text(p1, "certref")
        if certref is None:
            continue  # PSK or EAP-only Phase 1
        m = p1.find("mobile")
        mobile = m is not None and "".join(m.itertext()).strip().lower() not in ("false", "no", "0")
        into.phase1.append(P1(i, descr, certref, xml_text(p1, "caref"), mobile))
    if found == 0 and not into.notes:
        raise ValueError(f"No <cert> or <ca> entries with a certificate were found in {name}.")


def validity(c: Cert, p: str, who: str, now: dt.datetime) -> Finding:
    days = int((c.not_after - now).total_seconds() / 86_400)
    if now < c.not_before:
        return f(
            p + "valid",
            Severity.FAIL,
            "validity",
            f"{who} is not yet valid",
            f"Valid from {analysis.fmt(c.not_before)}. Check the firewall clock.",
        )
    if now > c.not_after:
        return f(
            p + "valid",
            Severity.FAIL,
            "validity",
            f"{who} expired {analysis.fmt(c.not_after)}",
            "Clients refuse expired certificates. Renew in Cert. Manager.",
        )
    if days <= analysis.WARN_DAYS:
        return f(
            p + "valid",
            Severity.WARNING,
            "validity",
            f"{who} expires in {days} day{'' if days == 1 else 's'}",
            f"Expires {analysis.fmt(c.not_after)}. Renew now and update every Phase 1 that uses it.",
        )
    return f(
        p + "valid",
        Severity.PASS,
        "validity",
        f"{who} valid for {days} more days",
        f"Expires {analysis.fmt(c.not_after)}.",
    )


def key_finding(c: Cert, p: str, who: str) -> Finding:
    kind, v = c.key.algorithm
    if kind == "rsa":
        if int(v) < 2048:
            return f(
                p + "key",
                Severity.FAIL,
                "reissue",
                f"{who} has a weak {v}-bit RSA key",
                "IKEv2 clients on macOS/iOS and Windows need RSA 2048+ or ECDSA.",
            )
        return f(p + "key", Severity.PASS, "reissue", f"{who} key: RSA {v}-bit")
    if kind == "ec":
        if v in ("P-256", "P-384", "P-521"):
            return f(
                p + "key",
                Severity.PASS,
                "reissue",
                f"{who} key: ECDSA {v}",
                "Phase 1 authentication must be an ECDSA method when the certificate is ECDSA.",
            )
        return f(
            p + "key",
            Severity.FAIL,
            "reissue",
            f"{who} uses unsupported curve {v}",
            "Use P-256 (prime256v1) or P-384 (secp384r1).",
        )
    if v == "Ed25519":
        return f(
            p + "key",
            Severity.WARNING,
            "reissue",
            f"{who} uses Ed25519",
            "macOS/iOS and Windows IKEv2 clients do not accept Ed25519 certificates. Use RSA 2048+ or ECDSA P-256/P-384.",
        )
    return f(p + "key", Severity.FAIL, "reissue", f"{who} uses an unsupported key algorithm", str(v))


def sig_finding(c: Cert, p: str, who: str) -> Finding:
    if c.signature_oid in SHA2_SIGNATURES:
        return f(p + "sig", Severity.PASS, "reissue", f"{who} signature: {c.signature_algorithm}")
    if c.signature_is_weak:
        return f(
            p + "sig",
            Severity.FAIL,
            "reissue",
            f"{who} is signed with {c.signature_algorithm}",
            "SHA-1/MD5 signatures are rejected. Reissue with Digest Algorithm SHA256 or stronger.",
        )
    if c.signature_oid == PSS:
        return f(
            p + "sig",
            Severity.INFO,
            "reissue",
            f"{who} is signed with RSASSA-PSS",
            "Supported by current macOS and Windows; older clients may not accept it.",
        )
    return f(
        p + "sig",
        Severity.WARNING,
        "reissue",
        f"{who} uses an unrecognised signature algorithm ({c.signature_algorithm})",
    )


def _norm_ip(s: str) -> str:
    try:
        return str(ipaddress.IPv6Address(s))
    except ValueError:
        return s


def evaluate_server(
    s: Entry,
    i: int,
    label: str,
    pool: Sequence[Entry],
    phase1: Sequence[P1],
    cas: Sequence[Entry],
    expected: str | None,
    now: dt.datetime,
    anchors: Sequence[Cert] = (),
) -> list[Finding]:
    c, p, who = s.cert, f"srv{i}-", f"{label}Server certificate"
    out = [validity(c, p, who, now), key_finding(c, p, who), sig_finding(c, p, who)]
    if c.is_ca is True:
        out.append(
            f(
                p + "isca",
                Severity.FAIL,
                "reissue",
                f"{who} is a CA certificate",
                "Choose Certificate Type: Server Certificate when creating it, so Basic Constraints is CA:FALSE.",
            )
        )
    lifetime = int((c.not_after - c.not_before).total_seconds() // 86_400)
    if c.not_before < chaincheck.APPLE_RULE_START:
        out.append(
            f(
                p + "lifetime",
                Severity.INFO,
                "reissue",
                f"{who} lifetime is {lifetime} days (issued before 1 July 2019)",
                "Apple's 825-day limit applies only to certificates issued on or after 1 July 2019. Any replacement must be 825 days or fewer.",
            )
        )
    elif lifetime > APPLE_MAX_DAYS:
        out.append(
            f(
                p + "lifetime",
                Severity.WARNING,
                "reissue",
                f"{who} lifetime is {lifetime} days (over {APPLE_MAX_DAYS})",
                "Apple limits server certificates issued on or after 1 July 2019 to 825 days for TLS, and macOS/iOS IKEv2 clients are reported to reject longer ones too. Reissue with Lifetime 825 or less.",
            )
        )
    else:
        out.append(f(p + "lifetime", Severity.PASS, "reissue", f"{who} lifetime is {lifetime} days (825 or fewer)"))
    if c.eku is not None:
        if SERVER_AUTH in c.eku:
            out.append(f(p + "eku", Severity.PASS, "reissue", f"{who} has the serverAuth EKU"))
        else:
            out.append(
                f(
                    p + "eku",
                    Severity.FAIL,
                    "reissue",
                    f"{who} lacks the serverAuth EKU",
                    f"Present: {', '.join(oid_name(o) for o in c.eku)}. Windows and macOS/iOS IKEv2 clients require TLS Web Server Authentication (1.3.6.1.5.5.7.3.1).",
                )
            )
        if IKE_INTERMEDIATE in c.eku:
            out.append(
                f(
                    p + "eku-ike",
                    Severity.PASS,
                    "reissue",
                    f"{who} has the IKE intermediate EKU (1.3.6.1.5.5.8.2.2)",
                    "Used by Windows; harmless for macOS/iOS.",
                )
            )
        else:
            out.append(
                f(
                    p + "eku-ike",
                    Severity.INFO,
                    "reissue",
                    f"{who} has no IKE intermediate EKU (1.3.6.1.5.5.8.2.2)",
                    "Recommended for Windows clients (pfSense's Server Certificate type adds it). macOS/iOS do not need it.",
                )
            )
    else:
        out.append(
            f(
                p + "eku",
                Severity.WARNING,
                "reissue",
                f"{who} has no Extended Key Usage",
                "Windows and macOS/iOS expect serverAuth; reissue as Certificate Type: Server Certificate (adds serverAuth and 1.3.6.1.5.5.8.2.2).",
            )
        )
    ku = c.key_usage_bits
    if ku:
        if ku[0] & 0x80:
            out.append(f(p + "ku", Severity.PASS, "reissue", f"{who} keyUsage includes digitalSignature"))
        else:
            out.append(
                f(
                    p + "ku",
                    Severity.FAIL,
                    "reissue",
                    f"{who} keyUsage lacks digitalSignature",
                    "IKEv2 AUTH payloads are signatures; the certificate must allow digitalSignature.",
                )
            )
    else:
        out.append(
            f(
                p + "ku",
                Severity.INFO,
                "reissue",
                f"{who} has no keyUsage extension",
                "Allowed by RFC 5280, but pfSense server certificates normally include digitalSignature and keyEncipherment.",
            )
        )
    names = list(c.dns_names) + list(c.ip_addresses)
    if not c.has_san or not names:
        out.append(
            f(
                p + "san",
                Severity.FAIL,
                "san",
                f"{who} has no DNS or IP Subject Alternative Name",
                "Windows and macOS/iOS match the server address and Remote ID against the SAN, not the Common Name.",
            )
        )
    else:
        out.append(f(p + "san", Severity.PASS, "san", f"{who} SAN: {', '.join(names)}"))
    ident = (expected or "").strip(" \t")
    if ident:
        matched, cn_only = c.matches(ident)
        if matched and not cn_only:
            wildcard = not any(d.lower() == ident.lower() for d in c.dns_names) and not any(
                _norm_ip(a) == _norm_ip(ident) for a in c.ip_addresses
            )
            out.append(
                f(
                    p + "id",
                    Severity.INFO,
                    "san",
                    f"{who} covers {ident} only via a wildcard",
                    "Some IKEv2 clients (notably Windows) handle wildcard server certificates poorly. Prefer the exact FQDN in the SAN.",
                )
                if wildcard
                else f(p + "id", Severity.PASS, "san", f"{who} covers the client identifier {ident}")
            )
        else:
            ip_like = ":" in ident or all(ch.isnumeric() or ch == "." for ch in ident)
            out.append(
                f(
                    p + "id",
                    Severity.FAIL,
                    "san",
                    f"{who} does not cover {ident}{' (Common Name only)' if cn_only else ''}",
                    f"Clients connect to and verify {ident}. Add it to the SAN as {'an IP address' if ip_like else 'an FQDN'} entry.",
                )
            )
    else:
        out.append(
            f(
                p + "id",
                Severity.INFO,
                "san",
                "No client identifier given",
                "Pass the FQDN or IP clients use (Server / Remote ID) to confirm the SAN covers it.",
            )
        )
    ch = chaincheck.chain(c, [e.cert for e in pool])
    if len(ch) == 1 and not c.is_self_issued:
        out.append(
            f(
                p + "chain",
                Severity.FAIL,
                "chain",
                f"{who}: issuing CA not supplied",
                f"Issuer: {c.issuer_text}. Add the CA from System › Cert. Manager › CAs (certificate only).",
            )
        )
    elif c.is_self_issued:
        out.append(
            f(
                p + "chain",
                Severity.FAIL,
                "chain",
                f"{who} is self-signed",
                "Issue it from a CA in Cert. Manager; clients trust the CA, not individual server certificates.",
            )
        )
    else:
        for k, issuer in enumerate(ch[1:]):
            if issuer.is_ca is not True:
                out.append(
                    f(
                        p + f"chain-notca-{k}",
                        Severity.FAIL,
                        "chain",
                        f"{label}Issuer {issuer.display_name} is not marked as a CA",
                        f"Its Basic Constraints is {'CA:FALSE' if issuer.is_ca is False else 'missing'}. Create the CA under System › Cert. Manager › CAs.",
                    )
                )
        # chain-bcbad-k: a malformed basicConstraints cannot reach here; cryptography refuses to parse such a
        # certificate, so it is reported as a parse failure instead (shared/known-differences.yaml).
        for k, issuer in enumerate(ch):
            if k >= 1 and issuer.is_ca is True and issuer.path_len is not None:
                below = sum(1 for x in ch[1:k] if not x.is_self_issued)  # RFC 5280 6.1.4: self-issued do not count
                pl = issuer.path_len
                if below > pl:
                    out.append(
                        f(
                            p + f"chain-pathlen-{k}",
                            Severity.FAIL,
                            "chain",
                            f"{label}{issuer.display_name} allows {pl} intermediate CA{'' if pl == 1 else 's'} below it, but the chain has {below}",
                            "basicConstraints pathLenConstraint is violated; clients reject the chain. Self-issued intermediates are not counted. Issue the server certificate from a CA within the limit.",
                        )
                    )
        ok, msg = chaincheck.verify(ch, now, anchors)
        out.append(
            f(
                p + "chain",
                Severity.PASS,
                "chain",
                f"{who} chain verifies to {ch[-1].display_name}",
                " → ".join(x.display_name for x in ch),
            )
            if ok
            else f(p + "chain", Severity.FAIL, "chain", f"{who} chain does not verify", msg)
        )
        top = ch[-1]
        if not chaincheck.is_self_signed(top):
            out.append(
                f(
                    p + "chain-top",
                    Severity.WARNING,
                    "chain",
                    f"{label}Chain stops at {top.display_name}",
                    f"Its issuer ({top.issuer_text}) was not supplied; clients need the root CA installed.",
                )
            )
        if len(ch) > 1 and ch[1].not_after < c.not_after:
            out.append(
                f(
                    p + "ca-before",
                    Severity.WARNING,
                    "chain",
                    f"{label}CA {ch[1].display_name} expires before the server certificate",
                    f"CA expires {analysis.fmt(ch[1].not_after)}; clients stop trusting the server certificate then.",
                )
            )
    for p1 in phase1:
        role = "mobile clients" if p1.mobile else "site-to-site"
        out.append(f(p + f"p1-{p1.index}", Severity.INFO, "info", f"Used by IPsec {p1.descr} ({role})"))
        ca = next((e for e in cas if p1.caref is not None and e.refid == p1.caref), None)
        if ca is not None and not any(x.sha256 == ca.cert.sha256 for x in ch[1:]):
            detail = (
                f"Mobile client certificates are validated against {ca.label}. That is normal when clients use a different CA; confirm it is intended."
                if p1.mobile
                else f"The remote peer's certificate is validated against {ca.label}. That is normal when each side has its own CA; confirm it is intended."
            )
            out.append(
                f(
                    p + f"p1ca-{p1.index}",
                    Severity.INFO,
                    "chain",
                    f"{p1.descr}: Peer Certificate Authority {ca.label} did not issue this server certificate",
                    detail,
                )
            )
    if s.own_key is not None:
        out.append(
            f(
                p + "prv",
                Severity.PASS,
                "keymatch",
                f"{who} stored private key matches",
                "Compared in memory; the key is not shown.",
            )
            if s.own_key.material == c.key.material
            else f(
                p + "prv",
                Severity.FAIL,
                "keymatch",
                f"{who} stored private key does not match the certificate",
                "Strongswan will fail to authenticate. Reissue the certificate in Cert. Manager.",
            )
        )
    return out


def evaluate_ca(e: Entry, i: int, now: dt.datetime) -> list[Finding]:
    c, p, who = e.cert, f"ca{i}-", f"CA {e.label}"
    out = [validity(c, p, who, now), key_finding(c, p, who)]
    if not c.is_self_issued:
        out.append(sig_finding(c, p, who))
    out.append(
        f(p + "bc", Severity.PASS, "chain", f"{who} has basicConstraints CA:TRUE")
        if c.is_ca is True
        else f(
            p + "bc",
            Severity.FAIL,
            "chain",
            f"{who} is missing basicConstraints CA:TRUE",
            "Clients will not accept it as an issuer.",
        )
    )
    ku = c.key_usage_bits
    if ku and not ku[0] & 0x04:
        out.append(f(p + "ku", Severity.FAIL, "chain", f"{who} keyUsage lacks keyCertSign"))
    if e.own_key is not None:
        out.append(
            f(
                p + "prv",
                Severity.INFO,
                "keymatch",
                f"{who} private key is stored in this file",
                "Treat this config.xml as secret; it can issue trusted VPN certificates.",
            )
        )
    return out


def inspect_data(
    items: Sequence[tuple[str, bytes]],
    expected_identifier: str | None = None,
    now: dt.datetime | None = None,
    anchors: Sequence[Cert] = (),
) -> Report:
    now = now or dt.datetime.now(dt.UTC)
    ld, r = Loaded(), Report()
    for name, data in items:
        r.sources.append(name)
        try:
            load(name, data, ld)
        except (ValueError, RecursionError) as e:  # RecursionError: fail closed on any too-deep input (review B2)
            why = "The file nests too deeply and is refused." if isinstance(e, RecursionError) else str(e)
            ld.notes.append(f(f"parse-{name}", Severity.FAIL, "info", f"Could not parse {name}", why))
    ld.entries = unique_by(ld.entries, lambda e: e.cert.sha256)
    r.cas = [
        e for e in ld.entries
        if e.cert.is_ca is True
        or (e.cert.is_self_issued and e.cert.is_ca is None and any(o.cert.sha256 != e.cert.sha256 and o.cert.issuer == e.cert.subject for o in ld.entries))
    ]  # fmt: skip
    ca_shas = {e.cert.sha256 for e in r.cas}
    servers = [e for e in ld.entries if e.cert.sha256 not in ca_shas]
    out = list(ld.notes)
    refs = {p.certref for p in ld.phase1 if p.certref is not None}
    if refs:
        unused = [s for s in servers if s.refid is not None and s.refid not in refs]
        if unused:
            n = len(unused)
            out.append(
                f(
                    "ipsec-unused",
                    Severity.INFO,
                    "info",
                    f"{n} certificate{'' if n == 1 else 's'} not used by IPsec skipped",
                    ", ".join(u.label for u in unused),
                )
            )
        servers = [s for s in servers if s.refid is None or s.refid in refs]
        for p in ld.phase1:
            if p.certref is not None and not any(e.refid == p.certref for e in ld.entries):
                out.append(
                    f(
                        f"ipsec-p1-missing-{p.certref}",
                        Severity.FAIL,
                        "chain",
                        f"{p.descr}: My Certificate refers to a certificate that is not in the file",
                        f"certref {p.certref}",
                    )
                )
    elif any(s.refid is not None for s in servers):

        def server_auth(e: Entry) -> bool:
            return e.cert.eku is not None and SERVER_AUTH in e.cert.eku

        other = [s for s in servers if s.refid is not None and not server_auth(s)]
        servers = [s for s in servers if s.refid is None or server_auth(s)]
        n = len(servers)
        out.append(
            f(
                "ipsec-nop1",
                Severity.INFO,
                "info",
                "No enabled Phase 1 uses a certificate",
                f"Checked {n} certificate{'' if n == 1 else 's'} with the serverAuth EKU as IKEv2 server candidates.",
            )
        )
        if other:
            m = len(other)
            out.append(
                f(
                    "ipsec-notserver",
                    Severity.INFO,
                    "info",
                    f"{m} non-server certificate{'' if m == 1 else 's'} skipped",
                    ", ".join(o.label for o in other),
                )
            )
    r.servers = servers
    if servers:
        out.append(
            f(
                "ipsec-revocation",
                Severity.INFO,
                "chain",
                "Revocation is not checked",
                "This check is offline, so CRLs and OCSP are not fetched. Confirm in System › Cert. Manager › Certificate Revocation that the certificate is not revoked.",
            )
        )
    else:
        out.append(
            f(
                "ipsec-noserver",
                Severity.FAIL if not r.cas else Severity.INFO,
                "info",
                "No certificate found" if not r.cas else "No server certificate supplied; checked the CA only",
            )
        )
    pool = r.cas + servers
    for i, s in enumerate(servers):
        p1 = [p for p in ld.phase1 if p.certref is not None and p.certref == s.refid]
        out += evaluate_server(
            s, i, f"{s.label}: " if len(servers) > 1 else "", pool, p1, r.cas, expected_identifier, now, anchors
        )
    for ci, ca in enumerate(r.cas):
        out += evaluate_ca(ca, ci, now)
    for k, key in enumerate(ld.keys):
        srv = next((s for s in servers if s.cert.key.material == key.material), None)
        owner = next((c for c in r.cas if c.cert.key.material == key.material), None)
        if srv is not None:
            out.append(
                f(
                    f"ipsec-key-{k}",
                    Severity.PASS,
                    "keymatch",
                    f"Private key matches {srv.label}",
                    "Compared public key material derived in memory.",
                )
            )
        elif owner is not None:
            out.append(
                f(
                    f"ipsec-key-{k}",
                    Severity.WARNING,
                    "keymatch",
                    f"Private key belongs to the CA {owner.label}, not a server certificate",
                    "Keep CA keys on pfSense only; never copy them to clients.",
                )
            )
        else:
            out.append(
                f(
                    f"ipsec-key-{k}",
                    Severity.FAIL,
                    "keymatch",
                    "Private key does not match any certificate supplied",
                    "Use the key generated with this certificate, or reissue in Cert. Manager.",
                )
            )
    r.findings = sort_findings(out)
    return r


def inspect(
    paths: Sequence[Path],
    expected_identifier: str | None = None,
    now: dt.datetime | None = None,
    anchors: Sequence[Cert] = (),
) -> Report:
    items, pre = read_files(paths, MAX_FILE_SIZE, "20 MB", Topic.IPSEC)
    r = inspect_data(items, expected_identifier, now, anchors)
    r.findings = sort_findings(pre + r.findings)
    return r
