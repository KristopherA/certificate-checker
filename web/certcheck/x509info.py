"""Certificate, key and CSR facts used by the analysis, read with `cryptography`.

Mirrors the fields of Source/Sources/Core/X509.swift that Analysis.evaluate uses.
Private keys are parsed in memory only to derive their public half; nothing is stored.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SERVER_AUTH = ExtendedKeyUsageOID.SERVER_AUTH.dotted_string
CLIENT_AUTH = ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string
ANY_EKU = "2.5.29.37.0"
WEAK_SIGNATURES = frozenset(
    {"1.2.840.113549.1.1.4", "1.2.840.113549.1.1.5", "1.2.840.10045.4.1", "1.2.840.113549.1.1.2"}
)
OID_NAMES = {
    "1.2.840.113549.1.1.4": "md5WithRSA",
    "1.2.840.113549.1.1.5": "sha1WithRSA",
    "1.2.840.113549.1.1.11": "sha256WithRSA",
    "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.1": "ecdsaWithSHA1",
    "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
    "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
    "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
    "1.3.101.112": "Ed25519",
    SERVER_AUTH: "TLS Web Server Authentication",
    CLIENT_AUTH: "TLS Web Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "E-mail Protection",
    ANY_EKU: "Any Extended Key Usage",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
}
CURVES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}


def oid_name(oid: str) -> str:
    return OID_NAMES.get(oid, oid)


@dataclass(frozen=True)
class KeyInfo:
    """Public key facts. `algorithm` is ("rsa", bits) / ("ec", curve) / ("other", description)."""

    algorithm: tuple[str, int | str]
    material: bytes  # SubjectPublicKeyInfo DER, used for key/cert matching

    @property
    def description(self) -> str:
        kind, v = self.algorithm
        return f"RSA {v}-bit" if kind == "rsa" else f"ECDSA {v}" if kind == "ec" else str(v)


def key_info(pub: object) -> KeyInfo:
    spki = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)  # type: ignore[attr-defined]
    if isinstance(pub, rsa.RSAPublicKey):
        return KeyInfo(("rsa", pub.key_size), spki)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return KeyInfo(("ec", CURVES.get(pub.curve.name, pub.curve.name)), spki)
    if isinstance(pub, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        return KeyInfo(("other", type(pub).__name__.removesuffix("PublicKey")), spki)
    return KeyInfo(("other", type(pub).__name__), spki)


def fingerprint(der: bytes) -> str:
    return ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())


def _ext(cert: x509.Certificate | x509.CertificateSigningRequest, cls: type) -> object | None:
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


@dataclass(frozen=True)
class Cert:
    der: bytes
    sha256: str
    subject: bytes  # DER of the Name: issuer/subject links compare raw bytes, like the Swift code
    issuer: bytes
    subject_text: str
    issuer_text: str
    common_name: str | None
    not_before: dt.datetime
    not_after: dt.datetime
    signature_oid: str
    key: KeyInfo
    dns_names: tuple[str, ...]
    ip_addresses: tuple[str, ...]
    has_san: bool
    is_ca: bool | None
    eku: tuple[str, ...] | None
    ski: bytes | None
    aki: bytes | None
    raw: x509.Certificate = field(repr=False, compare=False)

    @property
    def is_self_issued(self) -> bool:
        return self.issuer == self.subject

    @property
    def display_name(self) -> str:
        return self.common_name or (self.dns_names[0] if self.dns_names else self.subject_text)

    @property
    def signature_algorithm(self) -> str:
        return oid_name(self.signature_oid)

    @property
    def signature_is_weak(self) -> bool:
        return self.signature_oid in WEAK_SIGNATURES

    def matches(self, hostname: str) -> tuple[bool, bool]:
        """(matched, via_common_name_only): SAN DNS (one left-most wildcard), SAN IPs; CN only when no SAN."""
        host = hostname.lower().strip(".")
        if _is_ip(host):
            want = ipaddress.ip_address(host)
            return (any(ipaddress.ip_address(a) == want for a in self.ip_addresses), False)
        if any(wildcard_match(p, host) for p in self.dns_names):
            return (True, False)
        if not self.has_san and self.common_name and wildcard_match(self.common_name, host):
            return (True, True)
        return (False, False)


def _is_ip(host: str) -> bool:
    if ":" in host:
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(c.isdigit() or c == "." for c in host)


def wildcard_match(pattern: str, host: str) -> bool:
    p = pattern.lower().strip(".")
    if p == host:
        return True
    if not p.startswith("*."):
        return False
    suffix = p[2:]
    if "." not in suffix or "." not in host:
        return False
    label, rest = host.split(".", 1)
    return bool(label) and rest == suffix


def _name_text(n: x509.Name) -> str:
    return n.rfc4514_string()


def parse_cert(der: bytes) -> Cert:
    c = x509.load_der_x509_certificate(der)
    cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    san = _ext(c, x509.SubjectAlternativeName)
    basic = _ext(c, x509.BasicConstraints)
    eku = _ext(c, x509.ExtendedKeyUsage)
    ski = _ext(c, x509.SubjectKeyIdentifier)
    aki = _ext(c, x509.AuthorityKeyIdentifier)
    dns: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    if isinstance(san, x509.SubjectAlternativeName):
        dns = tuple(san.get_values_for_type(x509.DNSName))
        ips = tuple(str(a) for a in san.get_values_for_type(x509.IPAddress))
    return Cert(
        der=der,
        sha256=fingerprint(der),
        subject=c.subject.public_bytes(),
        issuer=c.issuer.public_bytes(),
        subject_text=_name_text(c.subject),
        issuer_text=_name_text(c.issuer),
        common_name=str(cn[0].value) if cn else None,
        not_before=c.not_valid_before_utc,
        not_after=c.not_valid_after_utc,
        signature_oid=c.signature_algorithm_oid.dotted_string,
        key=key_info(c.public_key()),
        dns_names=dns,
        ip_addresses=ips,
        has_san=san is not None,
        is_ca=getattr(basic, "ca", None),
        eku=tuple(o.dotted_string for o in eku) if isinstance(eku, x509.ExtendedKeyUsage) else None,
        ski=ski.digest if isinstance(ski, x509.SubjectKeyIdentifier) else None,
        aki=aki.key_identifier if isinstance(aki, x509.AuthorityKeyIdentifier) else None,
        raw=c,
    )


@dataclass(frozen=True)
class Request:
    subject_text: str
    common_name: str | None
    key: KeyInfo
    signature_oid: str
    dns_names: tuple[str, ...]
    ip_addresses: tuple[str, ...]

    @property
    def signature_algorithm(self) -> str:
        return oid_name(self.signature_oid)


def parse_request(der: bytes) -> Request:
    r = x509.load_der_x509_csr(der)
    cn = r.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    san = _ext(r, x509.SubjectAlternativeName)
    dns: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    if isinstance(san, x509.SubjectAlternativeName):
        dns = tuple(san.get_values_for_type(x509.DNSName))
        ips = tuple(str(a) for a in san.get_values_for_type(x509.IPAddress))
    return Request(
        subject_text=_name_text(r.subject),
        common_name=str(cn[0].value) if cn else None,
        key=key_info(r.public_key()),
        signature_oid=r.signature_algorithm_oid.dotted_string,
        dns_names=dns,
        ip_addresses=ips,
    )


def private_key_info(pem_block: bytes, password: bytes | None = None) -> KeyInfo:
    """Public half of a PEM private key, derived in memory. The private key object is dropped at once."""
    k = serialization.load_pem_private_key(pem_block, password=password)
    return key_info(k.public_key())
