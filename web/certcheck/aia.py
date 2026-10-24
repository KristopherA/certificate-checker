"""AIA issuer fetching and CT presence (M4).

AIA (opt-in, off by default): when the presented chain stops short of a self-signed certificate and does not
contain the issuer of its last certificate, download that certificate's caIssuers URL through certcheck.fetch
(TargetPolicy, http/https, size and time caps, few redirects), keep only a certificate that really issued it
(name match and signature), and repeat up to MAX_FETCHES times. Roots are never added (the trust store decides).

CT: SCT presence and count only (embedded SCT list extension). SCTs delivered in the TLS extension or in a
stapled OCSP response are not seen by the Python TLS stack and are not counted; log signatures are not checked.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID

from . import analysis, fetch, probe, revocation
from .model import Finding, Severity, Topic
from .x509info import Cert, parse_cert

MAX_FETCHES = 3


def ca_issuer_urls(c: Cert) -> list[str]:
    try:
        aia = c.raw.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return []
    return [
        d.access_location.value
        for d in aia
        if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS
        and isinstance(d.access_location, x509.UniformResourceIdentifier)
    ]


def _certs(data: bytes) -> list[x509.Certificate]:
    for load in (
        lambda b: [x509.load_der_x509_certificate(b)],
        pkcs7.load_der_pkcs7_certificates,
        x509.load_pem_x509_certificates,
        pkcs7.load_pem_pkcs7_certificates,
    ):
        try:
            return list(load(data))
        except ValueError:
            continue
    return []


@dataclass
class Completion:
    added: list[Cert] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    contacted: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)


def complete(
    chain: list[Cert], *, policy: probe.TargetPolicy | None = None, timeout: float = fetch.FETCH_TIMEOUT_S
) -> Completion:
    out = Completion()
    have = list(analysis.ordered_chain(chain))
    for _ in range(MAX_FETCHES):
        if not have:
            break
        top = have[-1]
        if top.is_self_issued or revocation.issuer_of(top, have) is not None:
            break
        urls = ca_issuer_urls(top)
        if not urls:
            out.notes.append(f"{top.display_name} has no AIA caIssuers URL")
            break
        found = None
        for url in urls:
            try:
                got = fetch.fetch(
                    url, purpose="aia", policy=policy, timeout=timeout, contacted=out.contacted, blocked=out.blocked
                )
            except probe.TargetDenied as e:
                out.notes.append(f"{url}: blocked by the target policy ({e})")
                continue
            except fetch.FetchError as e:
                out.notes.append(f"{url}: {e}")
                continue
            for raw in _certs(got.body):
                cand = parse_cert(raw.public_bytes(serialization.Encoding.DER))
                if cand.subject == top.issuer and revocation._signed_by(top.raw, cand.raw):
                    found = cand
                    break
            if found:
                break
            out.notes.append(f"{url}: no certificate that issued {top.display_name}")
        if found is None or (found.is_self_issued and revocation._signed_by(found.raw, found.raw)):
            break  # roots stay with the trust store
        out.added.append(found)
        have.append(found)
    return out


def aia_findings(c: Completion) -> list[Finding]:
    if c.added:
        names = ", ".join(x.display_name for x in c.added)
        detail = f"Fetched {names} from {', '.join(c.contacted)}. The server should send them itself."
        return [
            Finding(
                "aia-fetched",
                Severity.WARNING,
                Topic.CHAIN_INCOMPLETE,
                "Missing intermediate fetched via AIA",
                detail,
                "aia",
            )
        ]
    detail = "; ".join(c.notes) or "The presented chain already reaches its issuer or a self-signed certificate."
    if c.contacted:
        detail += f" URLs contacted: {', '.join(c.contacted)}."
    return [Finding("aia-none", Severity.INFO, Topic.CHAIN_INCOMPLETE, "AIA: nothing fetched", detail, "aia")]


def sct_count(c: Cert) -> int:
    try:
        return len(c.raw.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps).value)
    except x509.ExtensionNotFound:
        return 0


def ct_finding(leaf: Cert) -> Finding:
    n = sct_count(leaf)
    if n:
        return Finding(
            "ct-sct",
            Severity.INFO,
            Topic.TRUST,
            f"Certificate Transparency: {n} embedded SCT{'s' if n != 1 else ''}",
            "Presence and count only; log signatures are not checked.",
            "ct",
        )
    return Finding(
        "ct-sct",
        Severity.INFO,
        Topic.TRUST,
        "Certificate Transparency: no embedded SCTs",
        "Normal for private CAs. Publicly trusted certificates need SCTs for Chrome and Safari; SCTs sent in the TLS "
        "extension or a stapled OCSP response are not counted here.",
        "ct",
    )
