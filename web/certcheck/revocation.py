"""Opt-in revocation checking (M4): stapled OCSP, then live OCSP, then the CRL, per certificate.

Order per certificate (spec, Revocation checking): 1. the OCSP response the server stapled (leaf only), 2. the
OCSP responders in the certificate's AIA extension, 3. the CRL distribution points. The first step that gives a
verified GOOD or REVOKED answer wins; a step that fails (timeout, blocked by TargetPolicy, bad signature, stale
or unknown answer) is noted and the next step runs. When none answers the result is COULD NOT CHECK with the
reasons, never a failure of the whole check. Self-signed certificates are NOT APPLICABLE. Every URL contacted is
listed. All responses are verified against the issuer in the chain: an OCSP response must be signed by the issuer
or by a delegated responder certificate the issuer signed with the OCSPSigning EKU; a CRL must name the issuer and
carry its signature. Nothing is cached beyond one call. Network access is only through certcheck.fetch.
"""

from __future__ import annotations

import datetime as dt
import enum
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID

from . import fetch, probe
from .model import Finding, Severity, Topic
from .x509info import Cert

SKEW = dt.timedelta(minutes=5)


class Status(enum.StrEnum):
    GOOD = "good"
    REVOKED = "revoked"
    COULD_NOT_CHECK = "could not check"
    NOT_APPLICABLE = "not applicable"


@dataclass
class CertStatus:
    name: str
    status: Status
    method: str = ""  # "stapled OCSP" | "OCSP" | "CRL" when an answer was found
    reason: str = ""  # COULD NOT CHECK / NOT APPLICABLE reason, or the CRL/OCSP revocation reason
    revoked_at: dt.datetime | None = None
    notes: list[str] = field(default_factory=list)  # one line per step tried


@dataclass
class Revocation:
    certs: list[CertStatus]
    stapled: bool
    must_staple: bool
    contacted: list[str]
    blocked: list[str] = field(default_factory=list)


class Invalid(Exception):
    """A response that cannot be used (not an answer either way)."""


@dataclass(frozen=True)
class Answer:
    status: Status  # GOOD or REVOKED
    revoked_at: dt.datetime | None = None
    reason: str = ""


def _ext(c: Cert, cls: type) -> object | None:
    try:
        return c.raw.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def ocsp_urls(c: Cert) -> list[str]:
    aia = _ext(c, x509.AuthorityInformationAccess)
    if not isinstance(aia, x509.AuthorityInformationAccess):
        return []
    return [
        d.access_location.value
        for d in aia
        if d.access_method == AuthorityInformationAccessOID.OCSP
        and isinstance(d.access_location, x509.UniformResourceIdentifier)
    ]


def crl_urls(c: Cert) -> list[str]:
    cdp = _ext(c, x509.CRLDistributionPoints)
    if not isinstance(cdp, x509.CRLDistributionPoints):
        return []
    return [
        n.value
        for dp in cdp
        if dp.full_name and dp.crl_issuer is None
        for n in dp.full_name
        if isinstance(n, x509.UniformResourceIdentifier)
    ]


def must_staple(c: Cert) -> bool:
    tf = _ext(c, x509.TLSFeature)
    return isinstance(tf, x509.TLSFeature) and x509.TLSFeatureType.status_request in tf


def _signed_by(c: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        c.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def issuer_of(c: Cert, chain: list[Cert]) -> Cert | None:
    for cand in chain:
        if cand.subject == c.issuer and _signed_by(c.raw, cand.raw):
            return cand
    return None


def _verify_sig(pub: object, sig: bytes, data: bytes, h: hashes.HashAlgorithm | None) -> None:
    if isinstance(pub, rsa.RSAPublicKey) and h is not None:
        pub.verify(sig, data, padding.PKCS1v15(), h)
    elif isinstance(pub, ec.EllipticCurvePublicKey) and h is not None:
        pub.verify(sig, data, ec.ECDSA(h))
    elif isinstance(pub, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        pub.verify(sig, data)
    else:
        raise Invalid("unsupported signature algorithm")


def _key_hash(pub: object) -> bytes:
    return x509.SubjectKeyIdentifier.from_public_key(pub).digest  # type: ignore[arg-type]  # SHA-1 of the key bits


def _window(this: dt.datetime, nxt: dt.datetime | None, now: dt.datetime, what: str) -> None:
    if this > now + SKEW:
        raise Invalid(f"{what} is not valid yet (thisUpdate {this:%Y-%m-%d %H:%M} UTC)")
    if nxt is not None and nxt < now - SKEW:
        raise Invalid(f"{what} is stale (nextUpdate {nxt:%Y-%m-%d %H:%M} UTC)")


def check_ocsp(der: bytes, c: Cert, issuer: Cert, now: dt.datetime) -> Answer:
    """Verify an OCSP response for c and return its answer; Invalid for anything that is not GOOD/REVOKED."""
    try:
        resp = ocsp.load_der_ocsp_response(der)
    except ValueError:
        raise Invalid("not an OCSP response") from None
    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise Invalid(f"responder answered {resp.response_status.name.lower()}")
    ipub = issuer.raw.public_key()
    if resp.responder_name == issuer.raw.subject or resp.responder_key_hash == _key_hash(ipub):
        signer_pub = ipub
    else:
        signer_pub = None
        for d in resp.certificates:
            named = resp.responder_name == d.subject or resp.responder_key_hash == _key_hash(d.public_key())
            if not named or d.issuer != issuer.raw.subject or not _signed_by(d, issuer.raw):
                continue
            try:
                eku = d.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            except x509.ExtensionNotFound:
                continue
            if (
                ExtendedKeyUsageOID.OCSP_SIGNING in eku
                and d.not_valid_before_utc - SKEW <= now <= d.not_valid_after_utc
            ):
                signer_pub = d.public_key()
                break
        if signer_pub is None:
            raise Invalid("response is not signed by the issuer or a responder it authorised")
    try:
        _verify_sig(signer_pub, resp.signature, resp.tbs_response_bytes, resp.signature_hash_algorithm)
    except InvalidSignature:
        raise Invalid("response signature does not verify") from None
    for s in resp.responses:
        if s.serial_number != c.raw.serial_number:
            continue
        want = ocsp.OCSPRequestBuilder().add_certificate(c.raw, issuer.raw, s.hash_algorithm).build()
        if (s.issuer_key_hash, s.issuer_name_hash) != (want.issuer_key_hash, want.issuer_name_hash):
            continue
        _window(s.this_update_utc, s.next_update_utc, now, "OCSP response")
        if s.certificate_status == ocsp.OCSPCertStatus.GOOD:
            return Answer(Status.GOOD)
        if s.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            why = s.revocation_reason.name if s.revocation_reason else "unspecified"
            return Answer(Status.REVOKED, s.revocation_time_utc, why)
        raise Invalid("responder does not know this certificate (unknown)")
    raise Invalid("response does not cover this certificate")


def check_crl(data: bytes, c: Cert, issuer: Cert, now: dt.datetime) -> Answer:
    try:
        crl = x509.load_der_x509_crl(data)
    except ValueError:
        try:
            crl = x509.load_pem_x509_crl(data)
        except ValueError:
            raise Invalid("not a CRL") from None
    if crl.issuer != issuer.raw.subject:
        raise Invalid("CRL is issued by a different CA")
    if not crl.is_signature_valid(issuer.raw.public_key()):  # type: ignore[arg-type]
        raise Invalid("CRL signature does not verify against the issuer")
    _window(crl.last_update_utc, crl.next_update_utc, now, "CRL")
    try:
        idp = crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint).value
    except x509.ExtensionNotFound:
        idp = None
    if idp is not None and (idp.indirect_crl or idp.only_some_reasons or idp.only_contains_attribute_certs):
        raise Invalid("partitioned or indirect CRLs are not supported")
    if idp is not None and idp.only_contains_ca_certs and c.is_ca is not True:
        raise Invalid("CRL only covers CA certificates (IDP onlyContainsCACerts), not this end-entity certificate")
    if idp is not None and idp.only_contains_user_certs and c.is_ca is True:
        raise Invalid("CRL only covers end-entity certificates (IDP onlyContainsUserCerts), not this CA certificate")
    r = crl.get_revoked_certificate_by_serial_number(c.raw.serial_number)
    if r is None:
        return Answer(Status.GOOD)
    try:
        why = r.extensions.get_extension_for_class(x509.CRLReason).value.reason.name
    except x509.ExtensionNotFound:
        why = "unspecified"
    return Answer(Status.REVOKED, r.revocation_date_utc, why)


def _ocsp_request(c: Cert, issuer: Cert) -> bytes:
    req = ocsp.OCSPRequestBuilder().add_certificate(c.raw, issuer.raw, hashes.SHA1()).build()  # noqa: S303  RFC 5019 default
    return req.public_bytes(serialization.Encoding.DER)


def check(
    chain: list[Cert],
    *,
    stapled: bytes | None,
    now: dt.datetime,
    policy: probe.TargetPolicy | None = None,
    timeout: float = fetch.FETCH_TIMEOUT_S,
) -> Revocation:
    """chain is the ordered chain (leaf first), optionally completed by AIA."""
    contacted: list[str] = []
    blocked: list[str] = []
    out: list[CertStatus] = []
    for i, c in enumerate(chain):
        st = CertStatus(c.display_name, Status.COULD_NOT_CHECK)
        out.append(st)
        if c.is_self_issued and _signed_by(c.raw, c.raw):
            st.status, st.reason = Status.NOT_APPLICABLE, "self-signed"
            continue
        issuer = issuer_of(c, chain)
        if issuer is None:
            st.reason = "the issuer is not in the chain (AIA fetching can add it)"
            continue
        steps: list[tuple[str, str]] = []
        if i == 0 and stapled:
            steps.append(("stapled OCSP", ""))
        steps += [("OCSP", u) for u in ocsp_urls(c)]
        steps += [("CRL", u) for u in crl_urls(c)]
        if not steps:
            st.reason = "no stapled response, OCSP responder or CRL distribution point"
            continue
        for method, url in steps:
            try:
                if method == "stapled OCSP":
                    assert stapled is not None
                    a = check_ocsp(stapled, c, issuer, now)
                elif method == "OCSP":
                    got = fetch.fetch(
                        url,
                        purpose="ocsp",
                        policy=policy,
                        method="POST",
                        body=_ocsp_request(c, issuer),
                        content_type="application/ocsp-request",
                        timeout=timeout,
                        contacted=contacted,
                        blocked=blocked,
                    )
                    a = check_ocsp(got.body, c, issuer, now)
                else:
                    got = fetch.fetch(
                        url, purpose="crl", policy=policy, timeout=timeout, contacted=contacted, blocked=blocked
                    )
                    a = check_crl(got.body, c, issuer, now)
            except probe.TargetDenied as e:
                st.notes.append(f"{method} {url}: blocked by the target policy ({e})")
                continue
            except (fetch.FetchError, Invalid) as e:
                st.notes.append(f"{method} {url}".rstrip() + f": {e}")
                continue
            st.status, st.method, st.revoked_at, st.reason = a.status, method, a.revoked_at, a.reason
            st.notes.append(f"{method} {url}".rstrip() + f": {a.status.value}")
            break
        else:
            st.reason = "; ".join(st.notes)
    leaf_ms = bool(chain) and must_staple(chain[0])
    return Revocation(
        out,
        stapled=bool(stapled),
        must_staple=leaf_ms,
        contacted=list(dict.fromkeys(contacted)),
        blocked=list(dict.fromkeys(blocked)),
    )


def findings(rev: Revocation) -> list[Finding]:
    out: list[Finding] = []
    for i, s in enumerate(rev.certs):
        label = f"Certificate {i} ({s.name})"
        if s.status == Status.REVOKED:
            when = f" on {s.revoked_at:%Y-%m-%d %H:%M} UTC" if s.revoked_at else ""
            out.append(
                Finding(
                    f"rev-{i}",
                    Severity.FAIL,
                    Topic.TRUST,
                    f"{label} is REVOKED",
                    f"Revoked{when}, reason {s.reason} ({s.method}). Replace the certificate.",
                    "revocation",
                )
            )
        elif s.status == Status.GOOD:
            out.append(
                Finding(
                    f"rev-{i}",
                    Severity.PASS,
                    Topic.TRUST,
                    f"{label} is not revoked",
                    f"GOOD ({s.method}).",
                    "revocation",
                )
            )
        elif s.status == Status.NOT_APPLICABLE:
            out.append(
                Finding(
                    f"rev-{i}",
                    Severity.INFO,
                    Topic.TRUST,
                    f"{label}: revocation not applicable",
                    s.reason,
                    "revocation",
                )
            )
        else:
            out.append(
                Finding(
                    f"rev-{i}",
                    Severity.INFO,
                    Topic.TRUST,
                    f"{label}: revocation COULD NOT CHECK",
                    s.reason,
                    "revocation",
                )
            )
    if rev.must_staple and not rev.stapled:
        out.append(
            Finding(
                "must-staple",
                Severity.WARNING,
                Topic.TRUST,
                "Must-staple certificate, but the server did not staple an OCSP response",
                "The certificate has the TLS Feature (status_request) extension, so clients such as Firefox refuse it "
                "without a stapled response. Turn on OCSP stapling on the server (nginx ssl_stapling on; Apache "
                "SSLUseStapling on).",
                "revocation",
            )
        )
    out.append(
        Finding(
            "rev-urls",
            Severity.INFO,
            Topic.TRUST,
            "Revocation: URLs contacted",
            (", ".join(rev.contacted) if rev.contacted else "None (no outbound revocation request was made).")
            + (f" Blocked by the target policy (not contacted): {', '.join(rev.blocked)}." if rev.blocked else ""),
            "revocation",
        )
    )
    return out
