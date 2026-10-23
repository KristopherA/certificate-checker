"""Policy engine: a port of Analysis.evaluate (Source/Sources/Core/Analysis.swift).

Ids, severities and topics must match the Swift code; shared/golden holds the Mac verdicts and
tests/test_parity.py compares them. The explicit policy (398-day rule, SAN required, EKU,
RSA >= 2048, SHA-1/MD5 rejection) lives here, not in OpenSSL, so both platforms apply the same rules.
"""

from __future__ import annotations

import datetime as dt

from .model import Finding, Purpose, Severity, Topic, sort_findings
from .x509info import ANY_EKU, CLIENT_AUTH, SERVER_AUTH, WEAK_SIGNATURES, Cert, KeyInfo, Request, oid_name

WARN_DAYS = 30
MAX_PUBLIC_LIFETIME_DAYS = 398
P, I, W, F = Severity.PASS, Severity.INFO, Severity.WARNING, Severity.FAIL  # noqa: E741  (Mac shorthand)


def fmt(d: dt.datetime) -> str:
    """Display date in UTC, in the Mac app's en_US style (e.g. 'Jan 1, 2026 at 12:00 AM')."""
    d = d.astimezone(dt.UTC)
    hour = d.hour % 12 or 12
    return f"{d:%b} {d.day}, {d.year} at {hour}:{d:%M} {'AM' if d.hour < 12 else 'PM'}"


def ordered_chain(certs: list[Cert]) -> list[Cert]:
    """Leaf -> root by issuer/subject links; certificates that fit nowhere go at the end."""
    if len(certs) <= 1:
        return list(certs)
    leaf = next(
        (
            c
            for c in certs
            if not any(o.sha256 != c.sha256 and o.issuer == c.subject and not o.is_self_issued for o in certs)
        ),
        certs[0],
    )
    chain, used = [leaf], {leaf.sha256}
    while not chain[-1].is_self_issued:
        nxt = next((c for c in certs if c.sha256 not in used and c.subject == chain[-1].issuer), None)
        if nxt is None:
            break
        chain.append(nxt)
        used.add(nxt.sha256)
    chain += [c for c in certs if c.sha256 not in used]
    return chain


def _days(delta: dt.timedelta) -> int:
    return int(delta.total_seconds() / 86_400)  # truncates toward zero, like Swift Int(Double)


def evaluate(
    certs: list[Cert],
    hostname: str | None,
    purpose: Purpose,
    *,
    now: dt.datetime,
    keys: list[KeyInfo] | None = None,
    requests: list[Request] | None = None,
) -> list[Finding]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    keys, requests = keys or [], requests or []
    out: list[Finding] = []
    if not certs:
        if not requests and not keys:
            out.append(
                Finding(
                    "none",
                    F,
                    Topic.GENERAL,
                    "No certificate found",
                    "The input contained no readable PEM, DER, PKCS#7 or PFX certificate.",
                )
            )
        for i, r in enumerate(requests):
            out += evaluate_request(r, i, keys)
        return out
    chain = ordered_chain(certs)
    leaf = chain[0]
    path = " → ".join(c.display_name for c in chain)

    if len(certs) > 1:
        if [c.sha256 for c in certs] == [c.sha256 for c in chain]:
            out.append(Finding("order", P, Topic.CHAIN_ORDER, "Chain order is leaf → issuer", path))
        else:
            out.append(
                Finding(
                    "order",
                    W,
                    Topic.CHAIN_ORDER,
                    "Certificates are out of order",
                    "Servers should send the leaf first, then each issuer. Expected: " + path,
                )
            )
        for i in range(len(chain) - 1):
            a, b = chain[i], chain[i + 1]
            if a.issuer != b.subject:
                out.append(
                    Finding(
                        f"unlinked-{i}",
                        W,
                        Topic.CHAIN_INCOMPLETE,
                        "Unrelated certificate in bundle",
                        f"{b.display_name} did not issue {a.display_name}.",
                    )
                )
        for i in range(len(chain) - 1):
            a, b = chain[i], chain[i + 1]
            if a.issuer == b.subject and a.aki is not None and b.ski is not None and a.aki != b.ski:
                out.append(
                    Finding(
                        f"aki-{i}",
                        W,
                        Topic.CHAIN_INCOMPLETE,
                        "Authority key ID mismatch",
                        f"{a.display_name} names an issuer key that does not match {b.display_name}. "
                        "The issuing CA may have been re-keyed; use the matching intermediate.",
                    )
                )
    top = chain[-1]
    if not top.is_self_issued:
        out.append(
            Finding(
                "top",
                I,
                Topic.CHAIN_INCOMPLETE,
                "Bundle stops at an issued certificate",
                f"The last certificate ({top.display_name}) was issued by {top.issuer_text}. Servers must send "
                "every intermediate; the root may be omitted. "
                "Trust evaluation below shows whether the chain completes.",
            )
        )

    for i, c in enumerate(chain):
        who = "Leaf" if i == 0 else c.display_name
        days = _days(c.not_after - now)
        if now < c.not_before:
            out.append(
                Finding(
                    f"nb-{i}",
                    F,
                    Topic.EXPIRY,
                    f"{who} is not yet valid",
                    f"Valid from {fmt(c.not_before)}. Check the server clock and the certificate issue date.",
                )
            )
        elif now > c.not_after:
            out.append(
                Finding(
                    f"exp-{i}",
                    F,
                    Topic.EXPIRY,
                    f"{who} expired {fmt(c.not_after)}",
                    "Renew and deploy a replacement certificate.",
                )
            )
        elif days <= WARN_DAYS:
            out.append(
                Finding(
                    f"exp-{i}",
                    W,
                    Topic.EXPIRY,
                    f"{who} expires in {days} day{'' if days == 1 else 's'}",
                    f"Expires {fmt(c.not_after)}. Plan renewal now.",
                )
            )
        elif i == 0:
            out.append(
                Finding(f"exp-{i}", P, Topic.EXPIRY, f"Leaf valid for {days} days", f"Expires {fmt(c.not_after)}.")
            )
        if c.signature_is_weak and not c.is_self_issued:
            out.append(
                Finding(
                    f"sig-{i}",
                    F,
                    Topic.WEAK_SIGNATURE,
                    f"{who} uses a weak signature ({c.signature_algorithm})",
                    "SHA-1 and MD5 signatures are rejected by current clients. Reissue with SHA-256 or stronger.",
                )
            )
        kind, val = c.key.algorithm
        if kind == "rsa" and isinstance(val, int) and val < 2048:
            out.append(
                Finding(
                    f"key-{i}",
                    F,
                    Topic.WEAK_KEY,
                    f"{who} has a weak {val}-bit RSA key",
                    "Use RSA 2048-bit or stronger, or ECDSA P-256.",
                )
            )
        elif kind == "other":
            out.append(Finding(f"key-{i}", I, Topic.WEAK_KEY, f"{who} uses an unrecognised key algorithm", str(val)))
    kind, val = leaf.key.algorithm
    if kind == "rsa" and isinstance(val, int) and val >= 2048:
        out.append(Finding("key-strength", P, Topic.WEAK_KEY, f"Leaf key: RSA {val}-bit"))
    if kind == "ec":
        out.append(Finding("key-strength", P, Topic.WEAK_KEY, f"Leaf key: ECDSA {val}"))
    if not leaf.signature_is_weak:
        out.append(Finding("sig", P, Topic.WEAK_SIGNATURE, f"Leaf signature: {leaf.signature_algorithm}"))

    if leaf.is_ca is True and purpose != Purpose.ANY:
        out.append(
            Finding(
                "ca-leaf",
                W,
                Topic.CA_LEAF,
                "Leaf certificate is a CA certificate",
                "A server or client certificate should have Basic Constraints CA:FALSE. "
                "Check that the correct file was selected.",
            )
        )
    if purpose != Purpose.ANY:
        needed = SERVER_AUTH if purpose == Purpose.TLS_SERVER else CLIENT_AUTH
        p = purpose.value.lower()
        if leaf.eku is not None:
            if needed in leaf.eku:
                out.append(Finding("eku", P, Topic.EKU, f"Extended key usage allows {p}"))
            elif ANY_EKU in leaf.eku:
                # Stricter than the Mac app (which passes this): OpenSSL's TLS purposes reject an
                # anyExtendedKeyUsage-only leaf, so web fails it in both analysis and trust.
                out.append(
                    Finding(
                        "eku",
                        F,
                        Topic.EKU,
                        f"Extended key usage is anyExtendedKeyUsage only, not {oid_name(needed)}",
                        f"TLS libraries differ on this; reissue with {oid_name(needed)}.",
                    )
                )
            else:
                out.append(
                    Finding(
                        "eku",
                        F,
                        Topic.EKU,
                        f"Extended key usage does not allow {p}",
                        "Present: "
                        + ", ".join(oid_name(o) for o in leaf.eku)
                        + f". Reissue from a template that includes {oid_name(needed)}.",
                    )
                )
        else:
            out.append(
                Finding(
                    "eku",
                    I,
                    Topic.EKU,
                    "No extended key usage extension",
                    f"Most clients accept this, but CA templates normally include {oid_name(needed)}.",
                )
            )
    if not leaf.has_san and purpose == Purpose.TLS_SERVER:
        out.append(
            Finding(
                "san",
                W,
                Topic.NO_SAN,
                "Leaf has no Subject Alternative Name",
                "Browsers, macOS and Java ignore the Common Name for hostname checks. "
                "Reissue with the DNS names in the SAN.",
            )
        )
    host = (hostname or "").strip()
    if host:
        matched, cn_only = leaf.matches(host)
        if matched and cn_only:
            out.append(
                Finding(
                    "host",
                    W,
                    Topic.HOSTNAME,
                    f"{host} matches only the Common Name",
                    f"Add {host} to the SAN; modern clients will reject this certificate.",
                )
            )
        elif matched:
            out.append(Finding("host", P, Topic.HOSTNAME, f"Certificate covers {host}"))
        else:
            names = list(leaf.dns_names) + list(leaf.ip_addresses)
            out.append(
                Finding(
                    "host",
                    F,
                    Topic.HOSTNAME,
                    f"Certificate does not cover {host}",
                    "Names in certificate: " + ", ".join(names) if names else "The certificate lists no SAN names.",
                )
            )
    lifetime = _days(leaf.not_after - leaf.not_before)
    if purpose == Purpose.TLS_SERVER and lifetime > MAX_PUBLIC_LIFETIME_DAYS and not leaf.is_self_issued:
        out.append(
            Finding(
                "lifetime",
                I,
                Topic.LONG_VALIDITY,
                f"Leaf lifetime is {lifetime} days",
                "Publicly trusted TLS certificates are limited to 398 days or less. "
                "This is acceptable for a private AD CS or pfSense CA.",
            )
        )

    for k, key in enumerate(keys):
        owner = next((x for x in chain if x.key.material == key.material), None)
        if owner is None:
            out.append(
                Finding(
                    f"keymatch-{k}",
                    F,
                    Topic.KEY_MISMATCH,
                    "Private key does not match any certificate",
                    "The key's public half differs from every certificate supplied. "
                    "Find the key generated with this certificate's CSR, or reissue.",
                )
            )
        else:
            is_leaf = owner.sha256 == leaf.sha256
            out.append(
                Finding(
                    f"keymatch-{k}",
                    P if is_leaf else W,
                    Topic.KEY_MISMATCH,
                    "Private key matches the leaf certificate"
                    if is_leaf
                    else f"Private key matches {owner.display_name}, not the leaf",
                    "Compared public key material derived in memory.",
                )
            )
    for i, r in enumerate(requests):
        out += evaluate_request(r, i, keys)
        if r.key.material == leaf.key.material:
            out.append(Finding(f"csr-cert-{i}", P, Topic.CSR, "CSR key matches the leaf certificate"))
        else:
            out.append(
                Finding(
                    f"csr-cert-{i}",
                    I,
                    Topic.CSR,
                    "CSR key differs from the leaf certificate",
                    "Expected after a re-key; a renewal using the same key would match.",
                )
            )
    return sort_findings(out)


def evaluate_request(r: Request, i: int, keys: list[KeyInfo]) -> list[Finding]:
    names = ", ".join(list(r.dns_names) + list(r.ip_addresses)) or "none requested"
    out = [
        Finding(
            f"csr-{i}",
            I,
            Topic.CSR,
            f"CSR for {r.common_name or r.subject_text}",
            f"Key: {r.key.description}. SAN: {names}",
        )
    ]
    if not r.dns_names and not r.ip_addresses:
        out.append(
            Finding(
                f"csr-san-{i}",
                W,
                Topic.NO_SAN,
                "CSR requests no SAN names",
                "Add the service DNS names as SANs before submitting.",
            )
        )
    kind, val = r.key.algorithm
    if kind == "rsa" and isinstance(val, int) and val < 2048:
        out.append(
            Finding(
                f"csr-key-{i}", F, Topic.WEAK_KEY, f"CSR key is {val}-bit RSA", "Generate a 2048-bit or stronger key."
            )
        )
    if r.signature_oid in WEAK_SIGNATURES:
        out.append(Finding(f"csr-sig-{i}", W, Topic.WEAK_SIGNATURE, f"CSR signed with {r.signature_algorithm}"))
    for k, key in enumerate(keys):
        if key.material == r.key.material:
            out.append(Finding(f"csr-keymatch-{i}-{k}", P, Topic.KEY_MISMATCH, "Private key matches the CSR"))
    return out
