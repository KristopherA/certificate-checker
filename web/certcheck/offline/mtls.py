"""Offline client certificate + key validation against a CA, in memory only (Stack.swift MTLSPair).

The client certificate is never presented in a live handshake. Deviation: the chain to the supplied CA is verified with
that CA as the only anchor (chaincheck.verify), the same as the Mac, whose anchor here is the supplied CA too."""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .. import analysis, chaincheck
from ..adjust import non_ca_warnings
from ..filecheck import MAX_FILE_SIZE, FileReport
from ..filecheck import load as file_load
from ..model import Finding, Severity, Topic, sort_findings, unique_by
from ..radius import read_files
from ..x509info import Cert, KeyInfo, oid_name

CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
ANY_EKU = "2.5.29.37.0"


@dataclass(frozen=True)
class Context:
    server: str
    verifier: str
    key_setting: str
    pair_settings: str
    ca_setting: str


BEATS = Context(
    "The Logstash beats input / Elasticsearch",
    "Java (Logstash, Elasticsearch)",
    "ssl.key in filebeat.yml",
    "ssl.certificate and ssl.key",
    "Logstash ssl_certificate_authorities, Elasticsearch xpack.security.http.ssl.certificate_authorities",
)
MUNKI = Context(
    "The Munki repo web server",
    "The repo web server",
    "ClientKeyPath in ManagedInstalls (or --key)",
    "ClientCertificatePath and ClientKeyPath",
    "the CA the repo web server trusts for clients, or SoftwareRepoCACertificate",
)


def f(fid: str, s: Severity, kind: str, title: str, detail: str = "") -> Finding:
    return Finding(fid, s, Topic.STACK, title, detail, kind=kind)


def verifies(
    leaf: Cert, intermediates: Sequence[Cert], ca: Sequence[Cert], now: dt.datetime
) -> tuple[bool, list[Cert], str]:
    """Stack.verifies: leaf -> ... -> a certificate from `ca`, verified with that CA as the only anchor."""
    hashes = {c.sha256 for c in ca}
    path = chaincheck.chain(leaf, [c for c in intermediates if c.sha256 not in hashes] + list(ca))
    k = next((i for i, c in enumerate(path) if c.sha256 in hashes), None)
    if k is not None:
        path = path[: k + 1]
    if not (path[-1].sha256 in hashes and (len(path) > 1 or leaf.sha256 in hashes)):
        names = ", ".join(c.display_name for c in ca)
        return False, path, f"Issuer {path[-1].issuer_text} is not in the supplied CA file ({names})."
    ok, msg = chaincheck.verify(path, now, ca)
    return ok, path, "" if ok else msg


def evaluate(
    certs: Sequence[Cert], keys: Sequence[KeyInfo], ca: Sequence[Cert], now: dt.datetime, c: Context = BEATS
) -> tuple[list[Cert], list[Finding]]:
    leaf = next((x for x in certs if x.is_ca is not True), certs[0] if certs else None)
    if leaf is None:
        return [], [f("mtls-none", Severity.FAIL, "mtls-client", "No client certificate found")]
    who = f"Client certificate {leaf.display_name}"
    out: list[Finding] = []
    days = int((leaf.not_after - now).total_seconds() / 86_400)
    if now < leaf.not_before:
        out.append(
            f(
                "mtls-valid",
                Severity.FAIL,
                "mtls-client",
                f"{who} is not yet valid",
                f"Valid from {analysis.fmt(leaf.not_before)}.",
            )
        )
    elif now > leaf.not_after:
        out.append(
            f(
                "mtls-valid",
                Severity.FAIL,
                "mtls-client",
                f"{who} expired {analysis.fmt(leaf.not_after)}",
                f"{c.server} will reject the handshake.",
            )
        )
    elif days <= analysis.WARN_DAYS:
        out.append(
            f("mtls-valid", Severity.WARNING, "mtls-client", f"{who} expires in {days} day{'' if days == 1 else 's'}")
        )
    else:
        out.append(
            f(
                "mtls-valid",
                Severity.PASS,
                "mtls-client",
                f"{who} valid for {days} more days",
                f"Expires {analysis.fmt(leaf.not_after)}.",
            )
        )
    if leaf.is_ca is True:
        out.append(
            f(
                "mtls-isca",
                Severity.FAIL,
                "mtls-client",
                f"{who} is a CA certificate",
                "Use an end-entity certificate (CA:FALSE).",
            )
        )
    if leaf.eku is not None:
        if CLIENT_AUTH in leaf.eku:
            out.append(f("mtls-eku", Severity.PASS, "mtls-client", f"{who} has the clientAuth EKU"))
        elif ANY_EKU in leaf.eku:
            srv = c.server[:1].lower() + c.server[1:]
            out.append(
                f(
                    "mtls-eku",
                    Severity.FAIL,
                    "mtls-client",
                    f"{who} has anyExtendedKeyUsage instead of clientAuth",
                    f"anyExtendedKeyUsage (2.5.29.37.0) does not name TLS Web Client Authentication. RFC 5280 says applications that require a specific purpose may reject it, and validators differ on whether they accept it in place of clientAuth, so {srv} may refuse the handshake. Reissue with extendedKeyUsage=clientAuth.",
                )
            )
        else:
            out.append(
                f(
                    "mtls-eku",
                    Severity.FAIL,
                    "mtls-client",
                    f"{who} lacks the clientAuth EKU",
                    f"Present: {', '.join(oid_name(o) for o in leaf.eku)}. {c.verifier} rejects client certificates whose EKU excludes TLS Web Client Authentication. Reissue with extendedKeyUsage=clientAuth.",
                )
            )
    else:
        out.append(
            f(
                "mtls-eku",
                Severity.INFO,
                "mtls-client",
                f"{who} has no Extended Key Usage",
                "Accepted for any purpose; prefer extendedKeyUsage=clientAuth when reissuing.",
            )
        )
    if not keys:
        out.append(
            f(
                "mtls-key",
                Severity.WARNING,
                "mtls-key",
                "No private key supplied",
                f"Add the key file named by {c.key_setting} to confirm it matches.",
            )
        )
    for k, key in enumerate(keys):
        out.append(
            f(
                f"mtls-key-{k}",
                Severity.PASS,
                "mtls-key",
                "Private key matches the client certificate",
                "Compared in memory; the key is not shown.",
            )
            if key.material == leaf.key.material
            else f(
                f"mtls-key-{k}",
                Severity.FAIL,
                "mtls-key",
                "Private key does not match the client certificate",
                f"{c.pair_settings} must be a pair. The handshake fails with a signature or bad-certificate error.",
            )
        )
    chain = [leaf]
    if not ca:
        out.append(
            f(
                "mtls-ca",
                Severity.WARNING,
                "mtls-ca",
                "No CA supplied",
                f"Add the CA the server trusts for clients ({c.ca_setting}) with --ca.",
            )
        )
    else:
        out += non_ca_warnings(ca)
        ok, chain, msg = verifies(leaf, [x for x in certs if x.sha256 != leaf.sha256], ca, now)
        out.append(
            f(
                "mtls-ca",
                Severity.PASS,
                "mtls-ca",
                f"Client certificate chains to the supplied CA {chain[-1].display_name}",
                " → ".join(x.display_name for x in chain),
            )
            if ok
            else f("mtls-ca", Severity.FAIL, "mtls-ca", "Client certificate does not chain to the supplied CA", msg)
        )
    out.append(
        f(
            "mtls-handshake",
            Severity.INFO,
            "mtls-client",
            "Client certificate not presented in a live handshake",
            "Not implemented: presenting it needs the private key in a TLS client identity. Keys stay in memory only, so only this offline check is done.",
        )
    )
    return chain, sort_findings(out)


def inspect_data(
    items: Sequence[tuple[str, bytes]],
    ca_items: Sequence[tuple[str, bytes]],
    now: dt.datetime | None = None,
    context: Context = BEATS,
) -> tuple[list[Cert], list[Finding]]:
    now = now or dt.datetime.now(dt.UTC)
    rep, ca_rep, notes = FileReport(), FileReport(), []
    for name, data in items:
        try:
            file_load(name, data, rep)
        except ValueError as e:
            notes.append(f(f"parse-{name}", Severity.FAIL, "info", f"Could not parse {name}", str(e)))
    for name, data in ca_items:
        try:
            file_load(name, data, ca_rep)
        except ValueError as e:
            notes.append(f(f"parse-ca-{name}", Severity.FAIL, "info", f"Could not parse CA file {name}", str(e)))
    certs = unique_by(rep.certificates, lambda c: c.sha256)
    chain, out = evaluate(certs, rep.keys, ca_rep.certificates, now, context)
    return chain, sort_findings(notes + out)


def inspect(
    paths: Sequence[Path], ca: Sequence[Path], now: dt.datetime | None = None, context: Context = BEATS
) -> tuple[list[Cert], list[Finding]]:
    items, pre = read_files(paths, MAX_FILE_SIZE, "2 MB", Topic.STACK)
    ca_items, pre2 = read_files(ca, MAX_FILE_SIZE, "2 MB", Topic.STACK)
    chain, out = inspect_data(items, ca_items, now, context)
    return chain, sort_findings(pre + pre2 + out)
