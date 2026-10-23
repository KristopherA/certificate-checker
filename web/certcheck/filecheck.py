"""Offline inspection of PEM/DER files: the FileCheck.inspect path the goldens were recorded with.

M1 covers PEM and DER certificates, CSRs and unencrypted private keys. PKCS#7 and PFX arrive in M3.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm

from . import analysis, trust
from .model import Finding, Purpose, Severity, Topic, sort_findings
from .x509info import Cert, KeyInfo, Request, key_info, parse_cert, parse_request, private_key_info

MAX_FILE_SIZE = 2 * 1024 * 1024
MAX_PEM_BLOCKS = 256
BEGIN, END, DASHES = b"-----BEGIN ", b"-----END ", b"-----"
LABEL = re.compile(rb"[A-Z0-9 ]{1,64}")


def pem_blocks(data: bytes) -> list[tuple[str, bytes]]:
    """Linear scan: each BEGIN pairs with the next END; never backtracks (no regex over the body).

    A BEGIN whose next END has another label is skipped with it. More than MAX_PEM_BLOCKS blocks is an error."""
    out: list[tuple[str, bytes]] = []
    pos = 0
    while (b := data.find(BEGIN, pos)) != -1:
        lab_end = data.find(DASHES, b + len(BEGIN), b + len(BEGIN) + 70)
        if lab_end == -1:
            pos = b + len(BEGIN)
            continue
        label = data[b + len(BEGIN) : lab_end]
        e = data.find(END, lab_end)
        if e == -1:
            break
        e_end = data.find(DASHES, e + len(END), e + len(END) + 70)
        if not LABEL.fullmatch(label) or e_end == -1 or data[e + len(END) : e_end] != label:
            pos = e + len(END)  # skip past this END: every byte is scanned a bounded number of times
            continue
        if len(out) >= MAX_PEM_BLOCKS:
            raise ValueError(f"More than {MAX_PEM_BLOCKS} PEM blocks.")
        out.append((label.decode(), data[b : e_end + len(DASHES)] + b"\n"))
        pos = e_end + len(DASHES)
    return out


@dataclass
class FileReport:
    certificates: list[Cert] = field(default_factory=list)
    requests: list[Request] = field(default_factory=list)
    keys: list[KeyInfo] = field(default_factory=list)
    notes: list[Finding] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    trust: trust.TrustResult | None = None

    @property
    def chain(self) -> list[Cert]:
        return analysis.ordered_chain(self.certificates)


def load(name: str, data: bytes, r: FileReport) -> None:
    if b"-----BEGIN " in data:
        blocks = pem_blocks(data)
        if not blocks:
            raise ValueError("PEM markers found but no block could be decoded.")
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        for label, block in blocks:
            if label in ("CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE"):
                c = x509.load_pem_x509_certificate(block)
                r.certificates.append(parse_cert(c.public_bytes(serialization.Encoding.DER)))
            elif label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
                q = x509.load_pem_x509_csr(block)
                r.requests.append(parse_request(q.public_bytes(serialization.Encoding.DER)))
            elif label.endswith("PRIVATE KEY"):
                r.keys.append(private_key_info(block))
            elif label == "PUBLIC KEY":
                r.keys.append(key_info(serialization.load_pem_public_key(block)))
            else:
                r.notes.append(Finding(f"pem-{label}", Severity.INFO, Topic.GENERAL, f"Skipped PEM block {label}"))
        return
    try:
        r.certificates.append(parse_cert(data))
        return
    except ValueError:
        pass
    try:
        r.requests.append(parse_request(data))
        return
    except ValueError:
        pass
    raise ValueError("Not a recognised PEM, DER certificate or CSR file.")


def inspect(
    paths: list[Path],
    hostname: str | None,
    purpose: Purpose,
    *,
    now: dt.datetime | None = None,
    anchors: Path | None = None,
) -> FileReport:
    items: list[tuple[str, bytes]] = []
    notes: list[Finding] = []
    for p in paths:
        try:
            if not p.is_file():
                raise ValueError("Not a regular file.")
            with p.open("rb") as fh:
                data = fh.read(MAX_FILE_SIZE + 1)
            if len(data) > MAX_FILE_SIZE:
                raise ValueError("File is larger than 2 MB.")
            items.append((p.name, data))
        except (OSError, ValueError) as e:
            notes.append(Finding(f"read-{p.name}", Severity.FAIL, Topic.GENERAL, f"Could not read {p.name}", str(e)))
    r = inspect_data(items, hostname, purpose, now=now, anchors=anchors)
    r.notes = notes + r.notes
    r.findings = sort_findings(notes + r.findings)
    return r


def inspect_data(
    items: list[tuple[str, bytes]],
    hostname: str | None,
    purpose: Purpose,
    *,
    now: dt.datetime | None = None,
    anchors: Path | None = None,
) -> FileReport:
    now = now or dt.datetime.now(dt.UTC)
    r = FileReport()
    for name, data in items:
        try:
            if len(data) > MAX_FILE_SIZE:
                raise ValueError("File is larger than 2 MB.")
            load(name, data, r)
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            r.notes.append(Finding(f"parse-{name}", Severity.FAIL, Topic.GENERAL, f"Could not parse {name}", str(e)))
    unique: dict[str, Cert] = {}
    for c in r.certificates:
        unique.setdefault(c.sha256, c)  # first occurrence wins, order kept
    r.certificates = list(unique.values())
    f = r.notes + analysis.evaluate(r.certificates, hostname, purpose, now=now, keys=r.keys, requests=r.requests)
    if r.certificates:
        r.trust = trust.verify(r.chain, hostname=hostname, purpose=purpose, now=now, anchors=anchors)
        f.append(trust.finding(r.trust, "offline"))
    r.findings = sort_findings(f)
    return r
