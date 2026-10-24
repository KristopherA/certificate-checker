"""Offline inspection of PEM/DER files: the FileCheck.inspect path the goldens were recorded with.

PEM and DER certificates, CSRs, PKCS#7 bags (.p7b/.p7c), PFX/P12 (opened in memory; the password is
never stored or logged) and unencrypted private keys. Encrypted PKCS#8 keys are refused, as on the Mac.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from cryptography.exceptions import UnsupportedAlgorithm

from . import analysis, pfx, trust
from .model import Finding, Purpose, Severity, Topic, sort_findings
from .x509info import Cert, KeyInfo, Request, key_info, parse_cert, parse_request, private_key_facts

PFX_PASSWORD = "The PFX/P12 password is incorrect."  # noqa: S105 - a user-facing message, not a password
PFX_CORRUPT = "The PFX/P12 file is damaged or not a PFX/P12 file."
PFX_ITERATIONS = f"The PFX/P12 uses more than {1_000_000:,} key-derivation iterations and is refused."

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
    key_formats: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    trust: trust.TrustResult | None = None

    @property
    def chain(self) -> list[Cert]:
        return analysis.ordered_chain(self.certificates)


def pkcs7_certificates(der: bytes) -> list[Cert]:
    """Certificates in a PKCS#7 / CMS SignedData bag. An empty bag gives []."""
    import warnings

    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)  # unsorted SET OF certificates: parsed as BER, as the Mac does
            certs = pkcs7.load_der_pkcs7_certificates(der)
    except ValueError as e:
        if "no certificates" in str(e).lower():  # a SignedData without a certificates field
            return []
        raise ValueError("Not PKCS#7 SignedData") from e
    return [parse_cert(c.public_bytes(Encoding.DER)) for c in certs]


PFX_TIME_BUDGET_S = 10.0  # wall-clock limit for one PFX decryption (pfx_worker), review M3c
_WORKER_CODE = (
    "import sys; sys.path.insert(0, sys.argv[1]); from certcheck.pfx_worker import main; raise SystemExit(main())"
)
PFX_TIMEOUT = "The PFX/P12 took too long to open (key derivation over the time limit) and is refused."


def _pkcs12_worker(data: bytes, password: str) -> dict[str, object]:
    """cryptography's load_pkcs12 in a child process killed after PFX_TIME_BUDGET_S (pfx_worker docstring)."""
    import json
    import subprocess
    import sys

    pw = password.encode()
    payload = len(pw).to_bytes(4, "big") + pw + data
    root = str(Path(__file__).resolve().parent.parent)
    env = {"PYTHONPATH": root, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONSAFEPATH": "1"}
    with subprocess.Popen(  # noqa: S603 - fixed argv, no shell; the password goes over stdin only
        [sys.executable, "-I", "-c", _WORKER_CODE, root],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
    ) as p:  # fmt: skip
        try:
            out, _ = p.communicate(payload, timeout=PFX_TIME_BUDGET_S)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            raise ValueError(PFX_TIMEOUT) from None
    try:
        res = json.loads(out)
    except ValueError:
        raise ValueError(PFX_CORRUPT) from None
    if not isinstance(res, dict):
        raise ValueError(PFX_CORRUPT)
    return res


def load_pkcs12(data: bytes, password: str | None, r: FileReport) -> None:
    """Open a PFX in a time-limited worker. The password is used once and not kept."""
    import base64

    from cryptography.hazmat.primitives.serialization import load_der_public_key

    try:
        params = pfx.read_params(data)
    except pfx.Corrupt:
        raise ValueError(PFX_CORRUPT) from None
    if any(n < 1 or n > pfx.MAX_ITERATIONS for n in params.iterations):
        raise ValueError(PFX_ITERATIONS)
    res = _pkcs12_worker(data, password or "")
    if res.get("status") != "ok":
        # Review S6: tell a wrong password from a corrupt file where the MAC can be checked independently.
        if pfx.mac_matches(params, password or "") is True:
            raise ValueError(PFX_CORRUPT)
        raise ValueError(PFX_PASSWORD)
    certs = cast(list[str], res.get("certs") or [])
    r.certificates += [parse_cert(base64.b64decode(c)) for c in certs]
    spki = res.get("spki")
    if isinstance(spki, str):
        r.keys.append(key_info(load_der_public_key(base64.b64decode(spki))))
        r.key_formats.append("PFX identity")


def load(name: str, data: bytes, r: FileReport, password: str | None = None) -> None:
    if Path(name).suffix.lower() in (".pfx", ".p12"):
        load_pkcs12(data, password, r)
        return
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
            elif label == "PKCS7":
                from cryptography.hazmat.primitives.serialization import pkcs7

                der = pkcs7.load_pem_pkcs7_certificates(block) if b"PKCS7" in block else []
                r.certificates += [parse_cert(c.public_bytes(serialization.Encoding.DER)) for c in der]
            elif label.endswith("PRIVATE KEY"):
                info, fmt = private_key_facts(label, block)
                r.keys.append(info)
                r.key_formats.append(fmt)
            elif label == "PUBLIC KEY":
                r.keys.append(key_info(serialization.load_pem_public_key(block)))
            else:
                r.notes.append(Finding(f"pem-{label}", Severity.INFO, Topic.GENERAL, f"Skipped PEM block {label}"))
        return
    for parse in (parse_cert, parse_request):
        try:
            got = parse(data)
        except ValueError:
            continue
        (r.certificates if isinstance(got, Cert) else r.requests).append(got)  # type: ignore[arg-type]
        return
    try:
        certs = pkcs7_certificates(data)
    except ValueError:
        certs = []
    if certs:
        r.certificates += certs
        return
    if data[:1] == b"\x30" and password is not None:
        load_pkcs12(data, password, r)
        return
    raise ValueError("Not a recognised PEM, DER certificate, CSR, PKCS#7 or PFX file.")


def inspect(
    paths: list[Path],
    hostname: str | None,
    purpose: Purpose,
    *,
    now: dt.datetime | None = None,
    anchors: Path | None = None,
    password: str | None = None,
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
    r = inspect_data(items, hostname, purpose, now=now, anchors=anchors, password=password)
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
    password: str | None = None,
) -> FileReport:
    now = now or dt.datetime.now(dt.UTC)
    r = FileReport()
    for name, data in items:
        try:
            if len(data) > MAX_FILE_SIZE:
                raise ValueError("File is larger than 2 MB.")
            load(name, data, r, password)
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
