"""RADIUS server certificate checks for EAP-TLS / PEAP / TTLS (Radius.swift).

Offline checks read PEM/DER/PKCS#7 files. The live probe runs eapol_test once (anonymous outer identity, dummy
inner credentials, no retries) only to capture the server certificate chain. The shared secret is held in memory
only: it reaches eapol_test as an argv element (-s), never a shell, file or log, and is redacted from the transcript.

Deviation from the Mac (shared/known-differences.yaml): rad-chain PASS needs the top certificate to be
anchored (a verifying self-signature). Radius.swift:92-93 passes the top certificate to SecTrust as its own
anchor, so a chain whose root was never supplied reports "Chain verifies" (a false PASS).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import ipaddress
import os
import shutil
import socket
import subprocess
import tempfile
import threading
from collections.abc import Sequence
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import cast

from . import analysis, chaincheck, filecheck, probe
from .model import Finding, Severity, Topic, sort_findings, unique_by
from .x509info import SERVER_AUTH, Cert, KeyInfo, oid_name

APPLE_MAX_DAYS = 825
WHO = "RADIUS server certificate"


def f(fid: str, s: Severity, kind: str, title: str, detail: str = "") -> Finding:
    return Finding(fid, s, Topic.RADIUS, title, detail, kind=kind)


def days_between(later: dt.datetime, earlier: dt.datetime) -> int:
    """Int(interval / 86_400) in Swift: truncates toward zero."""
    return int((later - earlier).total_seconds() / 86_400)


def inspect_data(
    items: Sequence[tuple[str, bytes]], expected_name: str | None, *, now: dt.datetime | None = None
) -> tuple[list[Cert], list[Finding]]:
    now = now or dt.datetime.now(dt.UTC)
    rep = filecheck.FileReport()
    notes: list[Finding] = []
    for name, data in items:
        try:
            if len(data) > filecheck.MAX_FILE_SIZE:
                raise ValueError("File is larger than 2 MB.")
            filecheck.load(name, data, rep)
        except (ValueError, TypeError) as e:
            notes.append(f(f"parse-{name}", Severity.FAIL, "info", f"Could not parse {name}", str(e)))
    unique: dict[str, Cert] = {}
    for c in rep.certificates:
        unique.setdefault(c.sha256, c)
    chain = analysis.ordered_chain(list(unique.values()))
    return chain, sort_findings(notes + evaluate(chain, rep.keys, expected_name, now=now))


def inspect(
    paths: Sequence[Path], expected_name: str | None, *, now: dt.datetime | None = None
) -> tuple[list[Cert], list[Finding]]:
    items, pre = read_files(paths, filecheck.MAX_FILE_SIZE, "2 MB", Topic.RADIUS)
    chain, out = inspect_data(items, expected_name, now=now)
    return chain, sort_findings(pre + out)


def read_files(
    paths: Sequence[Path], limit: int, limit_text: str, topic: Topic
) -> tuple[list[tuple[str, bytes]], list[Finding]]:
    """Regular files only (symlinks are not followed), at most `limit` bytes, read in memory."""
    items: list[tuple[str, bytes]] = []
    pre: list[Finding] = []
    for p in paths:
        try:
            if p.is_symlink() or not p.is_file():
                raise ValueError("Not a regular file.")
            with p.open("rb") as fh:
                data = fh.read(limit + 1)
            if len(data) > limit:
                raise ValueError(f"File is larger than {limit_text}.")
            items.append((p.name, data))
        except (OSError, ValueError) as e:
            pre.append(Finding(f"read-{p.name}", Severity.FAIL, topic, f"Could not read {p.name}", str(e), kind="info"))
    return items, pre


def evaluate(
    chain: Sequence[Cert],
    keys: Sequence[KeyInfo] = (),
    expected_name: str | None = None,
    *,
    now: dt.datetime | None = None,
    anchors: Sequence[Cert] = (),
) -> list[Finding]:
    """`chain` must be leaf-first (analysis.ordered_chain or the order eapol_test received it)."""
    now = now or dt.datetime.now(dt.UTC)
    if not chain:
        return [f("rad-none", Severity.FAIL, "info", "No certificate found")]
    leaf = chain[0]
    out: list[Finding] = []
    fmt = analysis.fmt
    days = days_between(leaf.not_after, now)
    if now < leaf.not_before:
        out.append(
            f("rad-valid", Severity.FAIL, "reissue", f"{WHO} is not yet valid", f"Valid from {fmt(leaf.not_before)}.")
        )
    elif now > leaf.not_after:
        out.append(
            f(
                "rad-valid",
                Severity.FAIL,
                "reissue",
                f"{WHO} expired {fmt(leaf.not_after)}",
                "Every 802.1X client will refuse it. Renew and rebind it in NPS/FreeRADIUS.",
            )
        )
    elif days <= analysis.WARN_DAYS:
        out.append(
            f(
                "rad-valid",
                Severity.WARNING,
                "reissue",
                f"{WHO} expires in {days} day{'' if days == 1 else 's'}",
                "Renew now; clients that pinned the old certificate may prompt users.",
            )
        )
    else:
        out.append(
            f(
                "rad-valid",
                Severity.PASS,
                "reissue",
                f"{WHO} valid for {days} more days",
                f"Expires {fmt(leaf.not_after)}.",
            )
        )
    lifetime = int((leaf.not_after - leaf.not_before).total_seconds() // 86_400)
    if not leaf.is_self_issued and leaf.not_before >= chaincheck.APPLE_RULE_START and lifetime > APPLE_MAX_DAYS:
        out.append(
            f(
                "rad-lifetime",
                Severity.WARNING,
                "reissue",
                f"{WHO} lifetime is {lifetime} days (over 825)",
                "Apple's 825-day limit is documented for TLS server certificates issued on or after 1 July 2019. Enforcement for 802.1X varies by OS version, so reissue with 825 days or fewer if Apple devices use this network.",
            )
        )
    if leaf.eku is not None:
        if SERVER_AUTH in leaf.eku:
            out.append(f("rad-eku", Severity.PASS, "reissue", f"{WHO} has the serverAuth EKU"))
        else:
            names = ", ".join(oid_name(o) for o in leaf.eku)
            out.append(
                f(
                    "rad-eku",
                    Severity.FAIL,
                    "reissue",
                    f"{WHO} lacks the serverAuth EKU",
                    f"Present: {names}. Windows clients reject PEAP/EAP-TLS servers without Server Authentication, and NPS does not offer such certificates.",
                )
            )
    else:
        out.append(
            f(
                "rad-eku",
                Severity.WARNING,
                "reissue",
                f"{WHO} has no Extended Key Usage",
                "Windows expects Server Authentication (1.3.6.1.5.5.7.3.1). Reissue from a template with it.",
            )
        )
    if leaf.is_ca is True:
        out.append(
            f(
                "rad-isca",
                Severity.FAIL,
                "reissue",
                f"{WHO} is a CA certificate",
                "Use an end-entity server certificate (CA:FALSE).",
            )
        )
    name = (expected_name or "").strip(" ")
    if name:
        matched, via_cn = leaf.matches(name)
        if matched and not via_cn:
            out.append(f("rad-name", Severity.PASS, "name", f"{WHO} covers {name}"))
        elif matched or (leaf.common_name or "").lower() == name.lower():
            out.append(
                f(
                    "rad-name",
                    Severity.INFO,
                    "name",
                    f"{name} matches only the Common Name",
                    f"Windows ('Connect to these servers'), Android ('Domain') and Apple (TLSTrustedServerNames) accept the CN for 802.1X, but add {name} to the SAN when reissuing.",
                )
            )
        else:
            names = ", ".join(([leaf.common_name] if leaf.common_name else []) + list(leaf.dns_names)) or "none"
            out.append(
                f(
                    "rad-name",
                    Severity.FAIL,
                    "name",
                    f"{WHO} does not match {name}",
                    f"Names in certificate: {names}. Clients configured to expect {name} will refuse to connect.",
                )
            )
    else:
        out.append(
            f(
                "rad-name",
                Severity.INFO,
                "name",
                "No expected server name given",
                "Enter the name clients are configured to trust (Windows 'Connect to these servers', Android 'Domain', Apple TLSTrustedServerNames).",
            )
        )
    kind, v = leaf.key.algorithm
    if kind == "rsa" and int(v) < 2048:
        out.append(
            f(
                "rad-key",
                Severity.FAIL,
                "reissue",
                f"{WHO} has a weak {v}-bit RSA key",
                "Use RSA 2048+ or ECDSA P-256/P-384.",
            )
        )
    elif kind == "rsa":
        out.append(f("rad-key", Severity.PASS, "reissue", f"{WHO} key: RSA {v}-bit"))
    elif kind == "ec" and v in ("P-256", "P-384", "P-521"):
        out.append(f("rad-key", Severity.PASS, "reissue", f"{WHO} key: ECDSA {v}"))
    else:
        out.append(
            f(
                "rad-key",
                Severity.WARNING,
                "reissue",
                f"{WHO} key {leaf.key.description} may not be supported by 802.1X clients",
                "Use RSA 2048+ or ECDSA P-256/P-384.",
            )
        )
    for i, c in enumerate(chain):
        if i > 0 and c.is_self_issued:
            continue
        label = WHO if i == 0 else f"Issuer {c.display_name}"
        if c.signature_is_weak:
            out.append(
                f(
                    f"rad-sig-{i}",
                    Severity.FAIL,
                    "reissue",
                    f"{label} is signed with {c.signature_algorithm}",
                    "SHA-1/MD5 signatures are rejected by current clients. Reissue with SHA-256 or stronger.",
                )
            )
        elif i == 0:
            out.append(f("rad-sig-0", Severity.PASS, "reissue", f"{WHO} signature: {c.signature_algorithm}"))
    if len(chain) == 1:
        if leaf.is_self_issued:
            out.append(
                f(
                    "rad-chain",
                    Severity.WARNING,
                    "chain",
                    f"{WHO} is self-signed",
                    "Every client must trust this exact certificate, and must be updated when it is renewed. Prefer a certificate from your internal CA.",
                )
            )
        else:
            out.append(
                f(
                    "rad-chain",
                    Severity.WARNING,
                    "chain",
                    "Issuing CA not supplied",
                    f"Issuer: {leaf.issuer_text}. Add the CA clients trust to verify the chain.",
                )
            )
    else:
        for i in range(len(chain) - 1):
            if chain[i].issuer != chain[i + 1].subject:
                out.append(
                    f(
                        f"rad-unlinked-{i}",
                        Severity.FAIL,
                        "chain",
                        f"{chain[i + 1].display_name} did not issue {chain[i].display_name}",
                        "The server must send its own certificate followed by the issuing intermediates.",
                    )
                )
        for k, c in enumerate(chain):
            if k > 0 and c.is_ca is not True:
                out.append(
                    f(
                        f"rad-notca-{k}",
                        Severity.FAIL,
                        "chain",
                        f"Issuer {c.display_name} is not a CA",
                        "Its basicConstraints is not CA:TRUE.",
                    )
                )
        for k, c in enumerate(chain):
            if k > 0 and now > c.not_after:
                out.append(
                    f(f"rad-caexp-{k}", Severity.FAIL, "chain", f"Issuer {c.display_name} expired {fmt(c.not_after)}")
                )
        ok, msg = chaincheck.verify(chain, now, anchors)  # strict: the top must be anchored (Mac bug, see module doc)
        if ok:
            out.append(
                f(
                    "rad-chain",
                    Severity.PASS,
                    "chain",
                    f"Chain verifies to {chain[-1].display_name}",
                    " → ".join(c.display_name for c in chain),
                )
            )
        else:
            out.append(f("rad-chain", Severity.FAIL, "chain", "Chain does not verify", msg))
        top = chain[-1]
        if not chaincheck.is_self_signed(top):
            out.append(
                f(
                    "rad-top",
                    Severity.INFO,
                    "chain",
                    f"Chain stops at {top.display_name}",
                    f"Clients must already trust {top.issuer_text} (normally the root, deployed by GPO/MDM).",
                )
            )
    for k, key in enumerate(keys):
        if key.material == leaf.key.material:
            out.append(
                f(
                    f"rad-key-{k}",
                    Severity.PASS,
                    "keymatch",
                    "Private key matches the RADIUS server certificate",
                    "Compared in memory; the key is not shown.",
                )
            )
        else:
            out.append(
                f(f"rad-key-{k}", Severity.FAIL, "keymatch", "Private key does not match the RADIUS server certificate")
            )
    return out


# MARK: live probe


class EAPMethod(StrEnum):
    PEAP = "PEAP"
    TTLS = "TTLS"


@dataclass
class ProbeResult:
    transcript: list[str] = field(default_factory=list)
    chain: list[Cert] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped: bool = False


SEARCH_PATHS = (
    "/usr/local/bin/eapol_test",
    "/usr/local/sbin/eapol_test",
    "/usr/bin/eapol_test",
    "/usr/sbin/eapol_test",
)
TIMEOUT_SECONDS = 15
OUTPUT_CAP = 1_000_000
KEEP = ("EAP", "RADIUS", "SUCCESS", "FAILURE", "Access-", "TLS", "CTRL-EVENT", "timeout", "Timeout", "No response")


def valid_host(h: str) -> bool:
    """Target.validHost (Swift): ASCII letters, digits and "-.:_", at most 253, no leading "-", not only dots."""
    return (
        0 < len(h) <= 253
        and all(c.isascii() and (c.isalnum() or c in "-.:_") for c in h)
        and not h.startswith("-")
        and h.strip(".") != ""
    )


def locate() -> Path | None:
    for p in SEARCH_PATHS:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return Path(p)
    return None


def config(method: EAPMethod) -> str:
    """eapol_test network block: anonymous identity, dummy inner password, no ca_cert (only the chain is wanted)."""
    phase2 = "auth=MSCHAPV2" if method == EAPMethod.PEAP else "auth=PAP"
    return (
        "# Certificate Checker probe: anonymous outer identity, non-existent inner identity and dummy password. Contains no secrets.\n"
        "network={\n"
        "\tkey_mgmt=IEEE8021X\n"
        f"\teap={method.value}\n"
        '\tidentity="certchecker-probe@invalid.example"\n'
        '\tanonymous_identity="anonymous"\n'
        '\tpassword="certificate-checker-probe-not-a-credential"\n'
        f'\tphase2="{phase2}"\n'
        "}\n\n"
    )


def arguments(
    conf: str, address: str, port: int, secret: str, cert_out: str, timeout: int = TIMEOUT_SECONDS
) -> list[str]:
    return [
        "-c",
        conf,
        "-a",
        address,
        "-p",
        str(port),
        "-s",
        secret,
        "-o",
        cert_out,
        "-t",
        str(timeout),
        "-r",
        "0",
        "-n",
    ]


def resolve(
    host: str, port: int, policy: probe.TargetPolicy | None = None, timeout: float = probe.RESOLVE_TIMEOUT_S
) -> list[str]:
    """Numeric addresses for eapol_test -a, filtered by TargetPolicy exactly like the TCP probe (review B1).

    IP literals pass through; names resolve IPv4-only, one lookup on the shared resolver pool with a timeout
    (review S3). Raises OSError (no address, timeout, resolver busy) or TargetDenied (every address refused)."""
    policy = policy or probe.TargetPolicy.from_env()
    try:
        addrs = [str(ipaddress.ip_address(host))]
    except ValueError:
        if not probe._resolver_slots.acquire(blocking=False):
            raise OSError(f"Name lookup for {host} not started: resolver busy with earlier lookups") from None
        try:
            fut = probe._resolver_pool.submit(socket.getaddrinfo, host, None, socket.AF_INET, socket.SOCK_DGRAM)
        except BaseException:
            probe._resolver_slots.release()
            raise
        fut.add_done_callback(probe._release_slot)
        try:
            infos = fut.result(timeout=timeout)
        except FutureTimeout:
            raise OSError(f"Name lookup for {host} timed out after {timeout:g} s") from None
        except UnicodeError as e:
            raise OSError(str(e)) from None
        addrs = list(dict.fromkeys(str(i[4][0]) for i in infos))
    if not addrs:
        raise OSError(f"{host} did not resolve")
    allowed, denied = [], []
    for a in addrs:
        try:
            policy.check(a, port)
            allowed.append(a)
        except probe.TargetDenied as e:
            denied.append(e)
    if not allowed:
        raise denied[0]
    return allowed


def redact(output: str, secret: str) -> list[str]:
    """Only protocol status lines; drops hexdumps, MPPE keys and any line mentioning the secret."""
    lines = [
        ln
        for ln in output.splitlines()
        if any(k in ln for k in KEEP) and "hexdump" not in ln.lower() and "MPPE" not in ln
    ]
    if secret:
        lines = [ln.replace(secret, "•••") for ln in lines]
    lines = [ln for ln in lines if "secret" not in ln.lower()]
    return [ln[:300] for ln in lines[-40:]]


def run(
    host: str,
    port: int = 1812,
    method: EAPMethod = EAPMethod.PEAP,
    expected_name: str | None = None,
    *,
    secret: str,
    tool: Path | None = None,
    now: dt.datetime | None = None,
    timeout: int = TIMEOUT_SECONDS,
    grace: int = 5,
    anchors: Sequence[Cert] = (),
    policy: probe.TargetPolicy | None = None,
) -> ProbeResult:
    """One eapol_test run, never retried. Fixed argv, no shell, stdin closed, a private 0700 folder removed after."""
    r = ProbeResult()
    tool = tool or locate()
    if tool is None:
        r.skipped = True
        r.findings = [
            f(
                "rad-probe-tool",
                Severity.INFO,
                "install",
                "eapol_test is not installed; live probe skipped",
                "Install it (see How to fix) and run the probe again. Offline file checks still work.",
            )
        ]
        return r
    if not valid_host(host) or not 1 <= port <= 65535:
        r.findings = [f("rad-probe-input", Severity.FAIL, "probe", "Invalid host or port")]
        return r
    if not secret or "\0" in secret or len(secret.encode()) > 128:
        r.findings = [f("rad-probe-input", Severity.FAIL, "probe", "Shared secret must be 1–128 characters")]
        return r
    try:
        address = resolve(host, port, policy)[0]
    except probe.TargetDenied as e:
        r.findings = [f("rad-probe-input", Severity.FAIL, "probe", "Invalid host or port", str(e))]
        return r
    except (OSError, ValueError):
        r.findings = [
            f(
                "rad-probe-dns",
                Severity.FAIL,
                "probe",
                f"{host} did not resolve to an IPv4 address",
                "Name resolution is IPv4-only (eapol_test needs a numeric address). Check DNS, or enter the server IP; IPv6 literals are passed through as entered.",
            )
        ]
        return r
    tmp = tempfile.mkdtemp(prefix="certchecker-radius-")  # mode 0700
    p: subprocess.Popen[bytes] | None = None
    try:
        conf = os.path.join(tmp, "eapol.conf")
        certs = os.path.join(tmp, "server-chain.pem")
        fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(config(method))
        argv = [str(tool), *arguments(conf, address, port, secret, certs, timeout)]
        p = subprocess.Popen(  # noqa: S603 - fixed argv list, shell=False; secret is in argv (documented limitation)
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=tmp, shell=False
        )
        buf = bytearray()
        assert p.stdout is not None
        out = cast(io.BufferedReader, p.stdout)

        def pump() -> None:
            while chunk := out.read1(65536):
                if len(buf) < OUTPUT_CAP:
                    buf.extend(chunk[: OUTPUT_CAP - len(buf)])

        reader = threading.Thread(target=pump, daemon=True)
        reader.start()
        timed_out = killed = False
        try:
            p.wait(timeout + grace)
        except subprocess.TimeoutExpired:
            timed_out = True
            p.terminate()
            try:
                p.wait(2)
            except subprocess.TimeoutExpired:
                p.kill()
                killed = True
                with contextlib.suppress(subprocess.TimeoutExpired):
                    p.wait(2)
        reader.join(None if not timed_out else 1)  # children may still hold the pipe after a kill: keep what was read
        text = bytes(buf).decode("utf-8", "replace")
        via = "" if address == host else f" ({address})"
        r.transcript = [f"eapol_test {method.value} → {host}{via}:{port}, one attempt", *redact(text, secret)]
        if timed_out:
            how = "killed (SIGKILL after ignoring SIGTERM)" if killed else "stopped"
            r.findings.append(
                f(
                    "rad-probe-timeout",
                    Severity.FAIL,
                    "probe",
                    f"eapol_test did not finish in {timeout + grace} s and was {how}",
                )
            )
        data = Path(certs).read_bytes() if os.path.isfile(certs) else b""
        if data:
            rep = filecheck.FileReport()
            with contextlib.suppress(ValueError, TypeError):
                filecheck.load("server-chain.pem", data[: filecheck.MAX_FILE_SIZE], rep)
            # eapol_test -o (eapol_test.c eapol_test_cert_cb) writes one PEM per OpenSSL verify-callback call
            # (tls_openssl.c tls_verify_cb -> openssl_tls_cert_event): the path OpenSSL BUILT, top (deepest) first
            # down to the leaf, not the wire order; certificates the server sent that are not on that path are
            # absent, and the leaf can repeat (tls_openssl.c ~2937-2953 re-emits depth 0 when depth > 0 fails).
            # Radius.swift:211 assumes leaf-first (see known-differences). De-duplicate, then order leaf-first.
            r.chain = analysis.ordered_chain(unique_by(rep.certificates, lambda c: c.sha256))
        if not r.chain:
            r.findings.append(
                f(
                    "rad-probe-nocert",
                    Severity.FAIL,
                    "probe",
                    "No server certificate was received",
                    f"Check that this server's IP is a RADIUS client (NAS) on the server, the shared secret, and that UDP {port} is allowed. A wrong secret usually looks like no response.",
                )
            )
        else:
            n = len(r.chain)
            r.findings.append(
                f(
                    "rad-probe-ok",
                    Severity.INFO,
                    "probe",
                    f"Received {n} certificate{'' if n == 1 else 's'} from the server",
                    "The authentication itself is expected to fail: the probe uses dummy credentials.",
                )
            )
            # No rad-order here: the wire order is not visible in eapol_test's output file (see above).
            r.findings += evaluate(r.chain, (), expected_name, now=now, anchors=anchors)
    except OSError as e:
        r.findings.append(
            f("rad-probe-run", Severity.FAIL, "probe", "eapol_test could not be run", e.strerror or type(e).__name__)
        )
    finally:
        if p is not None and p.poll() is None:  # any exception above (review S3): never leave eapol_test running
            p.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                p.wait(2)
        shutil.rmtree(tmp, ignore_errors=True)
    r.findings = sort_findings(r.findings)
    return r
