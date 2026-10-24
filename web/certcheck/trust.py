"""Trust evaluation with OpenSSL (`openssl verify -x509_strict`), plus the explicit TLS policy
that macOS SecTrust applies and OpenSSL does not (see shared/known-differences.yaml).

Runs the openssl CLI with a fixed argv (no shell), a short timeout and a private 0700 temp
directory that is removed before returning. Never fetches AIA, OCSP or CRLs.
"""

from __future__ import annotations

import datetime as dt
import functools
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding

from .model import Finding, Purpose, Severity, Topic
from .x509info import CLIENT_AUTH, SERVER_AUTH, Cert, oid_name, wildcard_match

TIMEOUT_S = 10
# Apple: TLS server certificates may be valid for at most 825 days, whatever the CA (HT210176).
APPLE_MAX_TLS_DAYS = 825
APPLE_825_FROM = dt.datetime(2019, 7, 1, tzinfo=dt.UTC)  # applies to certificates issued on or after this
HOMEBREW = (
    "/opt/homebrew/opt/openssl/bin/openssl",
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/usr/local/opt/openssl/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
)
ERROR_LINE = re.compile(r"error (\d+) at (\d+) depth lookup: (.+)")


class OpenSSLMissing(RuntimeError):
    pass


VERSION = re.compile(r"^OpenSSL (\d+)\.(\d+)\.(\d+)")


def openssl_binary() -> tuple[str, str]:
    """Cached per (CERTCHECK_OPENSSL, PATH); see _find_openssl."""
    return _find_openssl(os.environ.get("CERTCHECK_OPENSSL"), os.environ.get("PATH", ""))


@functools.lru_cache(maxsize=8)
def _find_openssl(env: str | None, _path: str) -> tuple[str, str]:
    """(path, version): CERTCHECK_OPENSSL, else the first OpenSSL >= 3 on PATH or in Homebrew.

    LibreSSL is refused. The container pins /usr/bin/openssl via CERTCHECK_OPENSSL (M7); CI parity
    must run on that pinned OpenSSL, not on whatever the build host has."""
    candidates = [env] if env else [shutil.which("openssl") or "", *HOMEBREW]
    for c in candidates:
        if not (c and Path(c).is_file()):
            continue
        try:
            v = subprocess.run(  # noqa: S603  fixed argv
                [c, "version"], capture_output=True, text=True, timeout=TIMEOUT_S, check=False
            ).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            continue
        m = VERSION.match(v)
        if m and int(m.group(1)) >= 3:
            return c, ".".join(m.groups())
    raise OpenSSLMissing("OpenSSL 3 or newer not found (set CERTCHECK_OPENSSL); LibreSSL is not supported")


@dataclass(frozen=True)
class TrustResult:
    trusted: bool
    message: str
    openssl_ok: bool
    error_code: int = 0  # OpenSSL X509_V_ERR_* number, 0 when verified
    policy: tuple[str, ...] = ()  # explicit policy failures applied on top of OpenSSL
    engine: str = ""  # "OpenSSL 3.5.7": version only, never the local binary path (review S7)


def _pem(c: Cert) -> bytes:
    return c.raw.public_bytes(Encoding.PEM)


def verify(
    chain: list[Cert],
    *,
    hostname: str | None,
    purpose: Purpose,
    now: dt.datetime,
    anchors: Path | None = None,
) -> TrustResult:
    """Verify leaf chain[0] with chain[1:] as untrusted intermediates.

    anchors=None uses the system store (ca-certificates on Linux); a path makes those PEM certificates
    the only anchors (like SecTrustSetAnchorCertificatesOnly)."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    if not chain:
        return TrustResult(False, "No certificate to verify.", False)
    try:
        exe, version = openssl_binary()
    except OpenSSLMissing as e:
        return TrustResult(False, f"Trust not evaluated: {e}", False, -1)
    engine = f"OpenSSL {version}"
    host = (hostname or "").strip().strip(".").lower()
    tmp = Path(tempfile.mkdtemp(prefix="certcheck-"))
    try:
        leaf, untrusted = tmp / "leaf.pem", tmp / "untrusted.pem"
        leaf.write_bytes(_pem(chain[0]))
        untrusted.write_bytes(b"".join(_pem(c) for c in chain[1:]))
        # auth_level 2 (112-bit security): rejects SHA-1 signatures and RSA < 2048, as SecTrust does.
        argv = [exe, "verify", "-x509_strict", "-auth_level", "2", "-attime", str(int(now.timestamp()))]
        if purpose == Purpose.TLS_SERVER:
            argv += ["-purpose", "sslserver"]
        elif purpose == Purpose.TLS_CLIENT:
            argv += ["-purpose", "sslclient"]
        if host and purpose != Purpose.ANY:
            argv += ["-verify_ip", host] if _is_ip(host) else ["-verify_hostname", host]
        if len(chain) > 1:
            argv += ["-untrusted", str(untrusted)]
        if anchors is not None:
            # resolve(): the subprocess runs with cwd=tmp, so a relative path would point elsewhere
            argv += ["-CAfile", str(anchors.resolve()), "-no-CApath", "-no-CAstore"]
        argv.append(str(leaf))
        p = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT_S, check=False, cwd=tmp)  # noqa: S603  fixed argv, no shell
    except subprocess.TimeoutExpired:
        return TrustResult(
            False, f"Trust not evaluated: openssl verify timed out after {TIMEOUT_S} s", False, -1, engine=engine
        )
    except OSError as e:
        return TrustResult(False, f"Trust not evaluated: could not run openssl ({e})", False, -1, engine=engine)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    ok = p.returncode == 0 and p.stdout.rstrip().endswith(": OK")
    code, msg = 0, ""
    m = ERROR_LINE.search(p.stderr + p.stdout)
    if not ok:
        code = int(m.group(1)) if m else -1
        msg = m.group(3).strip() if m else (p.stderr.strip().splitlines() or ["verification failed"])[-1]
    policy = tls_policy(chain[0], hostname=host, purpose=purpose)
    trusted = ok and not policy
    if trusted:
        message = "Trusted by the system trust store" if anchors is None else "Chains to the supplied anchor"
    elif not ok:
        message = f"OpenSSL: {msg}"
    else:
        message = "; ".join(policy)
    return TrustResult(trusted, message, ok, code, tuple(policy), engine)


def tls_policy(leaf: Cert, *, hostname: str, purpose: Purpose) -> list[str]:
    """Rules SecTrust's SSL policy enforces that `openssl verify` does not (or not by default).

    Name: a DNS name must be covered by a DNS SAN and an IP by an IP SAN. The Common Name is never
    used: OpenSSL's -verify_hostname falls back to the CN whenever the SAN has no DNS entry (an
    IP-only or email-only SAN), SecTrust does not."""
    if purpose == Purpose.ANY:
        return []
    out = []
    if hostname:
        if _is_ip(hostname):
            want = ipaddress.ip_address(hostname)
            if not any(ipaddress.ip_address(a) == want for a in leaf.ip_addresses):
                out.append(f"no IP address SAN for {hostname}")
        elif not any(wildcard_match(d, hostname) for d in leaf.dns_names):
            out.append(f"no DNS name SAN covers {hostname} (the Common Name is never used)")
    if leaf.eku is None:
        out.append("no extended key usage extension (macOS requires one for TLS)")
    needed = SERVER_AUTH if purpose == Purpose.TLS_SERVER else CLIENT_AUTH
    if leaf.eku is not None and needed not in leaf.eku:
        # anyExtendedKeyUsage alone is not accepted (consistent with analysis.py's eku finding)
        out.append(f"extended key usage does not include {oid_name(needed)}")
    if (
        purpose == Purpose.TLS_SERVER
        and leaf.not_before >= APPLE_825_FROM
        and (leaf.not_after - leaf.not_before).days > APPLE_MAX_TLS_DAYS
    ):
        out.append(f"validity period longer than {APPLE_MAX_TLS_DAYS} days")
    return out


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def finding(r: TrustResult, context: str) -> Finding:
    detail = f"{r.message} [{r.engine}]" if r.engine else r.message
    if r.trusted:
        return Finding("trust", Severity.PASS, Topic.TRUST, f"Trusted ({context})", detail)
    return Finding("trust", Severity.FAIL, Topic.TRUST, f"Not trusted ({context})", detail)
