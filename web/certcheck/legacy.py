"""Legacy TLS 1.0/1.1 mode (M4): opt-in, isolated from every normal check.

The only place that builds a context allowing TLS 1.0/1.1: a fresh SSLContext per connection with ciphers
DEFAULT:@SECLEVEL=0 and the protocol pinned to exactly one legacy version. probe.default_context (TLS 1.2+,
default security level) and listener.server_context (the UI, TLS 1.2+) never use it; tests assert both refuse
TLS 1.0. Each accepted legacy protocol is reported as INSECURE, with the ciphers the server accepts (found by
repeated handshakes, removing the accepted cipher each time, so at most one handshake per cipher plus one).
"""

from __future__ import annotations

import socket
import ssl
import time
import warnings
from dataclasses import dataclass, field

from . import probe
from .model import Finding, Severity, Topic

VERSIONS = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1}
MAX_CIPHERS = 40
FIX = (
    "Disable TLS 1.0 and 1.1 on the device and enable TLS 1.2 or newer (firmware update or the TLS settings page); "
    "if the device cannot do TLS 1.2, isolate it on a management network and plan its replacement."
)


def legacy_context(version: str = "TLSv1", ciphers: str = "DEFAULT") -> ssl.SSLContext:
    """A per-connection context for exactly one legacy version. Never shared, never cached."""
    v = VERSIONS[version]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inspection only; trust.verify evaluates afterwards
    ctx.set_ciphers(f"{ciphers}:@SECLEVEL=0")
    with warnings.catch_warnings():  # legacy versions are the point of this context
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = v
        ctx.maximum_version = v
    return ctx


def fallback_context() -> ssl.SSLContext:
    """TLS 1.0 or 1.1, for the probe re-run when the normal probe fails and legacy mode is on."""
    ctx = legacy_context("TLSv1")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    return ctx


def offered_ciphers(version: str) -> list[str]:
    """OpenSSL names of the TLS 1.0/1.1-capable ciphers this build offers."""
    try:
        ctx = legacy_context(version, "ALL")
    except ssl.SSLError:
        return []
    return [c["name"] for c in ctx.get_ciphers() if c["protocol"] in ("TLSv1", "SSLv3", "TLSv1.0")][:MAX_CIPHERS]


@dataclass
class VersionResult:
    version: str
    supported: bool
    ciphers: list[str] = field(default_factory=list)
    error: str = ""


def _try(t: probe.Target, ip: str, ctx: ssl.SSLContext, deadline: float) -> str:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("legacy scan time budget used up")
    with socket.create_connection((ip, t.port), timeout=left) as raw:
        if t.service.uses_upgrade:
            c = probe._Reader(raw, deadline)
            probe.upgrade(c, t, probe.ProbeResult(target=t))
            if c.pending():
                raise probe.ProbeError("unexpected bytes before the TLS handshake")
        raw.settimeout(max(0.001, deadline - time.monotonic()))
        sni = None if probe._is_ip(t.server_name) else t.server_name
        with ctx.wrap_socket(raw, server_hostname=sni) as s:
            ci = s.cipher()
            return ci[0] if ci else ""


def scan(
    t: probe.Target, ip: str, *, policy: probe.TargetPolicy | None = None, timeout: float = 20.0
) -> list[VersionResult]:
    policy = policy or probe.TargetPolicy.from_env()
    policy.check(ip, t.port)
    deadline = time.monotonic() + timeout
    out = []
    for version in VERSIONS:
        res = VersionResult(version, False)
        out.append(res)
        remaining = offered_ciphers(version)
        while remaining:
            try:
                got = _try(t, ip, legacy_context(version, ":".join(remaining)), deadline)
            except (OSError, ssl.SSLError, probe.ProbeError) as e:
                if not res.supported:
                    res.error = str(e) or type(e).__name__
                break
            res.supported = True
            if not got or got not in remaining:
                break
            res.ciphers.append(got)
            remaining.remove(got)
    return out


def findings(results: list[VersionResult]) -> list[Finding]:
    out = []
    for r in results:
        if r.supported:
            names = ", ".join(r.ciphers) or "(cipher not reported)"
            out.append(
                Finding(
                    f"legacy-{r.version}",
                    Severity.FAIL,
                    Topic.GENERAL,
                    f"INSECURE: server accepts {r.version}",
                    f"Accepted ciphers: {names}. {FIX}",
                    "legacy",
                )
            )
    if not any(r.supported for r in results):
        out.append(Finding("legacy-none", Severity.PASS, Topic.GENERAL, "Server refuses TLS 1.0 and 1.1", "", "legacy"))
    return out
