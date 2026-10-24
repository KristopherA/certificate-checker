"""One live check with the M4 options (opt-in, all off by default): legacy TLS 1.0/1.1, AIA fetching, revocation.

Order: the normal probe (probe.run, TLS 1.2+); if it fails and legacy mode is on, the same probe once more with
legacy.fallback_context (badge: ProbeResult.legacy); a TLS 1.0/1.1 scan when legacy mode is on; AIA completion
(re-assessing trust with the fetched intermediates); the CT presence note; then revocation (stapled OCSP, live
OCSP, CRL). Without legacy mode, a handshake that fails on protocol version or ciphers gets a try-legacy hint.
Outbound requests (AIA/OCSP/CRL) are listed in ProbeResult.contacted and in the findings.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from . import aia, analysis, legacy, probe, revocation, staple
from .model import Finding, Severity, Topic, sort_findings

LEGACY_HINT_ERRORS = (
    "UNSUPPORTED_PROTOCOL",
    "TLSV1_ALERT_PROTOCOL_VERSION",
    "NO_PROTOCOLS_AVAILABLE",
    "SSLV3_ALERT_HANDSHAKE_FAILURE",
    "NO_CIPHERS_AVAILABLE",
    "NO_SHARED_CIPHER",
)


@dataclass(frozen=True)
class Options:
    legacy: bool = False
    aia: bool = False
    revocation: bool = False

    @classmethod
    def from_mapping(cls, m: Mapping[str, object]) -> Options:
        """Per-check or per-target flags (targets.yaml keys legacy / aia / revocation); only real booleans."""
        unknown = set(m) - {"legacy", "aia", "revocation"}
        if unknown:
            raise ValueError(f"Unknown option(s): {', '.join(sorted(unknown))}")
        vals = {}
        for k, v in m.items():
            if not isinstance(v, bool):
                raise ValueError(f"Option {k} must be true or false")
            vals[k] = v
        return cls(**vals)


def run(
    t: probe.Target,
    options: Options = Options(),  # noqa: B008  frozen, immutable default
    *,
    timeout: float = probe.DEFAULT_TIMEOUT_S,
    now: dt.datetime | None = None,
    anchors: Path | None = None,
    policy: probe.TargetPolicy | None = None,
    nameservers: list[str] | None = None,
) -> probe.ProbeResult:
    policy = policy or probe.TargetPolicy.from_env()
    when = now or dt.datetime.now(dt.UTC)
    kw = {"timeout": timeout, "now": when, "anchors": anchors, "policy": policy, "nameservers": nameservers}
    r = probe.run(t, **kw)  # type: ignore[arg-type]
    extra: list[Finding] = []
    if r.error is not None and not r.chain:
        if options.legacy:
            lr = probe.run(t, context=legacy.fallback_context(), **kw)  # type: ignore[arg-type]
            if lr.error is None:
                lr.legacy = True
                extra.append(
                    Finding(
                        "legacy-mode",
                        Severity.INFO,
                        Topic.GENERAL,
                        "Result from legacy mode (TLS 1.0/1.1)",
                        f"The normal probe (TLS 1.2+) failed: {r.error}",
                        "legacy",
                    )
                )
                lr.transcript = [*r.transcript, "Retried in legacy mode", *lr.transcript]
                r = lr
        elif r.error and any(code in r.error for code in LEGACY_HINT_ERRORS):
            r.findings.append(
                Finding(
                    "legacy-hint",
                    Severity.INFO,
                    Topic.CONNECTION,
                    "The server may offer only TLS 1.0/1.1",
                    "The handshake failed on protocol version or ciphers. Run the check again with legacy mode to "
                    "see what the server accepts.",
                    "legacy",
                )
            )
    if r.error is not None or not r.chain or r.connected_ip is None:
        r.findings = sort_findings(r.findings)
        return r
    if options.legacy:
        extra += legacy.findings(legacy.scan(t, r.connected_ip, policy=policy, timeout=timeout))
    chain = analysis.ordered_chain(r.chain)
    if options.aia:
        comp = aia.complete(r.chain, policy=policy)
        r.contacted += comp.contacted
        r.blocked += comp.blocked
        extra += aia.aia_findings(comp)
        if comp.added:
            chain = [*chain, *comp.added]
            tr, f = probe.assess(chain, t, tls_version=r.tls_version, now=when, anchors=anchors)
            r.trust = tr
            kept = [
                x for x in r.findings if x.id in ("connected-ip", "split-dns", "firewall-hint") or x in r.negotiation
            ]
            r.findings = [*f, *kept]
    extra.append(aia.ct_finding(chain[0]))
    if options.revocation:
        stapled, note = staple.fetch_stapled(t, r.connected_ip, policy=policy)
        r.transcript.append(f"OCSP stapling: {note}")
        rev = revocation.check(chain, stapled=stapled, now=when, policy=policy)
        r.contacted += rev.contacted
        r.blocked += rev.blocked
        extra += revocation.findings(rev)
    r.contacted = list(dict.fromkeys(r.contacted))
    r.blocked = list(dict.fromkeys(r.blocked))
    r.findings = sort_findings(r.findings + extra)
    return r
