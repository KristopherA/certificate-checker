"""Service-specific certificate rules applied after the generic analysis of a live probe.

Ports Remote.adjust, Appliance.adjust, Stack.adjust/suppliedCA and Vendor.adjust (plus the
handshake-failure notes) from Source/Sources/Core: same ids, severities, topics and kinds.

One deliberate difference (shared/known-differences.yaml): every trust downgrade goes through
`may_downgrade`, which is stricter than the Mac. A failed trust verdict is softened only when the whole
presented chain is inside its validity dates, its signatures verify, a DNS SAN covers the expected
name (never the Common Name, never for an IP address) and no EKU check failed.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from collections.abc import Sequence
from dataclasses import replace
from typing import Protocol

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.x509.oid import NameOID

from . import analysis, trust
from .model import Finding, Purpose, Severity, Topic, sort_findings
from .services import Service
from .wire import REMOTE_DESKTOP_AUTH_EKU
from .x509info import ANY_EKU, SERVER_AUTH, Cert, _is_ip, oid_name, wildcard_match


class AdjustTarget(Protocol):
    @property
    def service(self) -> Service: ...
    @property
    def port(self) -> int: ...
    @property
    def endpoint(self) -> str: ...
    @property
    def expected_name(self) -> str: ...
    @property
    def fingerprint_pin(self) -> str | None: ...


# --- shared helpers ---------------------------------------------------------------------------


def _ci(hay: str, needle: str) -> bool:
    return needle.casefold() in hay.casefold()


def _attrs(name: x509.Name, *oids: x509.ObjectIdentifier) -> list[str]:
    return [str(a.value) for oid in oids for a in name.get_attributes_for_oid(oid)]


def org(name: x509.Name) -> str:
    """O and OU values joined, in attribute order (the Swift Appliance org helper)."""
    return " ".join(
        str(a.value) for a in name if a.oid in (NameOID.ORGANIZATION_NAME, NameOID.ORGANIZATIONAL_UNIT_NAME)
    )


def issuer_cn(c: Cert) -> str | None:
    v = _attrs(c.raw.issuer, NameOID.COMMON_NAME)
    return v[0] if v else None


def sha1_thumb(c: Cert) -> str:
    return hashlib.sha1(c.der, usedforsecurity=False).hexdigest().upper()


def normalize_pin(s: str) -> str | None:
    """FingerprintPin.normalize: colon-hex or plain 64 hex digits -> upper-case colon-hex, else None."""
    t = s.strip()
    if not t or len(t) > 200:
        return None
    parts = t.split(":") if ":" in t else [t[i : i + 2] for i in range(0, len(t), 2)]
    hexd = set("0123456789abcdefABCDEF")
    if len(parts) != 32 or not all(len(p) == 2 and set(p) <= hexd for p in parts):
        return None
    return ":".join(p.upper() for p in parts)


def in_date(c: Cert, now: dt.datetime) -> bool:
    return c.not_before <= now <= c.not_after


def signatures_verify(chain: Sequence[Cert], anchors: Sequence[Cert] = ()) -> bool:
    """True only when the chain verifies up to an anchor. Each certificate must be signed by the next one
    (presented order, then leaf-first order), and the top certificate must either be self-issued with a valid
    self-signature or be (or be signed by) one of `anchors` (a supplied CA file). A top certificate whose issuer
    was not sent is never accepted: its issuer NAME alone proves nothing (review B1). No network."""
    if not chain:
        return False
    for order in (list(chain), analysis.ordered_chain(list(chain))):
        try:
            for child, parent in zip(order, order[1:], strict=False):
                child.raw.verify_directly_issued_by(parent.raw)
        except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
            continue  # this order does not verify (unsupported key/algorithm counts as not verified)
        if _anchored(order[-1], anchors):
            return True
    return False


def _signed_by(child: Cert, parent: Cert) -> bool:
    try:
        child.raw.verify_directly_issued_by(parent.raw)
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        return False
    return True


def _anchored(top: Cert, anchors: Sequence[Cert]) -> bool:
    if top.is_self_issued and _signed_by(top, top):
        return True
    return any(a.der == top.der or _signed_by(top, a) for a in anchors)


def san_covers(leaf: Cert, host: str) -> bool:
    h = host.lower().strip(".")
    if not h or _is_ip(h):
        return False
    return any(wildcard_match(d, h) for d in leaf.dns_names)


def eku_failed(findings: Sequence[Finding]) -> bool:
    return any((f.id == "eku" or f.topic == Topic.EKU) and f.severity == Severity.FAIL for f in findings)


def may_downgrade(
    findings: Sequence[Finding], chain: Sequence[Cert], host: str, now: dt.datetime, anchors: Sequence[Cert] = ()
) -> bool:
    """The strict downgrade rule (see module docstring). True means the trust failure may be softened."""
    if not chain or not any(f.id == "trust" and f.severity == Severity.FAIL for f in findings):
        return False
    return (
        all(in_date(c, now) for c in chain)
        and signatures_verify(chain, anchors)
        and san_covers(chain[0], host)
        and not eku_failed(findings)
    )


def _downgrade(out: list[Finding], chain: Sequence[Cert], host: str, now: dt.datetime, note: str, to: Severity) -> None:
    if not may_downgrade(out, chain, host, now):
        return
    i = next(i for i, f in enumerate(out) if f.id == "trust" and f.severity == Severity.FAIL)
    out[i] = replace(out[i], severity=to, detail=f"{out[i].detail} {note}".strip())


def _set(out: list[Finding], f: Finding) -> None:
    for i, g in enumerate(out):
        if g.id == f.id:
            out[i] = f
            return
    out.append(f)


# --- Remote (RDP, RD Gateway, WinRM) ------------------------------------------------------------


def remote_adjust(
    findings: list[Finding], chain: Sequence[Cert], t: AdjustTarget, now: dt.datetime, anchors: object = None
) -> list[Finding]:
    if not chain or not t.service.is_remote_admin:
        return findings
    leaf = chain[0]
    out = list(findings)
    R = Topic.REMOTE
    out.append(
        Finding(
            "remote-thumb",
            Severity.INFO,
            R,
            f"Presented certificate thumbprint (SHA-1) {sha1_thumb(leaf)}",
            "Compare with the thumbprint bound on the server (see How to fix). It is shown for comparison only.",
            "thumb",
        )
    )
    if t.service == Service.RDP:
        if leaf.eku is not None:
            names = ", ".join(oid_name(o) for o in leaf.eku)
            server = SERVER_AUTH in leaf.eku or ANY_EKU in leaf.eku
            rda = REMOTE_DESKTOP_AUTH_EKU in leaf.eku
            if server or rda:
                _set(
                    out,
                    Finding(
                        "eku",
                        Severity.PASS,
                        Topic.EKU,
                        "Extended key usage allows RDP",
                        f"Present: {names}. RDP accepts Server Authentication or Remote Desktop Authentication "
                        f"({REMOTE_DESKTOP_AUTH_EKU}).",
                    ),
                )
            else:
                _set(
                    out,
                    Finding(
                        "eku",
                        Severity.FAIL,
                        Topic.EKU,
                        "Extended key usage does not allow RDP",
                        f"Present: {names}. Reissue with Server Authentication ({SERVER_AUTH}) or Remote Desktop "
                        f"Authentication ({REMOTE_DESKTOP_AUTH_EKU}).",
                    ),
                )
            if rda and not server:
                # The TLS server policy needs serverAuth; evaluate the chain with the plain X.509 policy instead.
                r = trust.verify(
                    analysis.ordered_chain(list(chain)),
                    hostname=None,
                    purpose=Purpose.ANY,
                    now=now,
                    anchors=anchors,  # type: ignore[arg-type]
                )
                _set(
                    out,
                    Finding(
                        "trust",
                        Severity.PASS if r.trusted else Severity.FAIL,
                        Topic.TRUST,
                        "Chain trusted (X.509 policy)" if r.trusted else "Not trusted (X.509 policy)",
                        f"{r.message}. The certificate carries only the Remote Desktop Authentication EKU, so the "
                        "TLS server policy was not applied; hostname coverage is checked separately.",
                    ),
                )
        if leaf.is_self_issued and leaf.is_ca is not True:
            days = int((leaf.not_after - leaf.not_before).total_seconds() // 86_400)
            out.append(
                Finding(
                    "rdp-selfsigned",
                    Severity.WARNING,
                    R,
                    "Self-signed RDP certificate (likely the Windows default)",
                    f"{leaf.display_name}, issued by itself, {days}-day lifetime. Clients show a certificate warning "
                    "or trust it on first use. Bind a certificate from your CA.",
                    "rdp-cert",
                )
            )
            if len(chain) == 1:
                _downgrade(
                    out, chain, t.expected_name, now, "Expected for a self-signed RDP certificate.", Severity.WARNING
                )
            if leaf.signature_is_weak:
                out.append(
                    Finding(
                        "rdp-selfsigned-sig",
                        Severity.INFO,
                        Topic.WEAK_SIGNATURE,
                        f"Self-signed certificate uses {leaf.signature_algorithm}",
                        "Regenerating or replacing it with a CA-issued SHA-256 certificate avoids client warnings.",
                    )
                )
    elif t.service == Service.RD_GATEWAY:
        if leaf.is_self_issued:
            out.append(
                Finding(
                    "rdg-selfsigned",
                    Severity.FAIL,
                    R,
                    "RD Gateway presents a self-signed certificate",
                    "Remote Desktop clients refuse a gateway certificate they do not trust. Bind a certificate from "
                    "a CA the clients trust, with the gateway's public name in the SAN.",
                    "rdg-cert",
                )
            )
    elif t.service == Service.WINRM_HTTPS:
        cn = leaf.common_name or ""
        if cn and cn.lower() != t.expected_name.lower() and not cn.startswith("*"):
            out.append(
                Finding(
                    "winrm-cn",
                    Severity.WARNING,
                    R,
                    f"Certificate CN {cn} differs from {t.expected_name}",
                    "WinRM HTTPS listeners expect the certificate CN to equal the listener HostName, and clients "
                    "connect with that name. Use a certificate whose CN (and SAN) is the host name clients use.",
                    "winrm-cert",
                )
            )
        if leaf.is_self_issued:
            out.append(
                Finding(
                    "winrm-selfsigned",
                    Severity.WARNING,
                    R,
                    "WinRM presents a self-signed certificate",
                    "Clients then need -SkipCACheck/-SkipCNCheck, which removes server authentication. Use a "
                    "CA-issued certificate instead.",
                    "winrm-cert",
                )
            )
    return sort_findings(out)


# --- Appliance (Synology DSM, Proxmox VE, Proxmox Backup Server) --------------------------------


def is_synology_default(leaf: Cert) -> bool:
    return (
        (leaf.common_name or "").lower() == "synology"
        or _ci(org(leaf.raw.issuer), "Synology")
        or _ci(issuer_cn(leaf) or "", "Synology")
    )


def is_pve_default(leaf: Cert) -> bool:
    i = f"{issuer_cn(leaf) or ''} {org(leaf.raw.issuer)}"
    return _ci(i, "Proxmox Virtual Environment") or _ci(i, "PVE Cluster Manager CA")


def is_pbs_default(leaf: Cert) -> bool:
    return leaf.is_self_issued and leaf.is_ca is not True


def appliance_adjust(
    findings: list[Finding], chain: Sequence[Cert], t: AdjustTarget, now: dt.datetime
) -> list[Finding]:
    if not chain or not t.service.is_appliance:
        return findings
    leaf = chain[0]
    out = list(findings)
    A = Topic.APPLIANCE

    def down(note: str, to: Severity = Severity.WARNING) -> None:
        _downgrade(out, chain, t.expected_name, now, note, to)

    def pin_findings(p: str, raw: str, explained: bool, hint: str) -> None:
        fid = f"{p}-pin"
        pin = normalize_pin(raw)
        if pin is None:
            out.append(
                Finding(
                    fid,
                    Severity.FAIL,
                    A,
                    "Fingerprint pin is not a SHA-256 colon-hex value",
                    f"Expected 32 bytes as AA:BB:… (64 ASCII hex digits). Copy it from {hint}",
                    fid,
                )
            )
            return
        if pin == leaf.sha256:
            leaf_only = len(chain) == 1 and not leaf.is_self_issued
            note = " · Pinned: the server sent only its own certificate, so no issuing chain was checked."
            out.append(
                Finding(
                    fid,
                    Severity.PASS,
                    A,
                    "Fingerprint pin matches the served certificate",
                    pin + (note if leaf_only else ""),
                    fid,
                )
            )
            if explained:
                # No leaf-only wording here (review S10): a lone non-self-issued leaf never passes
                # signatures_verify (B1), so _downgrade cannot apply to it; the PASS detail above carries that note.
                down("Trusted by the matching fingerprint pin.", Severity.INFO)
        else:
            out.append(
                Finding(
                    fid,
                    Severity.FAIL,
                    A,
                    "Fingerprint pin does NOT match the served certificate",
                    f"Pinned {pin}, served {leaf.sha256}. The certificate was regenerated or replaced, or something "
                    f"else answers on {t.endpoint}. Confirm on the host before updating the pin.",
                    fid,
                )
            )

    product = t.service.value.replace(" (HTTPS)", "")
    out.append(
        Finding(
            "appl-fp",
            Severity.INFO,
            A,
            f"Presented certificate SHA-256 fingerprint {leaf.sha256}",
            f"{product} on {t.endpoint}. Shown for comparison only.",
            "fingerprint",
        )
    )
    issuer = issuer_cn(leaf) or leaf.issuer_text
    raw_pin = (t.fingerprint_pin or "").strip() or None
    if t.service == Service.SYNOLOGY_DSM:
        if is_synology_default(leaf):
            out.append(
                Finding(
                    "dsm-default",
                    Severity.WARNING,
                    A,
                    "Synology DSM factory certificate",
                    f"{leaf.display_name}, issued by {issuer}. Browsers and Hyper Backup / Drive clients warn. Replace "
                    "it with a CA-issued or Let's Encrypt certificate and assign it to DSM. Identity is unverified: "
                    "nothing ties this certificate to your NAS, so compare the SHA-256 fingerprint shown here with "
                    "Control Panel › Security › Certificate on the NAS.",
                    "dsm-cert",
                )
            )
            down("Expected for the DSM factory certificate.")
        elif leaf.is_self_issued:
            out.append(
                Finding(
                    "dsm-selfsigned",
                    Severity.WARNING,
                    A,
                    "Synology DSM presents a self-signed certificate",
                    "Clients cannot verify it. Assign a CA-issued certificate to DSM.",
                    "dsm-cert",
                )
            )
    elif t.service == Service.PROXMOX_VE:
        if is_pve_default(leaf):
            unverified = (
                " Identity is unverified without a fingerprint pin: supply --fingerprint (pvenode cert info) to "
                "confirm this is your node."
                if raw_pin is None
                else ""
            )
            out.append(
                Finding(
                    "pve-default",
                    Severity.WARNING,
                    A,
                    "Proxmox VE default node certificate (cluster CA)",
                    f"Issued by {issuer}, the cluster's own CA, which browsers do not trust. Install a custom "
                    "certificate or use the built-in ACME client; pveproxy then serves it from pveproxy-ssl.pem."
                    + unverified,
                    "pve-cert",
                )
            )
            if raw_pin is None:
                down(
                    "Expected for the default PVE cluster-CA certificate; "
                    "identity unverified without a fingerprint pin."
                )
        elif leaf.is_self_issued:
            out.append(
                Finding(
                    "pve-selfsigned",
                    Severity.WARNING,
                    A,
                    "Proxmox VE presents a self-signed certificate",
                    "Clients cannot verify it. Install a CA-issued certificate or use ACME.",
                    "pve-cert",
                )
            )
        if raw_pin is not None:
            pin_findings(
                "pve",
                raw_pin,
                is_pve_default(leaf) or leaf.is_self_issued,
                "pvenode cert info on the node (or the GUI: Node › System › Certificates).",
            )
    elif t.service == Service.PROXMOX_BACKUP:
        self_signed = is_pbs_default(leaf)
        if self_signed:
            out.append(
                Finding(
                    "pbs-selfsigned",
                    Severity.INFO,
                    A,
                    "Proxmox Backup Server self-signed certificate (default)",
                    "PVE and proxmox-backup-client trust it only through a pinned SHA-256 fingerprint.",
                    "pbs-cert",
                )
            )
        if raw_pin is not None:
            pin_findings(
                "pbs",
                raw_pin,
                self_signed,
                "proxmox-backup-manager cert info or the PBS dashboard › Show Fingerprint.",
            )
        elif self_signed:
            out.append(
                Finding(
                    "pbs-pin",
                    Severity.WARNING,
                    A,
                    "No fingerprint pin given for a self-signed PBS certificate",
                    "Supply the fingerprint from the PBS host to verify this is the expected server.",
                    "pbs-pin",
                )
            )
            down("Expected for the PBS default self-signed certificate; verify with a fingerprint pin.")
    return sort_findings(out)


# --- Stack (Docker registry, Logstash Beats, Elasticsearch) --------------------------------------


def _sf(fid: str, s: Severity, kind: str, title: str, detail: str = "") -> Finding:
    return Finding(fid, s, Topic.STACK, title, detail, kind)


def is_elastic_auto_configured(leaf: Cert, chain: Sequence[Cert]) -> bool:
    names = [issuer_cn(leaf), *(c.common_name for c in chain)]
    return any(n and _ci(n, "Elasticsearch security auto-configuration") for n in names)


def stack_adjust(findings: list[Finding], chain: Sequence[Cert], t: AdjustTarget) -> list[Finding]:
    if not chain or not t.service.is_stack:
        return findings
    leaf = chain[0]
    out = list(findings)
    if t.service == Service.DOCKER_REGISTRY:
        port = "" if t.port == 443 else f":{t.port}"
        out.append(
            _sf(
                "reg-tls",
                Severity.INFO,
                "registry-cert",
                f"Docker registry TLS endpoint {t.endpoint}",
                f"Docker validates this chain against the system store plus /etc/docker/certs.d/{t.expected_name}"
                f"{port}/ca.crt. Never use insecure-registries to work around a certificate problem.",
            )
        )
    elif t.service == Service.LOGSTASH_BEATS:
        out.append(
            _sf(
                "beats-tls",
                Severity.INFO,
                "beats-tls",
                f"Logstash Beats input TLS on {t.endpoint}",
                "Beats trust this certificate through ssl.certificate_authorities in filebeat.yml (output.logstash). "
                "Use --ca to check the chain against that CA file.",
            )
        )
    elif t.service == Service.ELASTICSEARCH:
        if is_elastic_auto_configured(leaf, chain):
            out.append(
                _sf(
                    "es-autoca",
                    Severity.WARNING,
                    "es-cert",
                    "Elasticsearch auto-configured HTTP CA",
                    f"Issued by {issuer_cn(leaf) or leaf.issuer_text}. Clients must be given http_ca.crt "
                    "(ssl.certificate_authorities or ca_trusted_fingerprint); browsers and other tools will not trust "
                    "it. Replace it with a certificate from your CA for long-lived deployments.",
                )
            )
        else:
            out.append(
                _sf(
                    "es-tls",
                    Severity.INFO,
                    "es-cert",
                    f"Elasticsearch HTTPS on {t.endpoint}",
                    "Beats output.elasticsearch trusts this certificate through ssl.certificate_authorities. Use --ca "
                    "to check the chain against that CA file.",
                )
            )
    return sort_findings(out)


def non_ca_warnings(ca: Sequence[Cert]) -> list[Finding]:
    return [
        _sf(
            f"ca-nonca-{k}",
            Severity.WARNING,
            "ca-chain",
            f"CA file contains a non-CA certificate: {c.display_name}",
            "It lacks basicConstraints CA:TRUE, so it cannot act as a trust anchor for ssl.certificate_authorities / "
            "certs.d. Put only the issuing CA certificates in this file.",
        )
        for k, c in enumerate(ca)
        if c.is_ca is not True
    ]


def _is_self_signed(c: Cert) -> bool:
    return c.is_self_issued and (c.aki is None or c.ski is None or c.aki == c.ski)


def build_chain(leaf: Cert, pool: Sequence[Cert]) -> list[Cert]:
    """ChainCheck.chain: leaf -> root by subject/issuer, preferring AKI = SKI, at most 6 links."""
    c = [leaf]
    while not _is_self_signed(c[-1]) and len(c) < 6:
        last = c[-1]
        seen = {x.sha256 for x in c}
        cands = [p for p in pool if p.subject == last.issuer and p.sha256 not in seen]
        nxt = next((p for p in cands if last.aki is None or p.ski == last.aki), cands[0] if cands else None)
        if nxt is None:
            break
        c.append(nxt)
    return c


def supplied_ca(
    findings: list[Finding], chain: Sequence[Cert], ca: Sequence[Cert], hostname: str | None, now: dt.datetime
) -> list[Finding]:
    """Stack.suppliedCA: compare the presented chain with the CA file the clients use."""
    if not chain or not ca:
        return findings
    leaf = chain[0]
    out = list(findings) + non_ca_warnings(ca)
    hashes = {c.sha256 for c in ca}
    path = build_chain(leaf, [c for c in chain[1:] if c.sha256 not in hashes] + list(ca))
    k = next((i for i, c in enumerate(path) if c.sha256 in hashes), None)
    if k is not None:
        path = path[: k + 1]
    ok = path[-1].sha256 in hashes and (len(path) > 1 or leaf.sha256 in hashes)
    if ok and signatures_verify(path, ca):
        out.append(
            _sf(
                "ca-chain",
                Severity.PASS,
                "ca-chain",
                f"Chains to the supplied CA {path[-1].display_name}",
                " → ".join(c.display_name for c in path),
            )
        )
        if hostname and may_downgrade(out, path, hostname, now, ca):
            i = next(i for i, f in enumerate(out) if f.id == "trust" and f.severity == Severity.FAIL)
            out[i] = replace(
                out[i],
                severity=Severity.INFO,
                detail=f"{out[i].detail} Clients configured with the supplied CA file trust it.",
            )
    elif ok:
        out.append(
            _sf(
                "ca-chain",
                Severity.FAIL,
                "ca-chain",
                "Does not chain to the supplied CA",
                "Signature chain did not verify",
            )
        )
    else:
        names = ", ".join(c.display_name for c in ca)
        out.append(
            _sf(
                "ca-chain",
                Severity.FAIL,
                "ca-chain",
                "Does not chain to the supplied CA",
                f"Issuer {path[-1].issuer_text} is not in the supplied CA file ({names}).",
            )
        )
    return sort_findings(out)


# --- Vendor (Munki, FileMaker, Retrospect, HP, Barracuda) ---------------------------------------


def _names(c: Cert) -> str:
    return " ".join([c.common_name or "", org(c.raw.subject), issuer_cn(c) or "", org(c.raw.issuer)])


def _has(c: Cert, words: Sequence[str]) -> bool:
    n = _names(c)
    return any(_ci(n, w) for w in words)


def is_filemaker_default(leaf: Cert) -> bool:
    subject_has_dot = "." in leaf.subject_text
    return (leaf.common_name or "").lower() == "filemaker" or (
        _has(leaf, ["FileMaker", "Claris International"]) and not subject_has_dot
    )


def is_hp_name(cn: str) -> bool:
    u = cn.upper()
    if u == "HP":
        return True
    if u.startswith("HP-UX"):
        return False
    if u.startswith("HP") and len(u) > 2 and not u[2].isalpha():
        return True
    if u.startswith("NPI"):
        rest = u[3:]
        return len(rest) >= 6 and all(ch in "0123456789ABCDEF" for ch in rest)
    return False


def is_hp_default(leaf: Cert) -> bool:
    if not leaf.is_self_issued:
        return False
    orgs = [
        v.strip().lower() for n in (leaf.raw.subject, leaf.raw.issuer) for v in _attrs(n, NameOID.ORGANIZATION_NAME)
    ]
    hp_org = any(
        o in ("hp", "hp inc.", "hp inc") or o.startswith("hewlett-packard") or o.startswith("hewlett packard")
        for o in orgs
    )
    return hp_org or is_hp_name(leaf.common_name or "")


def is_barracuda_default(leaf: Cert) -> bool:
    return leaf.is_self_issued and _has(leaf, ["Barracuda"])


def is_retrospect_default(leaf: Cert) -> bool:
    return leaf.is_self_issued and _has(leaf, ["Retrospect"])


def is_generic_default(leaf: Cert) -> bool:
    cn = (leaf.common_name or "").lower()
    return leaf.is_self_issued and (
        cn in ("localhost", "localhost.localdomain") or _has(leaf, ["Internet Widgits Pty Ltd", "snakeoil"])
    )


MAC_TLS_NAMES = {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1", "TLSv1.2": "TLS 1.2", "TLSv1.3": "TLS 1.3"}


def vendor_adjust(
    findings: list[Finding], chain: Sequence[Cert], t: AdjustTarget, tls_version: str | None, now: dt.datetime
) -> list[Finding]:
    """`tls_version` uses Python's names (TLSv1.2); titles show the Mac form (TLS 1.2)."""
    if not chain or not t.service.is_vendor:
        return findings
    leaf = chain[0]
    out = list(findings)
    V = Topic.VENDOR

    def add(fid: str, s: Severity, title: str, detail: str, kind: str) -> None:
        out.append(Finding(fid, s, V, title, detail, kind))

    def down(note: str) -> None:
        _downgrade(out, chain, t.expected_name, now, note, Severity.WARNING)

    product = t.service.value.replace(" (HTTPS)", "").replace(" (TLS)", "")
    add(
        "vendor-fp",
        Severity.INFO,
        f"Presented certificate SHA-256 fingerprint {leaf.sha256}",
        f"{product} on {t.endpoint}. Shown for comparison only.",
        "fingerprint",
    )
    unverified = (
        "Identity is unverified: compare the SHA-256 fingerprint shown here with the one on the device before "
        "trusting it."
    )
    issuer = issuer_cn(leaf) or leaf.issuer_text
    s = t.service
    if s == Service.FILEMAKER:
        if is_filemaker_default(leaf):
            add(
                "fms-default",
                Severity.FAIL,
                "FileMaker Server default certificate",
                f"{leaf.display_name}, issued by {issuer}. Claris supports it for testing only; it does not verify the "
                "server name, so FileMaker Pro/Go show an unverified connection and the Data API / WebDirect clients "
                "reject it. Import a CA-issued certificate in Admin Console.",
                "fms-cert",
            )
        elif leaf.is_self_issued:
            add(
                "fms-selfsigned",
                Severity.WARNING,
                "FileMaker Server presents a self-signed certificate",
                "Clients cannot verify it. Import a CA-issued certificate for the server's DNS name.",
                "fms-cert",
            )
        if t.port == 5003:
            add(
                "fms-5003",
                Severity.INFO,
                "Checked the FileMaker client port 5003",
                "FileMaker Pro/Go use 5003 (or 443 with HTTPS tunneling); Admin Console, WebDirect and the Data API "
                "use 443. Both serve the same certificate.",
                "",
            )
    elif s == Service.RETROSPECT_CONSOLE:
        add(
            "retro-scope",
            Severity.INFO,
            "Checked the Retrospect web console only",
            "The Retrospect Engine (TCP 22024) and Retrospect Clients (TCP/UDP 497) use Retrospect's own protocol, not "
            "standard TLS, so there is no certificate to check there. The hosted Management Console is Retrospect's "
            "own service; this check is for a self-hosted web console such as Retrospect Virtual (443 or 8443).",
            "",
        )
        if is_retrospect_default(leaf) or is_generic_default(leaf):
            add(
                "retro-default",
                Severity.WARNING,
                "Retrospect console default certificate",
                f"{leaf.display_name} is self-signed. Browsers warn and cannot verify the console. {unverified}",
                "retro-cert",
            )
            down("Expected for the console's default self-signed certificate.")
        elif leaf.is_self_issued:
            add(
                "retro-selfsigned",
                Severity.WARNING,
                "Retrospect console presents a self-signed certificate",
                "Install a CA-issued certificate for the console name.",
                "retro-cert",
            )
    elif s == Service.HP_PRINTER:
        if is_hp_default(leaf):
            add(
                "hp-default",
                Severity.WARNING,
                "HP printer factory self-signed certificate",
                f"{leaf.display_name}. Browsers warn and nothing ties it to this printer. Install a CA-issued "
                f"certificate (or a CSR signed by your CA) in the EWS. {unverified}",
                "hp-cert",
            )
            down("Expected for the HP factory self-signed certificate.")
        elif leaf.is_self_issued:
            add(
                "hp-selfsigned",
                Severity.WARNING,
                "HP printer presents a self-signed certificate",
                "Install a CA-issued certificate in the EWS.",
                "hp-cert",
            )
        kind, bits = leaf.key.algorithm
        if kind == "rsa" and isinstance(bits, int) and bits < 2048:
            add(
                "hp-weakkey",
                Severity.FAIL,
                f"HP printer certificate uses a {bits}-bit RSA key",
                "Older HP firmware generates 1024-bit keys. Create a new 2048-bit certificate or CSR in the EWS "
                "(firmware updates may be needed).",
                "hp-tls",
            )
        v = MAC_TLS_NAMES.get(tls_version or "", tls_version)
        if v in ("TLS 1.0", "TLS 1.1"):
            add(
                "hp-protocol",
                Severity.FAIL,
                f"HP printer negotiated {v}",
                "Disable TLS 1.0/1.1 in the EWS encryption settings.",
                "hp-tls",
            )
        else:
            known = f" ({v})" if v else ""
            add(
                "hp-protocol",
                Severity.INFO,
                "Older protocols not tested",
                f"One handshake: only the negotiated version{known} is known. Whether the printer still accepts TLS "
                "1.0/1.1 needs the copy-only openssl -tls1 / -tls1_1 commands in the guidance.",
                "hp-tls",
            )
    elif s in (Service.BARRACUDA_SERVICE, Service.BARRACUDA_MANAGEMENT):
        mgmt = s == Service.BARRACUDA_MANAGEMENT
        sev = Severity.WARNING if mgmt else Severity.FAIL
        if is_barracuda_default(leaf):
            add(
                "waf-default",
                sev,
                f"Barracuda factory self-signed certificate on the {'management UI' if mgmt else 'service listener'}",
                f"Administrators cannot verify the management interface. Upload a CA-issued certificate for the "
                f"management UI. {unverified}"
                if mgmt
                else "Clients of this published service get a certificate warning. Upload or create a trusted "
                "certificate and assign it to the HTTPS service.",
                "waf-cert",
            )
            if mgmt:
                down("Expected for the Barracuda factory management certificate.")
        elif leaf.is_self_issued:
            add(
                "waf-selfsigned",
                sev,
                f"Barracuda {'management UI' if mgmt else 'service'} presents a self-signed certificate",
                "Assign a CA-issued certificate.",
                "waf-cert",
            )
        if not mgmt and t.port == 8443:
            add(
                "waf-port",
                Severity.INFO,
                "Port 8443 is usually the management UI",
                "Use the management check (waf-mgmt) for 8443.",
                "",
            )
    elif s == Service.MUNKI_REPO:
        if is_generic_default(leaf):
            add(
                "munki-default",
                Severity.FAIL,
                "Munki repo serves a placeholder certificate",
                f"{leaf.display_name} is a self-signed web-server default. Munki clients reject it unless "
                "SoftwareRepoCACertificate trusts it. Install a certificate for the repo name.",
                "munki-cert",
            )
        elif leaf.is_self_issued:
            add(
                "munki-selfsigned",
                Severity.WARNING,
                "Munki repo presents a self-signed certificate",
                "Munki clients accept it only when SoftwareRepoCACertificate names it.",
                "munki-cert",
            )
    return sort_findings(out)


# --- failure notes ------------------------------------------------------------------------------


def handshake_failure_notes(t: AdjustTarget) -> list[Finding]:
    """Stack.handshakeFailureNote and Vendor.handshakeFailureNote."""
    out: list[Finding] = []
    if t.service in (Service.LOGSTASH_BEATS, Service.ELASTICSEARCH):
        cond = (
            'the beats input sets ssl_client_authentication => "required"'
            if t.service == Service.LOGSTASH_BEATS
            else "xpack.security.http.ssl.client_authentication is required"
        )
        out.append(
            _sf(
                "mtls-required",
                Severity.INFO,
                "mtls-client",
                "The server may require a client certificate",
                f"If {cond} the handshake fails without one. This checker never presents a client certificate (keys "
                "stay in memory only); validate the Beats client pair offline instead.",
            )
        )
    if t.service == Service.RETROSPECT_CONSOLE and t.port in (22024, 497):
        out.append(
            Finding(
                "retro-port",
                Severity.INFO,
                Topic.VENDOR,
                f"Port {t.port} is not a TLS port",
                "Retrospect Engine (22024) and Client (497) use Retrospect's own protocol; no certificate can be "
                "checked there. Check the web console port instead.",
            )
        )
    if t.service == Service.FILEMAKER and t.port == 5003:
        out.append(
            Finding(
                "fms-port",
                Severity.INFO,
                Topic.VENDOR,
                "FileMaker 5003 did not complete TLS",
                "FileMaker Server uses TLS on 5003 only when database connections use SSL (Admin Console › "
                "Configuration › SSL Certificate). Check 443 as well.",
            )
        )
    return out


def apply_all(
    findings: list[Finding],
    chain: Sequence[Cert],
    t: AdjustTarget,
    *,
    tls_version: str | None,
    now: dt.datetime,
    anchors: object = None,
) -> list[Finding]:
    """The four adjusters in Probe.runSync order."""
    f = remote_adjust(findings, chain, t, now, anchors)
    f = appliance_adjust(f, chain, t, now)
    f = stack_adjust(f, chain, t)
    return vendor_adjust(f, chain, t, tls_version, now)
