"""Munki ManagedInstalls plist checks plus the client pair (Vendor.swift Munki), offline, keys in memory only.

Deviation (shared/known-differences.yaml): the web version reads only uploaded files. Paths named inside the plist
(ClientCertificatePath, ClientKeyPath, SoftwareRepoCACertificate) are never opened."""

from __future__ import annotations

import codecs
import datetime as dt
import plistlib
import re
from dataclasses import dataclass, replace
from urllib.parse import urlsplit
from xml.parsers import expat

from ..filecheck import MAX_FILE_SIZE
from ..model import Finding, Severity, Topic, sort_findings
from ..x509info import Cert
from . import mtls

PROFILE_NOTE = "Configuration-profile (MDM) values for ManagedInstalls are not read; only the plist file is checked, and a profile can override any of these settings."


@dataclass(frozen=True)
class MunkiSettings:
    repo_url: str | None = None
    use_client_certificate: bool = False
    client_certificate_path: str | None = None
    client_key_path: str | None = None
    ca_certificate: str | None = None
    ca_path: str | None = None

    @property
    def repo_is_https(self) -> bool:
        return self.repo_url is not None and urlsplit(self.repo_url).scheme.lower() == "https"

    @property
    def repo_host(self) -> str | None:
        return urlsplit(self.repo_url).hostname if self.repo_url else None


_APPLE_DOCTYPE = re.compile(
    r'<!DOCTYPE\s+plist\s+PUBLIC\s+"-//Apple//DTD PLIST 1\.0//EN"\s+"http://www\.apple\.com/DTDs/PropertyList-1\.0\.dtd"\s*>'
)
_APPLE_PUBID = "-//Apple//DTD PLIST 1.0//EN"
_APPLE_SYSID = "http://www.apple.com/DTDs/PropertyList-1.0.dtd"
REFUSED = "Not a ManagedInstalls property list."
_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)
_NO_BOM = (  # XML 1.0 Appendix F: "<?" in each encoding without a byte order mark
    (b"\x00\x00\x00<", "utf-32-be"),
    (b"<\x00\x00\x00", "utf-32-le"),
    (b"\x00<\x00?", "utf-16-be"),
    (b"<\x00?\x00", "utf-16-le"),
)


def xml_text(data: bytes) -> str:
    """The XML as text, BOM and UTF-16/32 decoded (review M3c), so markup checks see what expat will see."""
    for bom, enc in _BOMS:
        if data.startswith(bom):
            return data[len(bom) :].decode(enc, "replace")
    for head, enc in _NO_BOM:
        if data.startswith(head):
            return data.decode(enc, "replace")
    return data.decode("utf-8", "replace")


def _refuse_dtd(data: bytes) -> None:
    """Text check on the decoded XML, then the same rule enforced by expat (which honours the declared encoding)."""
    rest = _APPLE_DOCTYPE.sub("", xml_text(data), count=1).upper()
    if "<!DOCTYPE" in rest or "<!ENTITY" in rest:
        raise ValueError(REFUSED)

    def doctype(name: str, sysid: str | None, pubid: str | None, internal: int) -> None:
        if name != "plist" or pubid != _APPLE_PUBID or sysid != _APPLE_SYSID or internal:
            raise ValueError(REFUSED)

    def refuse(*_: object) -> None:
        raise ValueError(REFUSED)

    px = expat.ParserCreate()
    px.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    px.StartDoctypeDeclHandler = doctype
    px.EntityDeclHandler = refuse
    px.UnparsedEntityDeclHandler = refuse
    px.NotationDeclHandler = refuse
    px.ExternalEntityRefHandler = refuse  # type: ignore[assignment]
    try:
        px.Parse(data, True)
    except (expat.ExpatError, RecursionError):
        raise ValueError(REFUSED) from None


def parse(data: bytes) -> MunkiSettings:
    """XML or binary plist; plistlib never resolves external entities."""
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("Plist is larger than 2 MB.")
    # Review S1/M3c: any ENTITY, or any DOCTYPE other than Apple's standard one (no internal subset), is refused,
    # in any encoding expat accepts (BOMs, UTF-16/32, declared encodings).
    if not data.startswith(b"bplist"):
        _refuse_dtd(data)
    try:
        d = plistlib.loads(data)
    except Exception as e:  # noqa: BLE001 - any malformed plist is the same user-facing error
        raise ValueError("Not a ManagedInstalls property list.") from e
    if not isinstance(d, dict):
        raise ValueError("Not a ManagedInstalls property list.")

    def s(k: str) -> str | None:
        v = d.get(k)
        return v if isinstance(v, str) and v.strip(" \t") else None

    u = d.get("UseClientCertificate")
    return MunkiSettings(
        s("SoftwareRepoURL"),
        u is True,
        s("ClientCertificatePath"),
        s("ClientKeyPath"),
        s("SoftwareRepoCACertificate"),
        s("SoftwareRepoCAPath"),
    )


def _f(fid: str, sev: Severity, t: str, d: str = "") -> Finding:
    return Finding(fid, sev, Topic.VENDOR, t, d, kind="munki-config")


def settings_findings(m: MunkiSettings) -> list[Finding]:
    out = [_f("munki-profiles", Severity.INFO, "Configuration-profile values not read", PROFILE_NOTE)]
    if m.repo_url is not None:
        if m.repo_is_https:
            out.append(_f("munki-url", Severity.PASS, "SoftwareRepoURL uses HTTPS", m.repo_url))
        else:
            out.append(
                _f(
                    "munki-url",
                    Severity.FAIL,
                    "SoftwareRepoURL is not HTTPS",
                    f"{m.repo_url}: catalogs, manifests and packages travel unencrypted and client certificates are never used.",
                )
            )
    else:
        out.append(
            _f(
                "munki-url",
                Severity.WARNING,
                "SoftwareRepoURL not set",
                "Munki falls back to http://munki/repo. It may be set by a configuration profile instead.",
            )
        )
    if m.ca_certificate is None:
        detail = (
            "SoftwareRepoCAPath is set (a folder); this check reads a single CA file. Supply one with --ca."
            if m.ca_path is not None
            else "The repo certificate must chain to a CA in the System keychain."
        )
        out.append(_f("munki-ca", Severity.INFO, "SoftwareRepoCACertificate not set", detail))
    if m.use_client_certificate:
        if m.client_certificate_path is None:
            out.append(
                _f(
                    "munki-clientcert",
                    Severity.WARNING,
                    "UseClientCertificate is true but ClientCertificatePath is not set",
                    "Munki then looks in <ManagedInstallDir>/certs. Supply the certificate with --cert to check it.",
                )
            )
    elif m.client_certificate_path is not None or m.client_key_path is not None:
        out.append(
            _f(
                "munki-clientcert",
                Severity.WARNING,
                "Client certificate paths set but UseClientCertificate is false",
                "Munki does not present the client certificate until UseClientCertificate is true.",
            )
        )
    return out


def inspect(
    m: MunkiSettings,
    cert: tuple[str, bytes] | None,
    key: tuple[str, bytes] | None,
    ca: tuple[str, bytes] | None,
    now: dt.datetime | None = None,
) -> tuple[list[Cert], list[Finding]]:
    """Validate an uploaded client pair against an uploaded repo CA. Plist paths are reported, never opened."""
    out = settings_findings(m)
    if cert is None:
        if m.use_client_certificate or m.client_certificate_path is not None:
            # Mac kind is "" (Finding default); kept so parity compares equal.
            out.append(
                Finding(
                    "munki-pair",
                    Severity.INFO,
                    Topic.VENDOR,
                    "Client certificate not checked",
                    "Upload the certificate named by ClientCertificatePath (and its key) to check it; paths inside the plist are not opened.",
                )
            )
        return [], sort_findings(out)
    chain, pair = mtls.inspect_data([cert] + ([key] if key else []), [ca] if ca else [], now, mtls.MUNKI)
    pair = [replace(g, topic=Topic.VENDOR, kind="munki-config") if g.topic == Topic.STACK else g for g in pair]
    return chain, sort_findings(out + pair)
