"""S/MIME certificate usage and expiry (SMIME.swift). Offline: reads certificates already parsed from a file."""

from __future__ import annotations

import datetime as dt

from ..model import Finding, Severity, Topic
from ..x509info import Cert, oid_name

EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"
ANY_EKU = "2.5.29.37.0"


def addresses(c: Cert) -> list[str]:
    """SAN rfc822Name entries, else the legacy subject emailAddress attribute (lowercased)."""
    san = [e.lower() for e in c.emails]
    return san if san else [e.lower() for e in c.subject_emails]


def bit(bits: bytes | None, n: int) -> bool:
    if bits is None or n // 8 >= len(bits):
        return False
    return bits[n // 8] & (0x80 >> (n % 8)) != 0


def _days(delta: dt.timedelta) -> int:
    return int(delta.total_seconds() / 86_400)  # truncates toward zero, like Swift Int(Double)


def inspect(
    leaf: Cert, address: str | None = None, now: dt.datetime | None = None, warn_days: int = 30
) -> list[Finding]:
    now = now or dt.datetime.now(dt.UTC)

    def f(fid: str, s: Severity, t: Topic, title: str, d: str = "") -> Finding:
        return Finding(fid, s, t, title, d, kind="smime")

    out: list[Finding] = []
    e = leaf.eku
    if e is None:
        out.append(
            f(
                "smime-eku",
                Severity.WARNING,
                Topic.EKU,
                "No Extended Key Usage",
                "Without the E-mail Protection EKU, some mail clients refuse the certificate for S/MIME.",
            )
        )
    elif EMAIL_PROTECTION in e:
        out.append(f("smime-eku", Severity.PASS, Topic.EKU, "E-mail Protection EKU present"))
    elif ANY_EKU in e:
        out.append(
            f(
                "smime-eku",
                Severity.WARNING,
                Topic.EKU,
                "Only Any Extended Key Usage",
                "Clients that require the E-mail Protection EKU will reject it.",
            )
        )
    else:
        out.append(
            f(
                "smime-eku",
                Severity.FAIL,
                Topic.EKU,
                "Not valid for e-mail",
                f"EKU lists {', '.join(oid_name(o) for o in e)} but not E-mail Protection.",
            )
        )
    if leaf.is_ca is True:
        out.append(
            f(
                "smime-ca",
                Severity.FAIL,
                Topic.CA_LEAF,
                "Certificate is a CA",
                "An S/MIME certificate should be an end-entity certificate.",
            )
        )
    ku = leaf.key_usage_bits
    if ku is not None:
        sign = bit(ku, 0) or bit(ku, 1)
        kind = leaf.key.algorithm[0]
        enc = bit(ku, 2) if kind == "rsa" else bit(ku, 4) if kind == "ec" else False
        out.append(
            f(
                "smime-ku-sign",
                Severity.PASS if sign else Severity.WARNING,
                Topic.EKU,
                "Key usage allows signing" if sign else "Key usage does not allow signing",
                "" if sign else "Digital Signature is not set, so signed mail will not verify.",
            )
        )
        out.append(
            f(
                "smime-ku-encrypt",
                Severity.PASS if enc else Severity.INFO,
                Topic.EKU,
                "Key usage allows encryption" if enc else "Key usage does not allow encryption",
                "" if enc else "Signing-only certificate: others cannot encrypt mail to this address with it.",
            )
        )
    else:
        out.append(f("smime-ku", Severity.INFO, Topic.EKU, "No Key Usage extension", "Any key usage is allowed."))
    names = addresses(leaf)
    a = (address or "").strip().lower()
    if not names:
        out.append(
            f(
                "smime-address",
                Severity.FAIL,
                Topic.HOSTNAME,
                "No e-mail address in the certificate",
                "Neither the SAN nor the subject names an address, so clients cannot match it to a sender.",
            )
        )
    elif a:
        if a in names:
            out.append(f("smime-address", Severity.PASS, Topic.HOSTNAME, f"Certificate names {a}"))
        else:
            out.append(
                f(
                    "smime-address",
                    Severity.FAIL,
                    Topic.HOSTNAME,
                    f"Certificate does not name {a}",
                    f"It names {', '.join(names)}.",
                )
            )
    else:
        out.append(f("smime-address", Severity.INFO, Topic.HOSTNAME, f"Certificate names {', '.join(names)}"))
    if not leaf.emails and names:
        out.append(
            f(
                "smime-san",
                Severity.WARNING,
                Topic.NO_SAN,
                "Address only in the subject",
                "Current S/MIME rules require the address in the SAN as an rfc822Name.",
            )
        )
    days = _days(leaf.not_after - now)
    if now < leaf.not_before:
        out.append(
            f(
                "smime-expiry",
                Severity.FAIL,
                Topic.EXPIRY,
                "Not yet valid",
                f"Valid from {leaf.not_before:%Y-%m-%d %H:%M:%S} +0000.",
            )
        )
    elif days < 0:
        out.append(
            f(
                "smime-expiry",
                Severity.FAIL,
                Topic.EXPIRY,
                f"Expired {-days} days ago",
                "New mail cannot be signed or encrypted with it. Keep the key to read old encrypted mail.",
            )
        )
    elif days < warn_days:
        out.append(
            f(
                "smime-expiry",
                Severity.WARNING,
                Topic.EXPIRY,
                f"Expires in {days} days",
                "Renew it and keep the old key for archived mail.",
            )
        )
    else:
        out.append(f("smime-expiry", Severity.PASS, Topic.EXPIRY, f"Valid for {days} more days"))
    kind, v = leaf.key.algorithm
    if kind == "rsa" and int(v) < 2048:
        out.append(f("smime-key", Severity.FAIL, Topic.WEAK_KEY, f"RSA key is {v} bits", "Use at least 2048 bits."))
    else:
        out.append(f("smime-key", Severity.PASS, Topic.WEAK_KEY, "Key strength OK"))
    if leaf.signature_is_weak:
        out.append(
            f("smime-sig", Severity.FAIL, Topic.WEAK_SIGNATURE, "Weak signature algorithm", leaf.signature_algorithm)
        )
    return out
