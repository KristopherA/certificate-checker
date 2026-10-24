#!/usr/bin/env python3
"""Generate the TEST-ONLY certificates for the service-adjustment goldens (shared/fixtures/adjust).

Writes certificates only: the private keys are throw-away and never saved, so re-running changes every
certificate (then re-record shared/golden, see shared/README.md). Names are example.test. The
appliance/vendor look-alikes (SYNTHETIC-*.pem) are copies of the Mac test fixtures and are not made here.
Requires the 'cryptography' package (uv run --with cryptography ...).

Usage: make_adjust_fixtures.py [OUT_DIR [NAME ...]]   (default: shared/fixtures/adjust next to this script;
       NAMEs limit the run to those fixtures, e.g. the forged-* ones, so the others keep their bytes)
"""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

START = dt.datetime(2026, 10, 1, tzinfo=dt.UTC)
END = dt.datetime(2027, 9, 1, tzinfo=dt.UTC)  # 335 days, covers the pinned 2027-01-15
RDA = x509.ObjectIdentifier("1.3.6.1.4.1.311.54.1.2")


def nm(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SYNTHETIC"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subject, key, issuer=None, ikey=None, *, san=None, eku=None, ca=False) -> x509.Certificate:
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer or subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(START)
        .not_valid_after(END)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if ikey is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ikey.public_key()), critical=False)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if ca:
        b = b.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    return b.sign(ikey or key, hashes.SHA256())


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "adjust"
    only = set(sys.argv[2:])
    out.mkdir(parents=True, exist_ok=True)
    k = lambda: ec.generate_private_key(ec.SECP256R1())  # noqa: E731
    S = [ExtendedKeyUsageOID.SERVER_AUTH]

    def write(name: str, *certs: x509.Certificate) -> None:
        if only and name not in only:
            return
        (out / f"{name}.pem").write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs))

    a = k()
    write("rdp-selfsigned", cert(nm("rdp.example.test"), a, san=["rdp.example.test"], eku=S))
    a = k()
    write("rdp-rda-only", cert(nm("rdp.example.test"), a, san=["rdp.example.test"], eku=[RDA]))
    a = k()
    write("rdp-clientauth", cert(nm("rdp.example.test"), a, san=["rdp.example.test"], eku=[ExtendedKeyUsageOID.CLIENT_AUTH]))
    a = k()
    write("rdp-nosan", cert(nm("rdp.example.test"), a, eku=S))
    a = k()
    write("rdg-selfsigned", cert(nm("rdg.example.test"), a, san=["rdg.example.test"], eku=S))
    ck = k()
    ca = cert(nm("SYNTHETIC Remote CA"), ck, ca=True)
    lk = k()
    write(
        "winrm-cn",
        cert(nm("other.example.test"), lk, ca.subject, ck, san=["winrm.example.test"], eku=S),
        ca,
    )
    # Forged-issuer look-alikes (review B1): the issuer NAME claims the appliance's own CA, but the leaf is
    # signed by an unrelated throw-away key and sent alone. The downgrade must not fire for these.
    def forged(issuer: list[tuple[x509.ObjectIdentifier, str]], host: str) -> x509.Certificate:
        name = x509.Name([x509.NameAttribute(o, v) for o, v in issuer])
        return cert(nm(host), k(), name, k(), san=[host], eku=S)

    write(
        "forged-synology",
        forged([(NameOID.ORGANIZATION_NAME, "Synology Inc."), (NameOID.COMMON_NAME, "Synology Inc. CA")], "nas.example.test"),
    )
    write(
        "forged-pve",
        forged(
            [(NameOID.ORGANIZATION_NAME, "PVE Cluster Manager CA"), (NameOID.COMMON_NAME, "Proxmox Virtual Environment")],
            "pve.example.test",
        ),
    )
    print(f"wrote adjust fixtures to {out}")


if __name__ == "__main__":
    main()
