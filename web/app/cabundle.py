"""/config/ca/ (spec section 7): internal CA certificates trusted IN ADDITION to the system store.

At start the app writes one PEM bundle (system store + every certificate in /config/ca/*.pem|*.crt|*.cer) into a
private 0700 directory and passes it to the trust engine as its anchors; it is deleted at shutdown. Only
certificates are copied, re-encoded from the parsed objects: any other PEM block in a mounted file (a private key
put there by mistake) is never read into the bundle. CERTCHECK_ANCHORS still replaces the store outright (tests).
"""

from __future__ import annotations

import os
import shutil
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

SUFFIXES = (".pem", ".crt", ".cer")
SYSTEM_CANDIDATES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem")


def internal_cas(ca_dir: Path) -> list[x509.Certificate]:
    if not ca_dir.is_dir():
        return []
    out: list[x509.Certificate] = []
    for p in sorted(ca_dir.iterdir()):
        if p.suffix.lower() not in SUFFIXES or not p.is_file() or p.name.startswith("."):
            continue
        data = p.read_bytes()
        try:
            certs = (
                x509.load_pem_x509_certificates(data)
                if b"-----BEGIN" in data
                else [x509.load_der_x509_certificate(data)]
            )
        except ValueError:
            raise ValueError(f"{p}: no certificate could be read (PEM or DER expected)") from None
        out.extend(certs)
    return out


def system_bundle() -> Path:
    paths = ssl.get_default_verify_paths()
    for c in (os.environ.get("SSL_CERT_FILE", ""), paths.cafile or "", paths.openssl_cafile, *SYSTEM_CANDIDATES):
        if c and Path(c).is_file():
            return Path(c)
    raise ValueError("no system CA bundle found to combine with /config/ca (set SSL_CERT_FILE)")


def build(ca_dir: Path) -> tuple[Path, Path] | None:
    """(bundle file, its private directory), or None when /config/ca holds no certificates."""
    cas = internal_cas(ca_dir)
    if not cas:
        return None
    system = system_bundle().read_bytes()
    d = Path(tempfile.mkdtemp(prefix="certcheck-ca-"))  # 0700
    try:
        bundle = d / "anchors.pem"
        bundle.write_bytes(system.rstrip(b"\n") + b"\n" + b"".join(c.public_bytes(Encoding.PEM) for c in cas))
    except OSError:
        shutil.rmtree(d, ignore_errors=True)
        raise
    return bundle, d
