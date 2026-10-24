"""/config/ca/ (spec section 7): internal CA certificates trusted IN ADDITION to the system store.

At start the app writes one PEM bundle (system store + every certificate in /config/ca/*.pem|*.crt|*.cer) into a
private 0700 directory and passes it to the trust engine as its anchors; it is deleted at shutdown. Only
certificates are copied, re-encoded from the parsed objects: any other PEM block in a mounted file (a private key
put there by mistake) is never read into the bundle. Symlinks are refused (a link could point anywhere in the
container) and each file is capped at 1 MiB.

These anchors widen trust for EVERYTHING the trust engine verifies: live probes (TLS, STARTTLS, RADIUS, appliance
checks) as well as uploaded files. A certificate chaining to a /config/ca anchor is reported as trusted wherever it
is seen, so only put CAs you control there. CERTCHECK_ANCHORS still replaces the store outright (tests).
"""

from __future__ import annotations

import os
import shutil
import ssl
import stat
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

SUFFIXES = (".pem", ".crt", ".cer")
MAX_CA_FILE = 1 << 20  # 1 MiB per file: far above any real CA bundle, small enough to read in memory


def _read_regular(p: Path) -> bytes:
    """The file's bytes, refusing symlinks, anything but a regular file, and files over MAX_CA_FILE. Opened with
    O_NOFOLLOW and checked with fstat, so a swap between the check and the read cannot slip a link through."""
    fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{p}: not a regular file")
        if st.st_size > MAX_CA_FILE:
            raise ValueError(f"{p}: larger than {MAX_CA_FILE} bytes")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(MAX_CA_FILE + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_CA_FILE:
        raise ValueError(f"{p}: larger than {MAX_CA_FILE} bytes")
    return data


SYSTEM_CANDIDATES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem")


def internal_cas(ca_dir: Path) -> list[x509.Certificate]:
    if not ca_dir.is_dir():
        return []
    out: list[x509.Certificate] = []
    for p in sorted(ca_dir.iterdir()):
        if p.suffix.lower() not in SUFFIXES or p.name.startswith("."):
            continue
        if p.is_symlink():
            raise ValueError(f"{p}: symlinks are refused in /config/ca (copy the certificate in instead)")
        if not p.is_file():
            continue
        try:
            data = _read_regular(p)
        except OSError as x:
            raise ValueError(f"{p}: cannot read ({type(x).__name__})") from None
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
