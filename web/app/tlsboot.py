"""UI certificate (spec section 5, TLS 1.2+ only): /config/tls/cert.pem + key.pem when mounted, otherwise a
self-signed certificate generated on first run and kept in the state directory (CERTCHECK_STATE, default /data).

The generated key is written once, mode 0600 in a 0700 directory, and reused until the certificate is within 30
days of expiry. Its SHA-256 fingerprint is logged at start so the user can compare it with the browser's warning.
The listener itself is certcheck.listener.server_context (TLS 1.2 minimum, never the legacy context).
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import socket
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

VALID_DAYS = 397
RENEW_DAYS = 30


@dataclass(frozen=True)
class UICert:
    cert: Path
    key: Path
    source: str  # "mounted", "generated" or "reused"
    fingerprint: str


def ensure(config_dir: Path, state_dir: Path, names: list[str], now: dt.datetime | None = None) -> UICert:
    mounted_c, mounted_k = config_dir / "tls" / "cert.pem", config_dir / "tls" / "key.pem"
    if mounted_c.exists() or mounted_k.exists():
        if not (mounted_c.is_file() and mounted_k.is_file()):
            raise ValueError(f"{config_dir / 'tls'} needs both cert.pem and key.pem")
        return UICert(mounted_c, mounted_k, "mounted", _fingerprint(mounted_c))
    now = now or dt.datetime.now(dt.UTC)
    d = state_dir / "tls"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    c, k = d / "selfsigned.pem", d / "selfsigned.key"
    if c.is_file() and k.is_file():
        try:
            old = x509.load_pem_x509_certificate(c.read_bytes())
            if old.not_valid_after_utc - now > dt.timedelta(days=RENEW_DAYS):
                return UICert(c, k, "reused", _fingerprint(c))
        except ValueError:
            pass
    key = ec.generate_private_key(ec.SECP256R1())
    sans = _sans(names)
    first = next((n for n in names if n), "certcheck")
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Certificate Checker (self-signed)"),
                      x509.NameAttribute(NameOID.COMMON_NAME, first[:64])])  # fmt: skip
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())  # fmt: skip
    _write_private(k, pem_key)
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return UICert(c, k, "generated", _fingerprint(c))


def default_names(env_names: str) -> list[str]:
    """CERTCHECK_TLS_NAMES (comma-separated DNS names or IPs) first, then this host's name and localhost."""
    out = [n.strip().lower() for n in env_names.split(",") if n.strip()]
    for n in (socket.gethostname().lower(), "localhost", "127.0.0.1", "::1"):
        if n and n not in out:
            out.append(n)
    return out


def _sans(names: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = []
    for n in names:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            if n and all(p and len(p) <= 63 for p in n.split(".")) and len(n) <= 253:
                out.append(x509.DNSName(n))
    return out


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _fingerprint(path: Path) -> str:
    try:
        c = x509.load_pem_x509_certificate(path.read_bytes())
    except ValueError as e:
        raise ValueError(f"{path}: not a PEM certificate") from e
    return c.fingerprint(hashes.SHA256()).hex(":").upper()
