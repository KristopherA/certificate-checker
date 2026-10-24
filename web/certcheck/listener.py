"""TLS server context for the UI listener. TLS 1.2+ only, default security level, AEAD ciphers only.

TLS 1.2 is limited to ECDHE with AES-GCM or ChaCha20-Poly1305 (no CBC, no static RSA key exchange); TLS 1.3 suites
are all AEAD already.

Kept apart from certcheck.legacy on purpose: tests/test_legacy.py proves this context refuses TLS 1.0.
"""

from __future__ import annotations

import ssl
from pathlib import Path

TLS12_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL"


def server_context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(TLS12_CIPHERS)
    ctx.load_cert_chain(cert, key)
    return ctx
