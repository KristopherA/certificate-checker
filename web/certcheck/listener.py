"""TLS server context for the UI listener (the app arrives in M5). TLS 1.2+ only, default security level.

Kept apart from certcheck.legacy on purpose: tests/test_legacy.py proves this context refuses TLS 1.0.
"""

from __future__ import annotations

import ssl
from pathlib import Path


def server_context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx
