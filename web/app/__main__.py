"""python -m app: serve the UI with uvicorn (one worker, one event loop; see main.py).

    python -m app                  serve (TLS 1.2+ on CERTCHECK_BIND:CERTCHECK_PORT, default 0.0.0.0:8080)
    python -m app hash-password    read a password twice (no echo) and print its argon2id hash

Environment: CERTCHECK_BIND, CERTCHECK_PORT, CERTCHECK_TLS (on by default; "off" only on a loopback bind, for a
TLS-terminating proxy on the same host), CERTCHECK_TLS_NAMES (names for the self-signed certificate),
CERTCHECK_STATE (where the self-signed certificate is kept, default /data), CERTCHECK_PASSWORD_HASH or
CERTCHECK_PASSWORD_HASH_FILE, CERTCHECK_NO_LOGIN=1 (loopback bind only; tests). Everything else: settings.py.

Clients outside the LAN are refused by the app (security.lan_client) even on a 0.0.0.0 bind. Access logs carry
method, path and status only; no route takes a secret in the URL.
"""

from __future__ import annotations

import getpass
import ipaddress
import logging
import os
import ssl
import sys
from pathlib import Path

import uvicorn

from certcheck import listener

from . import auth, tlsboot
from .settings import tls_enabled

log = logging.getLogger("certcheck.web")


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def hash_password() -> int:
    pw = getpass.getpass("Password: ")
    if len(pw) < 12:
        print("Use at least 12 characters.", file=sys.stderr)
        return 2
    if pw != getpass.getpass("Again: "):
        print("The passwords differ.", file=sys.stderr)
        return 2
    print(auth.hash_password(pw))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["hash-password"]:
        return hash_password()
    if args:
        print(__doc__, file=sys.stderr)
        return 2
    logging.basicConfig(level="INFO", format="%(levelname)s %(name)s: %(message)s")
    env = os.environ
    host = env.get("CERTCHECK_BIND", "0.0.0.0").strip()  # noqa: S104  LAN by design; non-LAN clients are refused
    port = int(env.get("CERTCHECK_PORT", "8080"))
    tls = tls_enabled(env)
    if not tls and not _loopback(host):
        print("CERTCHECK_TLS=off is only allowed with a loopback CERTCHECK_BIND (behind a TLS proxy).", file=sys.stderr)
        return 2
    if env.get("CERTCHECK_NO_LOGIN", "").strip().lower() in ("1", "true", "yes", "on") and not _loopback(host):
        print("CERTCHECK_NO_LOGIN is only allowed with a loopback CERTCHECK_BIND.", file=sys.stderr)
        return 2
    kw: dict[str, object] = {}
    if tls:
        ui = tlsboot.ensure(Path(env.get("CERTCHECK_CONFIG", "/config")), Path(env.get("CERTCHECK_STATE", "/data")),
                            tlsboot.default_names(env.get("CERTCHECK_TLS_NAMES", "")))  # fmt: skip
        log.warning("UI certificate (%s): SHA-256 %s", ui.source, ui.fingerprint)

        def context(_cfg: uvicorn.Config, _default: object) -> ssl.SSLContext:
            return listener.server_context(ui.cert, ui.key)  # TLS 1.2+ only; never the legacy context

        kw = {"ssl_certfile": str(ui.cert), "ssl_keyfile": str(ui.key), "ssl_context_factory": context}
    uvicorn.run(
        "app.main:asgi",
        factory=True,
        host=host,
        port=port,
        workers=1,
        proxy_headers=False,
        server_header=False,
        timeout_graceful_shutdown=5,  # open keep-alive TLS connections must not hold up a restart
        log_level="info",
        **kw,  # type: ignore[arg-type]
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
