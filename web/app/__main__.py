"""python -m app: serve the UI with uvicorn. CERTCHECK_BIND (default 127.0.0.1) and CERTCHECK_PORT (8080).

M5 serves plain HTTP on loopback by default; the TLS 1.2+ listener (certcheck.listener), LAN bind and login
arrive in M6. Access logs carry method, path and status only (no bodies, no query strings with secrets: no
route takes a secret in the URL).
"""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "app.main:asgi",
        factory=True,
        host=os.environ.get("CERTCHECK_BIND", "127.0.0.1"),
        port=int(os.environ.get("CERTCHECK_PORT", "8080")),
        proxy_headers=False,
        server_header=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
