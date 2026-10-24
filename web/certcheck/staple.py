"""Stapled OCSP (M4, revocation step 1): the OCSP response the server sends in the TLS handshake.

Python's ssl module cannot request or read a stapled response, so this opens one more connection to the address
the probe already used (re-checked by TargetPolicy), repeats the same pre-TLS dialogue for STARTTLS-style
services, and does a pyOpenSSL handshake with status_request set (TLS 1.2+, no certificate verification: only
the stapled bytes are kept; revocation.check_ocsp verifies them against the issuer). No application data is
sent. Only used when revocation checking is switched on.
"""

from __future__ import annotations

import select
import socket
import time

from OpenSSL import SSL

from . import probe


def _handshake(conn: SSL.Connection, sock: socket.socket, deadline: float) -> None:
    while True:
        try:
            conn.do_handshake()
            return
        except (SSL.WantReadError, SSL.WantWriteError) as e:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("Timed out in the stapling handshake") from None
            r, w = ([sock], []) if isinstance(e, SSL.WantReadError) else ([], [sock])
            select.select(r, w, [], left)


def fetch_stapled(
    t: probe.Target, ip: str, *, policy: probe.TargetPolicy | None = None, timeout: float = 5.0
) -> tuple[bytes | None, str]:
    """(stapled DER or None, note). Never raises for network or TLS problems."""
    policy = policy or probe.TargetPolicy.from_env()
    deadline = time.monotonic() + timeout
    got: list[bytes] = []

    def cb(_conn: SSL.Connection, data: bytes, _arg: object) -> bool:
        got.append(data)
        return True  # accept: this connection only collects the bytes

    try:
        policy.check(ip, t.port)
        with socket.create_connection((ip, t.port), timeout=timeout) as raw:
            if t.service.uses_upgrade:
                c = probe._Reader(raw, deadline)
                probe.upgrade(c, t, probe.ProbeResult(target=t))
                if c.pending():
                    return None, "server sent unexpected bytes before the stapling handshake"
            ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
            ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
            ctx.set_verify(SSL.VERIFY_NONE)
            ctx.set_ocsp_client_callback(cb)
            conn = SSL.Connection(ctx, raw)
            sni = None if probe._is_ip(t.server_name) else t.server_name
            if sni:
                conn.set_tlsext_host_name(sni.encode("idna"))
            conn.request_ocsp()
            conn.set_connect_state()
            raw.setblocking(False)
            _handshake(conn, raw, deadline)
    except (OSError, ValueError, SSL.Error, probe.ProbeError) as e:
        return None, f"stapling handshake failed: {e or type(e).__name__}"
    data = got[0] if got else b""
    return (data, "stapled response received") if data else (None, "server did not staple an OCSP response")
