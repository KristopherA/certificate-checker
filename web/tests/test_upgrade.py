"""STARTTLS / pre-TLS dialogues against fake loopback servers (127.0.0.1 only; no network, no Docker).

Each fake server speaks one protocol's plaintext opening, then serves the "good" fixture chain over TLS.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import struct
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest

from certcheck import probe, wire
from certcheck.services import Service
from certcheck.shared import load_manifest, shared_dir

CA = shared_dir() / "fixtures" / "ca"
LOOPBACK_OK = probe.TargetPolicy(allow_loopback=True)
NOW = dt.datetime.fromisoformat(load_manifest()["pinned_now"].replace("Z", "+00:00"))
Script = Callable[[socket.socket], bool]  # returns True to continue with the TLS handshake


def recv_line(c: socket.socket) -> bytes:
    b = b""
    while not b.endswith(b"\n"):
        ch = c.recv(1)
        if not ch:
            break
        b += ch
    return b


def recv_n(c: socket.socket, n: int) -> bytes:
    b = b""
    while len(b) < n:
        ch = c.recv(n - len(b))
        if not ch:
            break
        b += ch
    return b


@contextmanager
def fake_server(script: Script) -> Iterator[int]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CA / "cases" / "good" / "chain.pem", CA / "cases" / "good" / "key.pem")
    lsock = socket.create_server(("127.0.0.1", 0))
    lsock.settimeout(5)
    port = lsock.getsockname()[1]

    def serve() -> None:
        try:
            conn, _ = lsock.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(5)
            try:
                if script(conn):
                    with ctx.wrap_socket(conn, server_side=True) as s:
                        s.recv(1)
            except (OSError, ssl.SSLError):
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield port
    finally:
        lsock.close()
        t.join(5)


def probe_with(service: Service, script: Script) -> probe.ProbeResult:
    with fake_server(script) as port:
        t = probe.Target("good.example.test", port, connect_ip="127.0.0.1", service=service)
        return probe.run(t, timeout=5, now=NOW, anchors=CA / "root.pem", policy=LOOPBACK_OK, nameservers=[])


def assert_trusted(r: probe.ProbeResult) -> None:
    assert r.error is None, r.error
    assert len(r.chain) == 2
    assert ("trust", "pass", "trust") in {f.key() for f in r.findings}


def assert_upgrade_failed(r: probe.ProbeResult, text: str) -> None:
    assert r.error is not None and text in r.error, r.error
    assert ("probe", "fail", "startTLS") in {f.key() for f in r.findings}
    assert not r.chain


# --- SMTP --------------------------------------------------------------------------------------


def smtp(
    ehlo: bytes = b"250-mx.example.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n", go: bytes = b"220 Go ahead\r\n"
) -> Script:
    def script(c: socket.socket) -> bool:
        c.sendall(b"220 mx.example.test ESMTP\r\n")
        if not recv_line(c).startswith(b"EHLO "):
            return False
        c.sendall(ehlo)
        if not ehlo.rstrip().endswith(b"STARTTLS"):
            return False
        if recv_line(c) != b"STARTTLS\r\n":
            return False
        c.sendall(go)
        return go.startswith(b"220")

    return script


def test_smtp_starttls() -> None:
    r = probe_with(Service.SMTP_STARTTLS, smtp())
    assert_trusted(r)
    assert "C: STARTTLS" in r.transcript


def test_smtp_without_starttls() -> None:
    assert_upgrade_failed(
        probe_with(Service.SMTP_STARTTLS, smtp(ehlo=b"250-mx\r\n250 SIZE 1000\r\n")), "does not advertise STARTTLS"
    )


def test_smtp_malformed_multiline() -> None:
    assert_upgrade_failed(probe_with(Service.SMTP_STARTTLS, smtp(ehlo=b"250-mx\r\n251 STARTTLS\r\n")), "malformed")


def test_smtp_starttls_refused() -> None:
    assert_upgrade_failed(
        probe_with(Service.SMTP_STARTTLS, smtp(go=b"454 TLS not available\r\n")), "STARTTLS returned 454"
    )


def test_smtp_injection_is_detected() -> None:
    r = probe_with(Service.SMTP_STARTTLS, smtp(go=b"220 Go ahead\r\n250 injected\r\n"))
    assert_upgrade_failed(r, "possible STARTTLS injection")


def test_smtp_overlong_line_is_refused() -> None:
    def script(c: socket.socket) -> bool:
        c.sendall(b"220-" + b"x" * 70_000 + b"\r\n")
        return False

    r = probe_with(Service.SMTP_STARTTLS, script)
    assert r.error is not None and not r.chain


# --- IMAP / POP3 -------------------------------------------------------------------------------


def imap(reply: bytes) -> Script:
    def script(c: socket.socket) -> bool:
        c.sendall(b"* OK IMAP4rev1 ready\r\n")
        assert recv_line(c) == b"a1 STARTTLS\r\n"
        c.sendall(reply)
        return reply.startswith(b"a1 OK")

    return script


def test_imap_starttls() -> None:
    assert_trusted(probe_with(Service.IMAP_STARTTLS, imap(b"a1 OK Begin TLS negotiation now\r\n")))


def test_imap_refused() -> None:
    assert_upgrade_failed(probe_with(Service.IMAP_STARTTLS, imap(b"a1 NO not now\r\n")), "IMAP STARTTLS refused")


def test_imap_bye() -> None:
    assert_upgrade_failed(probe_with(Service.IMAP_STARTTLS, imap(b"* BYE shutting down\r\n")), "closed the session")


def pop3(reply: bytes) -> Script:
    def script(c: socket.socket) -> bool:
        c.sendall(b"+OK POP3 ready\r\n")
        assert recv_line(c) == b"STLS\r\n"
        c.sendall(reply)
        return reply.startswith(b"+OK")

    return script


def test_pop3_stls() -> None:
    assert_trusted(probe_with(Service.POP3_STARTTLS, pop3(b"+OK Begin TLS\r\n")))


def test_pop3_refused() -> None:
    assert_upgrade_failed(probe_with(Service.POP3_STARTTLS, pop3(b"-ERR no\r\n")), "POP3 STLS refused")


# --- LDAP --------------------------------------------------------------------------------------


def ldap(code: int) -> Script:
    def script(c: socket.socket) -> bool:
        req = recv_n(c, len(wire.ldap_starttls_request()))
        assert req == wire.ldap_starttls_request()
        op = bytes([0x78, 0x07, 0x0A, 0x01, code, 0x04, 0x00, 0x04, 0x00])
        body = bytes([0x02, 0x01, 0x01]) + op
        c.sendall(bytes([0x30, len(body)]) + body)
        return code == 0

    return script


def test_ldap_starttls() -> None:
    r = probe_with(Service.LDAP_STARTTLS, ldap(0))
    assert_trusted(r)
    assert any("resultCode 0" in x for x in r.transcript)


def test_ldap_refused() -> None:
    assert_upgrade_failed(probe_with(Service.LDAP_STARTTLS, ldap(2)), "LDAP StartTLS refused (resultCode 2)")


# --- MySQL -------------------------------------------------------------------------------------


def mysql(caps: int) -> Script:
    def script(c: socket.socket) -> bool:
        g = b"\x0a8.0.36\x00" + bytes(4) + bytes(8) + b"\x00" + struct.pack("<H", caps) + bytes(16)
        c.sendall(len(g).to_bytes(3, "little") + b"\x00" + g)
        if not caps & 0x0800:
            return False
        assert recv_n(c, 36) == wire.mysql_ssl_request()
        return True

    return script


def test_mysql_ssl_request() -> None:
    assert_trusted(probe_with(Service.MYSQL, mysql(0x0800 | 0x0200)))


def test_mysql_without_tls() -> None:
    assert_upgrade_failed(probe_with(Service.MYSQL, mysql(0x0200)), "does not offer TLS")


# --- RDP ---------------------------------------------------------------------------------------


def rdp(neg_type: int, value: int) -> Script:
    def script(c: socket.socket) -> bool:
        req = recv_n(c, 19)
        assert req == wire.rdp_connection_request()
        neg = bytes([neg_type, 0, 0x08, 0x00]) + struct.pack("<I", value)
        x224 = bytes([14, 0xD0, 0, 0, 0x12, 0x34, 0]) + neg
        c.sendall(bytes([3, 0, 0, 4 + len(x224)]) + x224)
        return neg_type == 0x02

    return script


def test_rdp_nla_selected() -> None:
    r = probe_with(Service.RDP, rdp(0x02, wire.PROTOCOL_HYBRID))
    assert r.error is None, r.error
    assert ("rdp-neg", "pass", "remote") in {f.key() for f in r.findings}


def test_rdp_negotiation_failure() -> None:
    r = probe_with(Service.RDP, rdp(0x03, 3))
    assert r.error is not None and "SSL_CERT_NOT_ON_SERVER" in r.error
    keys = {f.key() for f in r.findings}
    assert ("rdp-neg", "fail", "remote") in keys
    assert not any(k[0] == "probe" for k in keys)  # the negotiation finding replaces the generic failure


def test_rdp_not_an_rdp_server() -> None:
    def script(c: socket.socket) -> bool:
        recv_n(c, 19)
        c.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        return False

    assert_upgrade_failed(probe_with(Service.RDP, script), "Not an RDP server")


# --- plumbing ----------------------------------------------------------------------------------


def test_pin_rejected_for_other_services() -> None:
    t = probe.Target("good.example.test", 443, service=Service.HTTPS, fingerprint_pin="AA" * 32)
    with pytest.raises(ValueError):
        t.validate()


def test_openssl_command_starttls_and_rdp() -> None:
    smtp_t = probe.Target("mx.example.test", 25, service=Service.SMTP_STARTTLS)
    assert "-starttls smtp" in probe.openssl_command(smtp_t)
    rdp_t = probe.Target("rdp.example.test", 3389, service=Service.RDP)
    assert "nmap" in probe.openssl_command(rdp_t)


def test_ldap_reply_with_other_message_id_is_rejected() -> None:
    def script(c: socket.socket) -> bool:
        recv_n(c, len(wire.ldap_starttls_request()))
        op = bytes([0x78, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00])
        body = bytes([0x02, 0x01, 0x02]) + op  # messageID 2: not the reply to our request
        c.sendall(bytes([0x30, len(body)]) + body)
        return False

    assert_upgrade_failed(probe_with(Service.LDAP_STARTTLS, script), "did not return an LDAP ExtendedResponse")


def test_mysql_refusal_text_is_sanitized_in_findings() -> None:
    def script(c: socket.socket) -> bool:
        e = b"\xff\x15\x04Host \x1b[31mblocked\r\n"
        c.sendall(len(e).to_bytes(3, "little") + b"\x00" + e)
        return False

    r = probe_with(Service.MYSQL, script)
    assert_upgrade_failed(r, "MySQL refused the connection: Host [31mblocked")
    assert all("\x1b" not in (f.detail or "") for f in r.findings)


def test_one_overall_deadline_covers_upgrade_and_handshake() -> None:
    """Review S5: a slow STARTTLS dialogue leaves less time for the handshake, not a fresh timeout."""
    import time

    def script(c: socket.socket) -> bool:
        time.sleep(0.6)  # slow greeting: uses most of the 1 s budget
        c.sendall(b"220 mx.example.test ESMTP\r\n")
        recv_line(c)
        c.sendall(b"250-mx.example.test\r\n250 STARTTLS\r\n")
        recv_line(c)
        c.sendall(b"220 Go ahead\r\n")
        time.sleep(2.5)  # then never start TLS
        return False

    with fake_server(script) as port:
        t = probe.Target("good.example.test", port, connect_ip="127.0.0.1", service=Service.SMTP_STARTTLS)
        start = time.monotonic()
        r = probe.run(t, timeout=1, now=NOW, anchors=CA / "root.pem", policy=LOOPBACK_OK, nameservers=[])
        took = time.monotonic() - start
    assert r.error is not None
    assert took < 1.4, took  # a per-step timeout would give the handshake another full second
