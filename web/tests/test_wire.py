"""Byte-level tests for the pre-TLS protocol helpers (certcheck.wire)."""

from __future__ import annotations

import struct

import pytest

from certcheck import wire
from certcheck.model import Severity


def ldap_response(code: int, tag: int = 0x78, msg_id: int = 1, raw_code: bytes | None = None) -> bytes:
    rc = raw_code if raw_code is not None else bytes([code])
    inner = bytes([0x0A, len(rc)]) + rc + bytes([0x04, 0x00, 0x04, 0x00])
    op = bytes([tag, len(inner)]) + inner
    body = bytes([0x02, 0x01, msg_id]) + op
    return bytes([0x30, len(body)]) + body


def test_ldap_starttls_request_carries_the_oid() -> None:
    req = wire.ldap_starttls_request()
    assert req[0] == 0x30 and req[1] == len(req) - 2
    assert wire.LDAP_STARTTLS_OID.encode() in req
    assert bytes([0x77]) in req  # [APPLICATION 23] ExtendedRequest


@pytest.mark.parametrize("code", [0, 2, 52])
def test_ldap_result_code(code: int) -> None:
    assert wire.ldap_extended_result_code(ldap_response(code)) == code


def test_ldap_non_extended_response_is_none() -> None:
    assert wire.ldap_extended_result_code(ldap_response(0, tag=0x61)) is None
    assert wire.ldap_extended_result_code(b"\x30\x05garbage") is None


@pytest.mark.parametrize("msg_id", [0, 2])
def test_ldap_other_message_id_is_none(msg_id: int) -> None:
    """Only the reply to our request (messageID 1) counts; 0 is an unsolicited notification."""
    assert wire.ldap_extended_result_code(ldap_response(0, msg_id=msg_id)) is None


@pytest.mark.parametrize("raw", [b"", b"\xff", b"\x01\x00\x00", b"\x80\x00", b"\x00\x00\x00\x00\x01"])
def test_ldap_result_code_is_capped(raw: bytes) -> None:
    """Empty, negative, over-long or out-of-range resultCodes are malformed, not a number to print."""
    assert wire.ldap_extended_result_code(ldap_response(0, raw_code=raw)) is None


def test_ldap_result_code_two_bytes_ok() -> None:
    assert wire.ldap_extended_result_code(ldap_response(0, raw_code=b"\x00\x7b")) == 123


def greeting(caps: int, version: bytes = b"8.0.36") -> bytes:
    return b"\x0a" + version + b"\x00" + bytes(4) + bytes(8) + b"\x00" + struct.pack("<H", caps) + bytes(16)


def test_mysql_greeting() -> None:
    g = wire.parse_mysql_greeting(greeting(0x0800 | 0x0200))
    assert g.version == "8.0.36" and g.supports_tls
    assert not wire.parse_mysql_greeting(greeting(0x0200)).supports_tls


@pytest.mark.parametrize(
    ("payload", "msg"),
    [
        (b"", "Empty"),
        (b"\xff\x15\x04Host is blocked", "refused the connection"),
        (b"\x09old\x00", "Unsupported MySQL protocol 9"),
        (b"\x0a8.0\x00\x01\x02", "Truncated"),
    ],
)
def test_mysql_greeting_errors(payload: bytes, msg: str) -> None:
    with pytest.raises(wire.WireError, match=msg):
        wire.parse_mysql_greeting(payload)


def test_mysql_text_is_sanitized() -> None:
    with pytest.raises(wire.WireError) as e:
        wire.parse_mysql_greeting(b"\xff\x15\x04Host \x1b[31mblocked\r\n" + b"x" * 400)
    msg = str(e.value)
    assert "\x1b" not in msg and "\r" not in msg and "Host [31mblocked" in msg
    assert len(msg) <= len("MySQL refused the connection: ") + 200
    g = wire.parse_mysql_greeting(greeting(0x0800, version=b"8.0\x1b[2J\x07"))
    assert g.version == "8.0[2J"


def test_mysql_ssl_request_shape() -> None:
    p = wire.mysql_ssl_request()
    assert len(p) == 4 + 32 and p[:4] == bytes([32, 0, 0, 1])
    assert struct.unpack("<I", p[4:8])[0] & 0x0800


def test_smtp_reply() -> None:
    assert wire.smtp_reply([]) is None
    assert wire.smtp_reply(["250-mx"]) is None
    assert wire.smtp_reply(["250-mx", "250 STARTTLS"]) == (250, ["250-mx", "250 STARTTLS"])
    assert wire.smtp_reply(["220"]) == (220, ["220"])
    assert wire.smtp_reply(["250-mx", "251 x"])[0] == -1  # type: ignore[index]
    assert wire.smtp_reply(["not smtp"]) is None


def test_sanitize_strips_controls_and_caps() -> None:
    assert wire.sanitize("a\x1b[31mb\r\n") == "a[31mb"
    assert len(wire.sanitize("x" * 500)) == 200


def confirm(neg_type: int, value: int, flags: int = 0) -> bytes:
    neg = bytes([neg_type, flags, 0x08, 0x00]) + struct.pack("<I", value)
    return bytes([14, 0xD0, 0, 0, 0x12, 0x34, 0]) + neg


def test_rdp_request_has_no_cookie() -> None:
    req = wire.rdp_connection_request()
    assert req[:2] == b"\x03\x00" and len(req) == req[3] == 19
    assert b"Cookie" not in req and b"mstshash" not in req
    assert struct.unpack("<I", req[-4:])[0] == wire.PROTOCOL_SSL | wire.PROTOCOL_HYBRID


def test_tpkt_length() -> None:
    assert wire.tpkt_length(b"\x03\x00\x00\x13") == 15
    for bad in (b"HTTP", b"\x03\x00\x00\x05", b"\x03\x00\x10\x00"):
        with pytest.raises(wire.WireError, match="Not an RDP server"):
            wire.tpkt_length(bad)


def test_rdp_confirm_kinds() -> None:
    n = wire.rdp_parse_confirm(confirm(0x02, wire.PROTOCOL_HYBRID))
    assert n == wire.Negotiation("selected", wire.PROTOCOL_HYBRID, 0) and wire.rdp_starts_tls(n)
    assert wire.rdp_parse_confirm(confirm(0x03, 5)) == wire.Negotiation("failure", 5)
    assert wire.rdp_parse_confirm(bytes([6, 0xD0, 0, 0, 0, 0, 0])).kind == "legacy"
    assert not wire.rdp_starts_tls(wire.Negotiation("selected", wire.PROTOCOL_RDP))


@pytest.mark.parametrize(
    ("t", "msg"),
    [
        (b"\x06\xd0", "Truncated"),
        (bytes([6, 0x80, 0, 0, 0, 0, 0]), "Disconnect Request"),
        (bytes([6, 0xF0, 0, 0, 0, 0, 0]), "Unexpected X.224"),
        (confirm(0x09, 1), "Unknown RDP negotiation type"),
    ],
)
def test_rdp_confirm_errors(t: bytes, msg: str) -> None:
    with pytest.raises(wire.WireError, match=msg):
        wire.rdp_parse_confirm(t)


def test_rdp_findings_and_descriptions() -> None:
    nla = wire.rdp_findings(wire.Negotiation("selected", wire.PROTOCOL_HYBRID))
    assert [(f.id, f.severity) for f in nla] == [("rdp-neg", Severity.PASS)]
    ssl_only = wire.rdp_findings(wire.Negotiation("selected", wire.PROTOCOL_SSL))
    assert ssl_only and ssl_only[0].severity != Severity.PASS
    fail = wire.rdp_findings(wire.Negotiation("failure", 3))
    assert any(f.severity == Severity.FAIL for f in fail)
    assert "SSL_CERT_NOT_ON_SERVER" in wire.rdp_describe(wire.Negotiation("failure", 3))
    assert "Standard RDP Security only" in wire.rdp_describe(wire.Negotiation("legacy"))
    assert wire.rdp_failure_name(99)[0] == "failure code 99"
