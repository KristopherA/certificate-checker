"""Builders and parsers for the plaintext stage of each upgrade protocol.

Mirrors Wire and RDP in Source/Sources/Core/Probe.swift and Remote.swift: same bytes, same parse
rules, same messages and the same rdp-* findings. Pure functions, unit tested without a network.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .model import Finding, Severity, Topic


class WireError(ValueError):
    """A malformed or refused plaintext reply (Swift CheckError.message)."""


# --- LDAP StartTLS (RFC 4511 4.14.1) ---------------------------------------------------------

LDAP_STARTTLS_OID = "1.3.6.1.4.1.1466.20037"


def _tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + body


def ldap_starttls_request() -> bytes:
    """LDAPv3 ExtendedRequest for StartTLS, messageID 1."""
    ext = _tlv(0x77, _tlv(0x80, LDAP_STARTTLS_OID.encode()))
    return _tlv(0x30, bytes([0x02, 0x01, 0x01]) + ext)


def _parse_tlv(b: bytes, i: int) -> tuple[int, bytes, int]:
    """(tag, value, next index). Definite lengths only, like the Swift DER reader."""
    if i + 2 > len(b):
        raise WireError("truncated")
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or i + k > len(b):
            raise WireError("bad length")
        n = int.from_bytes(b[i : i + k], "big")
        i += k
    if i + n > len(b):
        raise WireError("truncated")
    return tag, b[i : i + n], i + n


def _children(v: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i < len(v):
        t, val, i = _parse_tlv(v, i)
        out.append((t, val))
    return out


LDAP_MESSAGE_ID = 1  # the only request we send (ldap_starttls_request)
LDAP_MAX_RESULT_CODE = 0x7FFF  # defined codes are < 200; a longer or negative ENUMERATED is malformed


def ldap_extended_result_code(message: bytes) -> int | None:
    """resultCode of the ExtendedResponse to our StartTLS request (messageID 1), or None when the message is
    not one: another messageID (including 0, an unsolicited notification), or a resultCode that is empty,
    longer than 2 bytes, negative or above LDAP_MAX_RESULT_CODE."""
    try:
        tag, body, _ = _parse_tlv(message, 0)
        if tag != 0x30:
            return None
        parts = _children(body)
        if len(parts) < 2 or parts[0][0] != 0x02 or parts[0][1] != bytes([LDAP_MESSAGE_ID]):
            return None
        op = next((v for t, v in parts if t == 0x78), None)
        if op is None:
            return None
        kids = _children(op)
    except WireError:
        return None
    if not kids or kids[0][0] != 0x0A or not 1 <= len(kids[0][1]) <= 2:
        return None
    code = int.from_bytes(kids[0][1], "big", signed=True)
    return code if 0 <= code <= LDAP_MAX_RESULT_CODE else None


# --- MySQL ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class MySQLGreeting:
    version: str
    supports_tls: bool


def _utf8(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def parse_mysql_greeting(payload: bytes) -> MySQLGreeting:
    if not payload:
        raise WireError("Empty MySQL greeting")
    proto = payload[0]
    if proto == 0xFF:
        msg = _utf8(payload[3:]) if len(payload) > 3 else ""
        raise WireError(f"MySQL refused the connection: {sanitize(msg)}")
    nul = payload.find(b"\x00", 1)
    if proto != 10 or nul < 0:
        raise WireError(f"Unsupported MySQL protocol {proto}")
    version = sanitize(_utf8(payload[1:nul]))  # server-controlled text that ends up in findings
    cap = nul + 1 + 4 + 8 + 1
    if len(payload) < cap + 2:
        raise WireError("Truncated MySQL greeting")
    caps = payload[cap] | payload[cap + 1] << 8
    return MySQLGreeting(version, bool(caps & 0x0800))


def mysql_ssl_request() -> bytes:
    """SSLRequest (sequence 1): CLIENT_SSL | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION."""
    p = struct.pack("<II", 0x0800 | 0x0200 | 0x8000, 16 * 1024 * 1024) + b"\x21" + bytes(23)
    return len(p).to_bytes(3, "little") + b"\x01" + p


# --- SMTP and text helpers --------------------------------------------------------------------


def smtp_reply(lines: list[str]) -> tuple[int, list[str]] | None:
    """Multi-line SMTP reply: None until the final line arrives; code -1 when the codes disagree."""
    if not lines:
        return None
    last = lines[-1]
    if len(last) < 3 or not last[:3].isdigit():
        return None
    code = int(last[:3])
    if not all(line.startswith(last[:3]) for line in lines):
        return (-1, lines)
    if len(last) == 3 or last[3] == " ":
        return (code, lines)
    return None


def sanitize(s: str) -> str:
    """Printable ASCII only, at most 200 characters: for any server-supplied text shown to the user."""
    return "".join(c for c in s if 0x20 <= ord(c) < 0x7F)[:200]


# --- RDP (MS-RDPBCGR 2.2.1.1 / 2.2.1.2) -------------------------------------------------------

PROTOCOL_RDP, PROTOCOL_SSL, PROTOCOL_HYBRID = 0, 0x1, 0x2
PROTOCOL_RDSTLS, PROTOCOL_HYBRID_EX, PROTOCOL_RDSAAD = 0x4, 0x8, 0x10
REMOTE_DESKTOP_AUTH_EKU = "1.3.6.1.4.1.311.54.1.2"


@dataclass(frozen=True)
class Negotiation:
    """kind "selected" (value = protocol, flags), "failure" (value = code) or "legacy" (no RDP_NEG_RSP)."""

    kind: str
    value: int = 0
    flags: int = 0


def rdp_connection_request(requested: int = PROTOCOL_SSL | PROTOCOL_HYBRID) -> bytes:
    """TPKT + X.224 Connection Request + RDP_NEG_REQ. No routing token and no cookie (no user name)."""
    neg = bytes([0x01, 0x00, 0x08, 0x00]) + struct.pack("<I", requested)
    x224 = bytes([6 + len(neg), 0xE0, 0, 0, 0, 0, 0]) + neg
    total = 4 + len(x224)
    return bytes([0x03, 0x00, total >> 8, total & 0xFF]) + x224


def tpkt_length(head: bytes) -> int:
    if len(head) != 4 or head[0] != 0x03 or head[1] != 0x00:
        raise WireError("Not an RDP server: the reply is not a TPKT (RFC 1006) packet.")
    n = head[2] << 8 | head[3]
    if not 11 <= n <= 1024:
        raise WireError(f"Not an RDP server: TPKT length {n} is out of range.")
    return n - 4


def rdp_parse_confirm(t: bytes) -> Negotiation:
    if len(t) < 7 or t[0] + 1 > len(t):
        raise WireError("Truncated X.224 reply.")
    code = t[1] & 0xF0
    if code == 0x80:
        raise WireError("The server sent an X.224 Disconnect Request instead of a Connection Confirm.")
    if code != 0xD0:
        raise WireError(f"Unexpected X.224 TPDU code 0x{t[1]:02X}.")
    if t[0] < 14 or len(t) < 15:
        return Negotiation("legacy")
    n = t[7:15]
    if n[2] != 0x08 or n[3] != 0x00:
        raise WireError("Malformed RDP negotiation response (length field).")
    value = struct.unpack("<I", n[4:8])[0]
    if n[0] == 0x02:
        return Negotiation("selected", value, n[1])
    if n[0] == 0x03:
        return Negotiation("failure", value)
    raise WireError(f"Unknown RDP negotiation type 0x{n[0]:02X}.")


_PROTOCOL_NAMES = {
    PROTOCOL_RDP: "Standard RDP Security (PROTOCOL_RDP, no TLS)",
    PROTOCOL_SSL: "TLS without NLA (PROTOCOL_SSL)",
    PROTOCOL_HYBRID: "CredSSP / NLA (PROTOCOL_HYBRID)",
    PROTOCOL_RDSTLS: "RDSTLS",
    PROTOCOL_HYBRID_EX: "CredSSP with Early User Authorization (PROTOCOL_HYBRID_EX)",
    PROTOCOL_RDSAAD: "RDS AAD Auth",
}
_FAILURES = {
    1: ("SSL_REQUIRED_BY_SERVER", "The server requires TLS but the request did not offer it."),
    2: (
        "SSL_NOT_ALLOWED_BY_SERVER",
        "The server allows only Standard RDP Security (Security Layer = RDP). TLS is disabled.",
    ),
    3: (
        "SSL_CERT_NOT_ON_SERVER",
        "The server has no usable certificate: the bound certificate is missing, or NETWORK SERVICE cannot "
        "read its private key.",
    ),
    4: ("INCONSISTENT_FLAGS", "The server rejected the requested protocol flags."),
    5: ("HYBRID_REQUIRED_BY_SERVER", "The server requires CredSSP / NLA."),
    6: ("SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER", "The server requires TLS with client certificate authentication."),
}


def rdp_protocol_name(p: int) -> str:
    return _PROTOCOL_NAMES.get(p, f"unknown protocol 0x{p:08X}")


def rdp_failure_name(c: int) -> tuple[str, str]:
    return _FAILURES.get(c, (f"failure code {c}", "Unknown negotiation failure."))


def rdp_starts_tls(n: Negotiation) -> bool:
    """Only the protocols this probe requested (SSL | HYBRID)."""
    return n.kind == "selected" and n.value in (PROTOCOL_SSL, PROTOCOL_HYBRID)


def rdp_describe(n: Negotiation) -> str:
    if n.kind == "selected":
        return f"RDP negotiation: server selected {rdp_protocol_name(n.value)}"
    if n.kind == "failure":
        return f"RDP negotiation failed: {rdp_failure_name(n.value)[0]}"
    return "RDP server did not negotiate (no RDP_NEG_RSP): Standard RDP Security only"


def rdp_findings(n: Negotiation) -> list[Finding]:
    R = Topic.REMOTE
    if n.kind == "selected":
        p = n.value
        if p == PROTOCOL_HYBRID:
            return [
                Finding(
                    "rdp-neg",
                    Severity.PASS,
                    R,
                    f"RDP: server selected {rdp_protocol_name(p)}",
                    "Network Level Authentication is required. This probe stops after the TLS handshake and sends "
                    "no credentials.",
                    "rdp-neg",
                )
            ]
        if p == PROTOCOL_SSL:
            return [
                Finding(
                    "rdp-nla",
                    Severity.WARNING,
                    R,
                    "RDP: TLS without Network Level Authentication",
                    "CredSSP was offered but the server chose plain TLS, so the logon screen is reachable before "
                    "authentication. Require NLA on the host.",
                    "rdp-nla",
                )
            ]
        if p == PROTOCOL_RDP:
            return [
                Finding(
                    "rdp-neg",
                    Severity.FAIL,
                    R,
                    "RDP: server selected Standard RDP Security (no TLS)",
                    "The server ignored the TLS/CredSSP request. Set the Security Layer to SSL (TLS) or Negotiate "
                    "and require NLA.",
                    "rdp-security",
                )
            ]
        return [
            Finding(
                "rdp-neg",
                Severity.FAIL,
                R,
                "RDP: server selected a protocol that was not requested",
                f"{rdp_protocol_name(p)}. Only PROTOCOL_SSL | PROTOCOL_HYBRID was offered, so the server is not "
                "following MS-RDPBCGR negotiation (or something in between rewrote it).",
                "rdp-security",
            )
        ]
    if n.kind == "failure":
        name, meaning = rdp_failure_name(n.value)
        kind = "rdp-cert" if n.value == 3 else "rdp-security"
        return [Finding("rdp-neg", Severity.FAIL, R, f"RDP negotiation failed: {name}", meaning, kind)]
    return [
        Finding(
            "rdp-neg",
            Severity.FAIL,
            R,
            "RDP server did not negotiate TLS",
            "The Connection Confirm carried no RDP negotiation response: the server speaks only Standard RDP "
            "Security (very old, or Security Layer = RDP).",
            "rdp-security",
        )
    ]
