"""PKCS#12 pre-checks run before cryptography decrypts anything (review S2, S6).

read_params walks the outer DER (bounded depth and node count, never decrypting) and returns every
iteration count it can see: the MacData iterations, PKCS#12 PBE parameters and PBKDF2 (PBES2) parameters
on the unencrypted layers. Counts above MAX_ITERATIONS are refused, so an upload cannot make the server
spend minutes in a KDF. Bags inside an encrypted SafeContents only become visible after decryption; their
counts are bounded by cryptography/OpenSSL alone (documented in shared/known-differences.yaml).

mac_matches recomputes the RFC 7292 MAC (Appendix B key derivation, HMAC over the authSafe content) so a
wrong password can be told apart from a corrupt file: MAC mismatch = wrong password (or a damaged
authSafe); MAC match but unreadable = corrupt.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

MAX_ITERATIONS = 1_000_000
MAX_DEPTH = 24
MAX_NODES = 50_000

_PKCS12_PBE = bytes.fromhex("2a864886f70d010c01")  # 1.2.840.113549.1.12.1.x prefix
_PBKDF2 = bytes.fromhex("2a864886f70d01050c")  # 1.2.840.113549.1.5.12
_DATA = bytes.fromhex("2a864886f70d010701")  # 1.2.840.113549.1.7.1
_HASHES = {
    bytes.fromhex("2b0e03021a"): ("sha1", 64),
    bytes.fromhex("608648016503040201"): ("sha256", 64),
    bytes.fromhex("608648016503040202"): ("sha384", 128),
    bytes.fromhex("608648016503040203"): ("sha512", 128),
    bytes.fromhex("608648016503040204"): ("sha224", 64),
}


class Corrupt(ValueError):
    """The outer PKCS#12 structure is not valid DER."""


@dataclass
class Params:
    iterations: list[int] = field(default_factory=list)
    mac: tuple[str, int, bytes, int, bytes, bytes] | None = None  # hash, block, salt, iterations, digest, content


@dataclass(frozen=True)
class _TLV:
    tag: int
    body: bytes


def _tlvs(buf: bytes) -> list[_TLV]:
    out, i = [], 0
    while i < len(buf):
        if i + 2 > len(buf):
            raise Corrupt("truncated")
        tag, n = buf[i], buf[i + 1]
        i += 2
        if tag & 0x1F == 0x1F:
            raise Corrupt("high tag")
        if n & 0x80:
            k = n & 0x7F
            if k == 0 or k > 4 or i + k > len(buf):
                raise Corrupt("bad length")
            n = int.from_bytes(buf[i : i + k], "big")
            i += k
        if i + n > len(buf):
            raise Corrupt("truncated")
        out.append(_TLV(tag, buf[i : i + n]))
        i += n
    return out


def _int(t: _TLV) -> int:
    if t.tag != 0x02 or not t.body:
        raise Corrupt("not an INTEGER")
    if len(t.body) > 8:
        return MAX_ITERATIONS + 1  # absurd; refused by the cap
    return int.from_bytes(t.body, "big", signed=True)


def read_params(data: bytes) -> Params:
    p = Params()
    top = _tlvs(data)
    if len(top) != 1 or top[0].tag != 0x30:
        raise Corrupt("not a SEQUENCE")
    pfx = _tlvs(top[0].body)
    if len(pfx) < 2 or pfx[0].tag != 0x02 or pfx[1].tag != 0x30:
        raise Corrupt("not a PFX")
    nodes = 0

    def walk(buf: bytes, depth: int, try_only: bool) -> None:
        nonlocal nodes
        if depth > MAX_DEPTH:
            raise Corrupt("too deep")
        try:
            items = _tlvs(buf)
        except Corrupt:
            if try_only:
                return
            raise
        for t in items:
            nodes += 1
            if nodes > MAX_NODES:
                raise Corrupt("too many nodes")
            if t.tag == 0x30:
                kids = _tlvs(t.body)
                if len(kids) == 2 and kids[0].tag == 0x06 and kids[1].tag == 0x30:
                    oid, prm = kids[0].body, _tlvs(kids[1].body)
                    if oid[:-1] == _PKCS12_PBE and len(prm) == 2 or oid == _PBKDF2 and len(prm) >= 2:
                        p.iterations.append(_int(prm[1]))
            if t.tag & 0x20:
                walk(t.body, depth + 1, try_only)
            elif t.tag == 0x04 and t.body[:1] == b"\x30":
                walk(t.body, depth + 1, True)  # OCTET STRING that may hold DER (the data ContentInfo)

    walk(pfx[1].body, 1, False)
    if len(pfx) >= 3 and pfx[2].tag == 0x30:
        md = _tlvs(pfx[2].body)
        if len(md) < 2 or md[0].tag != 0x30 or md[1].tag != 0x04:
            raise Corrupt("bad MacData")
        it = _int(md[2]) if len(md) >= 3 else 1
        p.iterations.append(it)
        di = _tlvs(md[0].body)
        alg = _tlvs(di[0].body) if di and di[0].tag == 0x30 else []
        ci = _tlvs(pfx[1].body)
        ok_alg = len(di) == 2 and di[1].tag == 0x04 and alg and alg[0].tag == 0x06 and alg[0].body in _HASHES
        if ok_alg and len(ci) == 2 and ci[0].body == _DATA and ci[1].tag == 0xA0:
            inner = _tlvs(ci[1].body)
            if len(inner) == 1 and inner[0].tag == 0x04:
                h, v = _HASHES[alg[0].body]
                p.mac = (h, v, md[1].body, it, di[1].body, inner[0].body)
    return p


def _kdf(h: str, v: int, password: bytes, salt: bytes, iterations: int, n: int) -> bytes:
    """RFC 7292 Appendix B.2, ID = 3 (MAC key)."""
    d = bytes([3]) * v

    def fill(x: bytes) -> bytes:
        if not x:
            return b""
        size = v * ((len(x) + v - 1) // v)
        return (x * (size // len(x) + 1))[:size]

    i_ = bytearray(fill(salt) + fill(password))
    out = b""
    while len(out) < n:
        a = d + bytes(i_)
        for _ in range(iterations):
            a = hashlib.new(h, a).digest()
        out += a
        b = int.from_bytes(fill(a)[:v], "big")
        for j in range(0, len(i_), v):
            chunk = (int.from_bytes(i_[j : j + v], "big") + b + 1) % (1 << (8 * v))
            i_[j : j + v] = chunk.to_bytes(v, "big")
    return out[:n]


def mac_matches(p: Params, password: str) -> bool | None:
    """True/False when the MAC can be checked; None when there is no MAC or an unknown digest."""
    if p.mac is None:
        return None
    h, v, salt, it, digest, content = p.mac
    if it < 1 or it > MAX_ITERATIONS:
        return None
    candidates = [password.encode("utf-16-be") + b"\0\0"]
    if not password:
        candidates.append(b"")  # some writers MAC an empty password as the empty string
    for pw in candidates:
        key = _kdf(h, v, pw, salt, it, hashlib.new(h).digest_size)
        if hmac.compare_digest(hmac.new(key, content, h).digest(), digest):
            return True
    return False
