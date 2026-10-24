"""DKIM record checks (DKIM.swift). Offline: compares a DKIM TXT record (pasted or a zone excerpt) with the signing
private key. No DNS query is made; the key is read into memory only, and only its public half is kept."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ..filecheck import MAX_FILE_SIZE, pem_blocks
from ..model import Finding, Severity, Topic
from ..x509info import KeyInfo, key_info, private_key_facts

MAX_RECORD = 8_192
MAX_RECORD_FILE = 65_536


@dataclass
class DKIMRecord:
    tags: dict[str, str] = field(default_factory=dict)
    public_key: KeyInfo | None = None

    @property
    def key_type(self) -> str:
        return self.tags.get("k", "rsa").lower()

    @property
    def revoked(self) -> bool:
        return self.tags.get("p", "") == ""


@dataclass
class ZoneRecord:
    owner: str | None
    value: str

    @property
    def selector(self) -> str | None:
        if self.owner is None:
            return None
        i = self.owner.lower().find("._domainkey")
        return self.owner[:i].lower() if i >= 0 else None


def _nows(s: str) -> str:
    return "".join(c for c in s if not c.isspace())


def parse(text: str) -> DKIMRecord:
    """Exactly one record: "v=DKIM1; k=rsa; p=MIIB…" or its quoted form. Use record_in() for zone excerpts."""
    r = zone_records(text)
    if len(r) != 1:
        raise ValueError(f"Expected one record, found {len(r)}. Use record(in:selector:) for zone excerpts.")
    return parse_value(r[0].value)


def parse_value(text: str) -> DKIMRecord:
    s = _nows(text)
    if len(s) > MAX_RECORD:
        raise ValueError("DKIM record is longer than 8 KB.")
    r = DKIMRecord()
    for part in s.split(";"):
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"DKIM tag without '=': {part[:20]}")
        k, v = part.split("=", 1)
        k = k.lower()
        if k in r.tags:
            raise ValueError(f"DKIM tag {k}= appears more than once.")
        r.tags[k] = v
    if "p" not in r.tags:
        raise ValueError("DKIM record has no p= (public key) tag.")
    if not r.revoked:
        try:
            raw = base64.b64decode(r.tags["p"], validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("DKIM p= is not valid base64.") from None
        if r.key_type == "rsa":
            try:
                r.public_key = key_info(serialization.load_der_public_key(raw))
            except (ValueError, TypeError):
                raise ValueError("DKIM p= is not a SubjectPublicKeyInfo key.") from None
        elif r.key_type == "ed25519":
            if len(raw) != 32:
                raise ValueError(f"DKIM ed25519 p= must be 32 bytes, found {len(raw)}.")
            r.public_key = key_info(ed25519.Ed25519PublicKey.from_public_bytes(raw))
    return r


def inspect(r: DKIMRecord, private_key: KeyInfo | None = None) -> list[Finding]:
    def f(fid: str, s: Severity, t: Topic, title: str, d: str = "") -> Finding:
        return Finding(fid, s, t, title, d, kind="dkim")

    out: list[Finding] = []
    v = r.tags.get("v")
    if v is not None and v != "DKIM1":
        out.append(
            f("dkim-version", Severity.FAIL, Topic.GENERAL, f"v={v} is not DKIM1", "Verifiers ignore the record.")
        )
    if r.revoked:
        out.append(
            f(
                "dkim-revoked",
                Severity.WARNING,
                Topic.GENERAL,
                "Key is revoked (empty p=)",
                "Mail signed with this selector will fail DKIM.",
            )
        )
        return out
    if r.key_type not in ("rsa", "ed25519"):
        out.append(f("dkim-type", Severity.FAIL, Topic.GENERAL, f"Unknown key type k={r.key_type}"))
        return out
    if r.public_key is not None and r.public_key.algorithm[0] == "rsa":
        bits = int(r.public_key.algorithm[1])
        if bits < 1024:
            out.append(
                f(
                    "dkim-key",
                    Severity.FAIL,
                    Topic.WEAK_KEY,
                    f"RSA key is {bits} bits",
                    "RFC 8301: verifiers must not accept keys under 1024 bits. Use 2048.",
                )
            )
        elif bits < 2048:
            out.append(
                f(
                    "dkim-key",
                    Severity.WARNING,
                    Topic.WEAK_KEY,
                    f"RSA key is {bits} bits",
                    "1024-bit DKIM keys are considered weak; rotate to 2048.",
                )
            )
        else:
            out.append(f("dkim-key", Severity.PASS, Topic.WEAK_KEY, f"RSA key is {bits} bits"))
    elif r.key_type == "ed25519":
        out.append(
            f(
                "dkim-key",
                Severity.PASS,
                Topic.WEAK_KEY,
                "Ed25519 key",
                "Many receivers do not verify Ed25519 yet; dual-sign with an RSA selector.",
            )
        )
    if "h" in r.tags:
        h = [x for x in r.tags["h"].lower().split(":") if x]
        if "sha1" in h:
            sev = Severity.WARNING if "sha256" in h else Severity.FAIL
            out.append(
                f(
                    "dkim-hash",
                    sev,
                    Topic.WEAK_SIGNATURE,
                    "h= allows sha1",
                    "RFC 8301: sha1 must not be used. Set h=sha256 or remove h=.",
                )
            )
    if "t" in r.tags and "y" in r.tags["t"].lower().split(":"):
        out.append(
            f(
                "dkim-testing",
                Severity.WARNING,
                Topic.GENERAL,
                "Testing mode (t=y)",
                "Receivers may treat failures as if the mail were unsigned.",
            )
        )
    if private_key is not None:
        pub = r.public_key
        if pub is not None and pub.algorithm == private_key.algorithm and pub.material == private_key.material:
            out.append(f("dkim-match", Severity.PASS, Topic.KEY_MISMATCH, "Private key matches the DNS record"))
        else:
            out.append(
                f(
                    "dkim-match",
                    Severity.FAIL,
                    Topic.KEY_MISMATCH,
                    "Private key does not match the DNS record",
                    "Mail signed with this key will fail DKIM until the record or the signing key is updated.",
                )
            )
    else:
        out.append(
            f(
                "dkim-match",
                Severity.INFO,
                Topic.KEY_MISMATCH,
                "No private key supplied",
                "Supply the signing key to confirm it matches the record.",
            )
        )
    return out


def private_key_public_half(data: bytes) -> KeyInfo:
    """Public half of the first PEM private key in `data` (at most 2 MB). The private bytes are not kept."""
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("Key file is larger than 2 MB.")
    for label, block in pem_blocks(data):
        if label.endswith("PRIVATE KEY"):
            return private_key_facts(label, block)[0]
    raise ValueError("The file holds no PEM private key.")


def record_in(text: str, selector: str | None = None) -> DKIMRecord:
    """A bare record, or zone-file lines; several DKIM records need `selector`."""
    t = text
    if '"' not in t:
        i = t.find("v=DKIM1")
        if i < 0:
            i = t.find("p=")
        if i >= 0:
            t = t[i:]
    every = zone_records(t)
    dkim = [z for z in every if is_dkim(z.value)]
    if selector is not None:
        sel = selector.lower()
        dkim = [z for z in dkim if z.selector == sel]
        if not dkim:
            raise ValueError(f"No DKIM record for selector {sel}. Found: {_selectors(every)}.")
    if not dkim:
        raise ValueError("No DKIM record (v=DKIM1 or p=) found.")
    if len(dkim) != 1:
        raise ValueError(f"Found {len(dkim)} DKIM records (selectors: {_selectors(dkim)}). Pass --selector NAME.")
    return parse_value(dkim[0].value)


def record_file(data: bytes, selector: str | None = None) -> DKIMRecord:
    if len(data) > MAX_RECORD_FILE:
        raise ValueError("Record file is larger than 64 KB.")
    return record_in(data.decode("utf-8", "replace"), selector)


def _selectors(r: list[ZoneRecord]) -> str:
    s = [z.selector for z in r if z.selector is not None]
    return ", ".join(s) if s else "none named"


def zone_records(text: str) -> list[ZoneRecord]:
    """Split text into TXT records (DKIM.zoneRecords). Without any quote the whole text is one bare record.

    Raises on an unterminated quote or a \\DDD escape above 255. Strings of a following non-TXT record are not
    appended; a blank line or $TTL/$ORIGIN ends the record; inside ( … ) bare words are character-strings too."""
    if '"' not in text:
        return [ZoneRecord(None, text)]
    out: list[ZoneRecord] = []
    depth = 0
    current: ZoneRecord | None = None
    ignoring = False

    def close() -> None:
        nonlocal current
        if current is not None:
            out.append(current)
        current = None

    for ln, raw in enumerate(text.split("\n")):
        pieces: list[tuple[str, bool]] = []
        in_q = False
        buf = word = ""
        i = 0
        depth_at_start = depth
        n = len(raw)
        while i < n:
            c = raw[i]
            if in_q:
                if c == "\\" and i + 1 < n:
                    d = raw[i + 1 : i + 4]
                    if i + 3 < n and len(d) == 3 and all(x.isascii() and x.isdigit() for x in d):
                        v = int(d)
                        if v >= 256:
                            raise ValueError(f"Line {ln + 1}: escape \\{v} is above 255.")
                        buf += chr(v)
                        i += 4
                        continue
                    buf += raw[i + 1]
                    i += 2
                    continue
                if c == '"':
                    in_q = False
                    pieces.append((buf, True))
                    buf = ""
                else:
                    buf += c
            else:
                if c == ";":
                    break
                if c in '"()' or c.isspace():
                    if word:
                        pieces.append((word, False))
                        word = ""
                    if c == '"':
                        in_q = True
                    elif c == "(":
                        depth += 1
                    elif c == ")":
                        depth = max(0, depth - 1)
                else:
                    word += c
            i += 1
        if in_q:
            raise ValueError(f"Line {ln + 1}: unterminated quoted string.")
        if word:
            pieces.append((word, False))
        words = [p for p, q in pieces if not q]
        if depth_at_start == 0 and not pieces:
            if raw.strip(" \t") == "":
                close()
                ignoring = False
            continue
        if depth_at_start == 0 and words and words[0].startswith("$"):
            close()
            ignoring = False
            continue
        ti = next((k for k, (p, q) in enumerate(pieces) if not q and p.upper() == "TXT"), None)
        if ti is not None:
            close()
            has_owner = bool(raw) and not raw[0].isspace() and bool(words) and words[0].upper() not in ("TXT", "IN")
            current = ZoneRecord(words[0] if has_owner else None, "".join(p for p, _ in pieces[ti + 1 :]))
            ignoring = False
        elif depth_at_start > 0:
            if not ignoring and current is not None:
                current.value += "".join(p for p, _ in pieces)
        elif words:
            close()
            ignoring = True
        elif not ignoring:
            if current is None:
                current = ZoneRecord(None, "")
            current.value += "".join(p for p, _ in pieces)
    close()
    return out


def is_dkim(value: str) -> bool:
    """v=DKIM1 first, or no v= and a p= (RFC 6376 3.6.1). DMARC, SPF and others do not count."""
    v = _nows(value)
    keys = [p.split("=", 1)[0].lower() for p in v.split(";") if p]
    return v.startswith("v=DKIM1") or ("v" not in keys and "p" in keys)
