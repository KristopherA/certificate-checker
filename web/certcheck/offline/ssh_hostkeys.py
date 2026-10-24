"""SSH host keys vs known_hosts (SSHHostKeys.swift). Offline: reads host public keys (.pub files or saved
ssh-keyscan output) and a known_hosts file; no connection is made. Hashed entries (|1|salt|hash) are matched with
HMAC-SHA1 of the host token, as OpenSSH does."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass

from ..model import Finding, Severity, Topic, unique_by

KEY_TYPES = frozenset(
    {
        "ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed448", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
    }
)  # fmt: skip
_FIELDS = re.compile(r"[ \t]+")


def _b64(s: str) -> bytes | None:
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


@dataclass(frozen=True)
class SSHKey:
    type: str
    blob: bytes

    @property
    def fingerprint(self) -> str:
        return "SHA256:" + base64.b64encode(hashlib.sha256(self.blob).digest()).decode().replace("=", "")

    @property
    def rsa_bits(self) -> int | None:
        """Modulus bits from the wire format (string type, mpint e, mpint n); None for other types."""
        if self.type != "ssh-rsa":
            return None
        b, i, fields = self.blob, 0, []
        for _ in range(3):
            if i + 4 > len(b):
                return None
            n = int.from_bytes(b[i : i + 4], "big")
            i += 4
            if i + n > len(b):
                return None
            fields.append(b[i : i + n])
            i += n
        m = fields[2].lstrip(b"\x00")
        return 0 if not m else (len(m) - 1) * 8 + m[0].bit_length()


@dataclass(frozen=True)
class KnownHostsEntry:
    patterns: tuple[str, ...]
    key: SSHKey
    marker: str | None  # @revoked / @cert-authority


def key(type_: str, b64: str) -> SSHKey | None:
    if type_ not in KEY_TYPES or (blob := _b64(b64)) is None or len(blob) < 4:
        return None
    n = int.from_bytes(blob[:4], "big")
    if n <= 0 or 4 + n > len(blob) or blob[4 : 4 + n].decode("utf-8", "replace") != type_:
        return None
    return SSHKey(type_, blob)


def _lines(text: str) -> list[list[str]]:
    return [[x for x in _FIELDS.split(ln) if x] for ln in text.splitlines() if ln]


def parse_host_keys(text: str) -> list[SSHKey]:
    """Host keys from .pub lines ("type base64 comment") or keyscan lines ("host type base64"), de-duplicated."""
    out: list[SSHKey] = []
    for f in _lines(text):
        if not f or f[0].startswith("#"):
            continue
        k = key(f[0], f[1]) if len(f) >= 2 else None
        if k is None and len(f) >= 3:
            k = key(f[1], f[2])
        if k is not None:
            out.append(k)
    return unique_by(out, lambda k: k.blob)


def parse_known_hosts(text: str) -> list[KnownHostsEntry]:
    out: list[KnownHostsEntry] = []
    for f in _lines(text):
        if not f or f[0].startswith("#"):
            continue
        marker = None
        if f[0].startswith("@"):
            marker = f.pop(0)
        if len(f) < 3 or (k := key(f[1], f[2])) is None:
            continue
        out.append(KnownHostsEntry(tuple(p for p in f[0].split(",") if p), k, marker))
    return out


def host_token(host: str, port: int) -> str:
    return host.lower() if port == 22 else f"[{host.lower()}]:{port}"


def glob(pattern: str, s: str) -> bool:
    """Iterative two-pointer '*'/'?' match: linear backtracking, no recursion."""
    i = j = 0
    star, mark = -1, 0
    while j < len(s):
        if i < len(pattern) and pattern[i] == "*":
            star, mark, i = i, j, i + 1
        elif i < len(pattern) and (pattern[i] == "?" or pattern[i] == s[j]):
            i, j = i + 1, j + 1
        elif star >= 0:
            i, mark = star + 1, mark + 1
            j = mark
        else:
            return False
    while i < len(pattern) and pattern[i] == "*":
        i += 1
    return i == len(pattern)


def matches(e: KnownHostsEntry, token: str) -> bool:
    hit = False
    for p in e.patterns:
        if p.startswith("|1|"):
            parts = [x for x in p.split("|") if x]
            if len(parts) != 3 or (salt := _b64(parts[1])) is None or (h := _b64(parts[2])) is None:
                continue
            if hmac.compare_digest(hmac.new(salt, token.encode(), hashlib.sha1).digest(), h):
                hit = True
        elif p.startswith("!"):
            if glob(p[1:].lower(), token):
                return False
        elif glob(p.lower(), token):
            hit = True
    return hit


def inspect(
    host_keys: list[SSHKey], known_hosts: list[KnownHostsEntry] | None, host: str | None, port: int = 22
) -> list[Finding]:
    def f(fid: str, s: Severity, t: Topic, title: str, d: str = "") -> Finding:
        return Finding(fid, s, t, title, d, kind="ssh")

    if not host_keys:
        return [
            f(
                "ssh-keys",
                Severity.FAIL,
                Topic.GENERAL,
                "No SSH host keys found",
                "Expected ssh_host_*_key.pub lines or ssh-keyscan output.",
            )
        ]
    out: list[Finding] = []
    for k in host_keys:
        fid = f"ssh-alg-{k.type}"
        if k.type == "ssh-dss":
            out.append(
                f(
                    fid,
                    Severity.FAIL,
                    Topic.WEAK_KEY,
                    f"DSA host key {k.fingerprint}",
                    "DSA is disabled in OpenSSH 7.0+ and removed in 9.8. Remove it from HostKey in sshd_config.",
                )
            )
        elif k.type == "ssh-rsa":
            b = k.rsa_bits or 0
            if b < 2048:
                out.append(
                    f(
                        fid,
                        Severity.FAIL,
                        Topic.WEAK_KEY,
                        f"RSA host key is {b} bits",
                        "Generate a new key of at least 3072 bits.",
                    )
                )
            elif b < 3072:
                out.append(
                    f(
                        fid,
                        Severity.INFO,
                        Topic.WEAK_KEY,
                        f"RSA host key is {b} bits",
                        "OpenSSH now generates 3072-bit host keys by default.",
                    )
                )
            else:
                out.append(f(fid, Severity.PASS, Topic.WEAK_KEY, f"RSA host key is {b} bits"))
        elif k.type == "ssh-ed25519":
            out.append(f(fid, Severity.PASS, Topic.WEAK_KEY, "Ed25519 host key"))
        else:
            out.append(f(fid, Severity.PASS, Topic.WEAK_KEY, f"{k.type} host key"))
    if not any(k.type == "ssh-ed25519" for k in host_keys):
        out.append(
            f(
                "ssh-ed25519",
                Severity.INFO,
                Topic.WEAK_KEY,
                "No Ed25519 host key",
                "Consider adding one; modern clients prefer it.",
            )
        )
    if known_hosts is None or not host:
        return out
    token = host_token(host, port)
    entries = [e for e in known_hosts if matches(e, token)]
    revoked = [e.key for e in entries if e.marker == "@revoked"]
    plain = [e.key for e in entries if e.marker is None and e.key not in revoked]
    ca_keys = [e for e in entries if e.marker == "@cert-authority"]
    for k in host_keys:
        if k in revoked:
            out.append(
                f(
                    f"ssh-revoked-{k.type}",
                    Severity.FAIL,
                    Topic.TRUST,
                    f"known_hosts marks this {k.type} key as revoked",
                    k.fingerprint,
                )
            )
    if ca_keys:
        n = len(ca_keys)
        out.append(
            f(
                "ssh-ca",
                Severity.INFO,
                Topic.TRUST,
                f"known_hosts trusts {n} SSH certificate authorit{'y' if n == 1 else 'ies'} for {token}",
                "Host certificates signed by it are accepted; plain host keys (checked here) are compared separately.",
            )
        )
    presented = [k for k in host_keys if k not in revoked]
    if not plain:
        out.append(
            f(
                "ssh-known",
                Severity.WARNING,
                Topic.TRUST,
                f"{token} is not in known_hosts",
                "Clients will be asked to trust the key on first use. Verify the fingerprint out of band before adding it.",
            )
        )
        return out
    matched = [k for k in presented if k in plain]
    different = [k for k in presented if k not in plain and any(p.type == k.type for p in plain)]
    for k in different:
        out.append(
            f(
                f"ssh-mismatch-{k.type}",
                Severity.FAIL,
                Topic.KEY_MISMATCH,
                f"{k.type} key does not match known_hosts",
                f"Host now presents {k.fingerprint}. Clients will refuse to connect. Confirm the key was rotated legitimately before running: ssh-keygen -R '{token}'",
            )
        )
    if matched and not different:
        out.append(
            f(
                "ssh-known",
                Severity.PASS,
                Topic.TRUST,
                f"known_hosts matches {len(matched)} host key{'' if len(matched) == 1 else 's'}",
            )
        )
    stale = [o for o in plain if o not in host_keys and not any(k.type == o.type for k in host_keys)]
    if stale:
        out.append(
            f(
                "ssh-stale",
                Severity.INFO,
                Topic.TRUST,
                "known_hosts has key types the host no longer offers",
                ", ".join(o.type for o in stale),
            )
        )
    return out
