"""Linux-side equivalent of Source/check-identifiers.sh's built-in checks for web/ and shared/:
no personal home paths and no RFC 1918 / CGNAT address outside the allowlist. Organisation
patterns stay in local files outside the tree and are applied by check-identifiers.sh on the Mac."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from certcheck.model import Purpose, Severity, Topic

ROOTS = [Path(__file__).resolve().parents[1], Path(__file__).resolve().parents[2] / "shared"]
SKIP_DIRS = {".venv", ".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
ALLOW_PREFIX = ("10.0.0.", "192.0.2.", "198.51.100.", "203.0.113.")
IPV4 = re.compile(rb"(?<![0-9.])((?:[0-9]{1,3}\.){3}[0-9]{1,3})")
HOME = re.compile(rb"/(?:Users|home)/[A-Za-z0-9._-]+")
# RFC 1918 + CGNAT, built from integers so this file does not itself trip the address scan.
PRIVATE = [
    ipaddress.IPv4Network((base, bits))
    for base, bits in ((0x0A000000, 8), (0xAC100000, 12), (0xC0A80000, 16), (0x64400000, 10))
]


def files() -> list[Path]:
    out = []
    for root in ROOTS:
        for p in root.rglob("*"):
            if p.is_file() and not SKIP_DIRS.intersection(p.parts):
                out.append(p)
    return out


def test_no_private_addresses_outside_allowlist() -> None:
    hits = []
    for p in files():
        for m in IPV4.finditer(p.read_bytes()):
            s = m.group(1).decode()
            try:
                ip = ipaddress.ip_address(s)
            except ValueError:
                continue
            if any(ip in n for n in PRIVATE) and not s.startswith(ALLOW_PREFIX):
                hits.append(f"{p}: {s}")
    assert not hits, hits


def test_no_home_paths() -> None:
    hits = [
        f"{p}: {m.group(0)!r}"
        for p in files()
        for m in HOME.finditer(p.read_bytes())
        if not m.group(0).startswith(b"/Users/Shared")
    ]
    assert not hits, hits


# Hostnames: any dotted name ending in a real-world TLD must be an example.* name or a known
# packaging/infra host (uv.lock points at PyPI). Organisation names stay in the Mac-side pattern files.
# Python enum members (Severity.INFO, Topic.CA_LEAF, Purpose.ANY) look like hostnames; exactly the real
# members are skipped (compared case-insensitively), nothing else that merely starts with "Topic.".
ENUM_MEMBERS = frozenset(f"{e.__name__}.{m.name}".lower() for e in (Severity, Topic, Purpose) for m in e)
TLDS = "com|net|org|ca|edu|gov|io|dev|app|info|biz|us|uk|cloud|ai|co|me|local|lan|internal|corp|test"
HOSTNAME = re.compile(rb"(?<![A-Za-z0-9._-])((?:[A-Za-z0-9-]+\.)+(?:" + TLDS.encode() + rb"))(?![A-Za-z0-9_-])", re.I)
ALLOWED_HOSTS = (
    "example.com",
    "example.org",
    "example.net",
    "example.test",
    "pypi.org",
    "pythonhosted.org",
    "noreply.github.com",
    "Xcode.app",
    "mask.icloud.com",
    "mask-h2.icloud.com",
)  # Xcode.app: the DEVELOPER_DIR default in record-golden.sh. mask*.icloud.com: Apple's public Private Relay
# hosts, named in the split-DNS advice exactly as in Resolution.swift.
EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def allowed_host(h: str) -> bool:
    h = h.lower().rstrip(".")
    return any(h == a.lower() or h.endswith("." + a.lower()) for a in ALLOWED_HOSTS)


def test_hostnames_are_examples() -> None:
    hits = [
        f"{p}: {h}"
        for p in files()
        for m in HOSTNAME.finditer(p.read_bytes())
        if (h := m.group(1).decode().lower()) not in ENUM_MEMBERS and not allowed_host(h)
    ]
    assert not hits, hits


def test_enum_skip_is_exact() -> None:
    assert "topic.ca_leaf" in ENUM_MEMBERS and "severity.info" in ENUM_MEMBERS
    # Built at runtime so the scan does not see them: only real members are skipped.
    for fake in ("topic." + "example-corp" + ".ca", "severity." + "internal"):
        assert fake not in ENUM_MEMBERS
        assert HOSTNAME.fullmatch(fake.encode())


def test_emails_are_examples() -> None:
    hits = []
    for p in files():
        for m in EMAIL.finditer(p.read_bytes()):
            addr = m.group(0).decode()
            if not (
                allowed_host(m.group(1).decode())
                or addr.lower().startswith("noreply@")
                or m.group(1).decode().lower().endswith("noreply.github.com")
            ):
                hits.append(f"{p}: {addr}")
    assert not hits, hits
