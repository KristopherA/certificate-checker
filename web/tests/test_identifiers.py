"""Linux-side equivalent of Source/check-identifiers.sh's built-in checks for web/ and shared/:
no personal home paths and no RFC 1918 / CGNAT address outside the allowlist. Organisation
patterns stay in local files outside the tree and are applied by check-identifiers.sh on the Mac."""

from __future__ import annotations

import hashlib
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
    "openssh.com",
    "invalid.example",
    "www.apple.com",
)  # openssh.com: SSH key-type names (sk-ssh-ed25519@openssh.com), protocol identifiers as in SSHHostKeys.swift.
# www.apple.com: only in Apple's public plist DTD system identifier, which munki.py must match exactly.
# invalid.example: the RFC 2606 reserved EAP probe identity, exactly as in Radius.swift.
# Xcode.app: the DEVELOPER_DIR default in record-golden.sh. mask*.icloud.com: Apple's public Private Relay
# hosts, named in the split-DNS advice exactly as in Resolution.swift.
# Python logging calls: log.info(...) / logger.info / logging.info end in ".info", a real TLD. Exactly those
# names (optionally on self.) are skipped; any other label before or after the logger name is still a hit,
# so the exemption cannot hide a hostname (see test_logging_skip_is_exact).
LOGGING_CALL = re.compile(r"(?:self\.)?(?:log|logger|logging)\.info")


def logging_call(h: str) -> bool:
    return LOGGING_CALL.fullmatch(h.lower()) is not None


EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


# Allowed as the exact host only (no subdomains): registries that host anyone's images.
# ghcr.io: the pinned uv build image pulled by web/docker/Dockerfile (nothing is pushed there). github.com: pinned
# tool downloads in the workflows.
EXACT_HOSTS = ("ghcr.io", "github.com")


def allowed_host(h: str) -> bool:
    h = h.lower().rstrip(".")
    if h in EXACT_HOSTS:
        return True
    return any(h == a.lower() or h.endswith("." + a.lower()) for a in ALLOWED_HOSTS)


# Vendored third-party code, pinned by hash: minified htmx has JavaScript (regex test calls) that
# looks like a hostname. Only this exact file is skipped by the hostname scan; the address, home-path and
# email scans still cover it.
VENDORED = {"web/app/static/htmx.min.js": "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717"}


def _vendored(p: Path) -> bool:
    rel = p.relative_to(ROOTS[0].parent).as_posix()
    return rel in VENDORED and hashlib.sha256(p.read_bytes()).hexdigest() == VENDORED[rel]


def test_vendored_files_are_pinned() -> None:
    for rel, digest in VENDORED.items():
        assert hashlib.sha256((ROOTS[0].parent / rel).read_bytes()).hexdigest() == digest, rel


def test_hostnames_are_examples() -> None:
    hits = [
        f"{p}: {h}"
        for p in files()
        if not _vendored(p)
        for m in HOSTNAME.finditer(p.read_bytes())
        if (h := m.group(1).decode().lower()) not in ENUM_MEMBERS and not allowed_host(h) and not logging_call(h)
    ]
    assert not hits, hits


def test_enum_skip_is_exact() -> None:
    assert "topic.ca_leaf" in ENUM_MEMBERS and "severity.info" in ENUM_MEMBERS
    # Built at runtime so the scan does not see them: only real members are skipped.
    for fake in ("topic." + "example-corp" + ".ca", "severity." + "internal"):
        assert fake not in ENUM_MEMBERS
        assert HOSTNAME.fullmatch(fake.encode())


def test_logging_skip_is_exact() -> None:
    # Built at runtime so the scan does not see the fakes.
    for ok in ("log" + ".info", "logging" + ".info", "logger" + ".info", "self.log" + ".info", "LOG" + ".INFO"):
        assert HOSTNAME.fullmatch(ok.encode()) and logging_call(ok), ok
    for bad in ("corp.log" + ".info", "log.example-corp" + ".info", "logs" + ".info", "log" + ".com", "blog" + ".info"):
        assert HOSTNAME.fullmatch(bad.encode()) and not logging_call(bad), bad
    # The real call sites are found by the scan and pass only through this exemption.
    src = (ROOTS[0] / "app" / "main.py").read_bytes()
    assert any(logging_call(m.group(1).decode()) for m in HOSTNAME.finditer(src))


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


def test_exact_hosts_do_not_cover_subdomains() -> None:
    # Built at runtime so the scan does not see the fakes.
    for host in ("ghcr" + ".io", "github" + ".com"):
        assert allowed_host(host), host
        for bad in ("evil." + host, "x.y." + host, host + ".evil.com", "not" + host):
            assert not allowed_host(bad), bad
    for bad in (
        "token.actions.githubusercontent" + ".com",
        "gist.github" + ".com",
        "raw.githubusercontent" + ".com",
        "actions.githubusercontent" + ".com",
    ):
        assert not allowed_host(bad), bad
    assert allowed_host("noreply.github" + ".com")  # the commit email domain stays allowed by its own entry
