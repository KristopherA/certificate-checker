"""App settings: built-in defaults, then /config/settings.yaml, then environment variables (each overrides the last).

settings.yaml (all keys optional; unknown keys are refused so a typo never silently loosens a limit):

    schema: 1
    limits:   {max_concurrent: 4, checks_per_minute: 30, max_upload_kb: 1024}
    timeouts: {probe_s: 10, session_idle_min: 30, session_max_hours: 12}
    login:    {max_failures: 5, window_min: 15, lockout_min: 15}
    network:  {allowed_hosts: [certcheck.example.test], lan_only: true}
    denylist: [192.0.2.0/24]          # optional, off (empty) by default

The password hash never comes from settings.yaml: only CERTCHECK_PASSWORD_HASH or a file named by
CERTCHECK_PASSWORD_HASH_FILE (a Docker secret; /run/secrets/certcheck_password_hash is read by default).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

MAX_UPLOAD_BYTES = 1024 * 1024  # the spec's 1 MB: the whole request body, all files and fields together
log = logging.getLogger("certcheck.settings")
DEFAULT_SECRET = Path("/run/secrets/certcheck_password_hash")
TRUE = ("1", "true", "yes", "on")
FALSE = ("0", "false", "no", "off")

# settings.yaml: section -> key -> (Settings field, lo, hi, scale to the field's unit)
_NUMBERS: dict[str, dict[str, tuple[str, int, int, int]]] = {
    "limits": {
        "max_concurrent": ("max_concurrent", 1, 64, 1),
        "checks_per_minute": ("checks_per_minute", 1, 600, 1),
        "max_upload_kb": ("max_upload_bytes", 1, MAX_UPLOAD_BYTES // 1024, 1024),
    },
    "timeouts": {
        "probe_s": ("probe_timeout_s", 1, 60, 1),
        "session_idle_min": ("session_idle_s", 1, 24 * 60, 60),
        "session_max_hours": ("session_max_s", 1, 7 * 24, 3600),
    },
    "login": {
        "max_failures": ("lockout_failures", 1, 100, 1),
        "window_min": ("lockout_window_s", 1, 24 * 60, 60),
        "lockout_min": ("lockout_s", 1, 24 * 60, 60),
    },
}


@dataclass(frozen=True)
class Settings:
    config_dir: Path = Path("/config")
    max_upload_bytes: int = MAX_UPLOAD_BYTES
    max_concurrent: int = 4  # live checks and file checks running at once; more get 429
    checks_per_minute: int = 30  # per client address, live and file checks together; more get 429
    probe_timeout_s: float = 10.0
    anchors: Path | None = None  # CERTCHECK_ANCHORS: a PEM bundle that REPLACES the system store (tests)
    allowed_hosts: tuple[str, ...] = ()  # Host header values accepted; empty means any
    secure_cookies: bool = False  # Secure flag on cookies: on whenever the UI is served over TLS
    lan_only: bool = True  # refuse clients whose address is not on the LAN (security.lan_client)
    login_required: bool = True  # False only with CERTCHECK_NO_LOGIN=1, which python -m app allows on loopback only
    password_hash: str | None = field(default=None, repr=False)
    session_idle_s: int = 30 * 60
    session_max_s: int = 12 * 3600
    lockout_failures: int = 5  # failed logins from one address inside the window before it is locked out
    lockout_window_s: int = 15 * 60
    lockout_s: int = 15 * 60
    denylist: tuple[str, ...] = ()  # extra CIDRs probes may not reach (settings.yaml), on top of TargetPolicy

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        s = cls(config_dir=Path(e.get("CERTCHECK_CONFIG", "/config")))
        s = s.with_yaml(s.config_dir / "settings.yaml")
        anchors = e.get("CERTCHECK_ANCHORS", "").strip()
        over: dict[str, Any] = {
            "anchors": Path(anchors) if anchors else None,
            "secure_cookies": tls_enabled(e) or _flag(e, "CERTCHECK_SECURE_COOKIES", False),
            "login_required": not _flag(e, "CERTCHECK_NO_LOGIN", False),
            "password_hash": password_hash(e),
        }
        for k, f, lo, hi in (("CERTCHECK_MAX_UPLOAD_BYTES", "max_upload_bytes", 1024, MAX_UPLOAD_BYTES),
                             ("CERTCHECK_MAX_CONCURRENT", "max_concurrent", 1, 64),
                             ("CERTCHECK_CHECKS_PER_MINUTE", "checks_per_minute", 1, 600),
                             ("CERTCHECK_PROBE_TIMEOUT", "probe_timeout_s", 1, 60)):  # fmt: skip
            v = _int(e, k, lo, hi)
            if v is not None:
                over[f] = float(v) if f == "probe_timeout_s" else v
        hosts = e.get("CERTCHECK_ALLOWED_HOSTS", "").strip()
        if hosts:
            over["allowed_hosts"] = tuple(h.strip().lower() for h in hosts.split(",") if h.strip())
        if e.get("CERTCHECK_LAN_ONLY", "").strip():
            over["lan_only"] = _flag(e, "CERTCHECK_LAN_ONLY", True)
        return replace(s, **over)

    def with_yaml(self, path: Path) -> Settings:
        """Apply settings.yaml when it exists. Any error raises ValueError: the app does not start on a file
        it could not read exactly (fail closed)."""
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return self
        except (OSError, UnicodeDecodeError) as x:
            raise ValueError(f"{path}: cannot read ({type(x).__name__})") from None
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as x:
            raise ValueError(f"{path}: not valid YAML ({str(x).splitlines()[0]})") from None
        if doc is None:
            return self
        if not isinstance(doc, dict):
            raise ValueError(f"{path}: the top level must be a mapping")
        if doc.get("schema", 1) != 1:
            raise ValueError(f"{path}: unsupported schema {doc.get('schema')!r} (expected 1)")
        unknown = set(doc) - {"schema", *_NUMBERS, "network", "denylist"}
        if unknown:
            raise ValueError(f"{path}: unknown key(s) {', '.join(sorted(map(str, unknown)))}")
        over: dict[str, Any] = {}
        for section, keys in _NUMBERS.items():
            sec = _section(path, doc, section)
            if bad := set(sec) - set(keys):
                raise ValueError(f"{path}: unknown key(s) in {section}: {', '.join(sorted(map(str, bad)))}")
            for k, (f, lo, hi, scale) in keys.items():
                if k in sec:
                    v = sec[k]
                    if type(v) is not int or not lo <= v <= hi:
                        raise ValueError(f"{path}: {section}.{k} must be a whole number from {lo} to {hi}")
                    over[f] = float(v) if f == "probe_timeout_s" else v * scale
        net = _section(path, doc, "network")
        if bad := set(net) - {"allowed_hosts", "lan_only"}:
            raise ValueError(f"{path}: unknown key(s) in network: {', '.join(sorted(map(str, bad)))}")
        if "lan_only" in net:
            if type(net["lan_only"]) is not bool:
                raise ValueError(f"{path}: network.lan_only must be true or false")
            over["lan_only"] = net["lan_only"]
        if "allowed_hosts" in net:
            over["allowed_hosts"] = tuple(
                h.lower() for h in _strings(path, net["allowed_hosts"], "network.allowed_hosts")
            )
        deny = _strings(path, doc.get("denylist") or [], "denylist")
        for c in deny:
            try:
                ipaddress.ip_network(c, strict=False)
            except ValueError:
                raise ValueError(f"{path}: denylist entry {c!r} is not an address or CIDR") from None
        over["denylist"] = deny
        return replace(self, **over)


def _section(path: Path, doc: dict[Any, Any], name: str) -> dict[Any, Any]:
    sec = doc.get(name) or {}
    if not isinstance(sec, dict):
        raise ValueError(f"{path}: {name} must be a mapping")
    return sec


def _strings(path: Path, v: Any, what: str) -> tuple[str, ...]:
    if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() and len(x) <= 253 for x in v):
        raise ValueError(f"{path}: {what} must be a list of strings")
    return tuple(x.strip() for x in v)


def _flag(e: Mapping[str, str], k: str, default: bool) -> bool:
    raw = e.get(k, "").strip().lower()
    if not raw:
        return default
    if raw in TRUE:
        return True
    if raw in FALSE:
        return False
    raise ValueError(f"{k}={raw!r} must be 1/true/yes/on or 0/false/no/off")


def _int(e: Mapping[str, str], k: str, lo: int, hi: int) -> int | None:
    raw = e.get(k, "").strip()
    if not raw:
        return None
    if not (raw.isascii() and raw.isdigit() and lo <= int(raw) <= hi):
        raise ValueError(f"{k}={raw!r} must be a whole number from {lo} to {hi}")
    return int(raw)


def tls_enabled(e: Mapping[str, str]) -> bool:
    """CERTCHECK_TLS: on by default; off is for a loopback bind behind a TLS proxy (python -m app enforces that)."""
    return _flag(e, "CERTCHECK_TLS", True)


def password_hash(e: Mapping[str, str]) -> str | None:
    """The argon2id hash from CERTCHECK_PASSWORD_HASH, else the file CERTCHECK_PASSWORD_HASH_FILE names, else the
    default Docker secret path when it exists. Anything but an argon2id hash is refused (never a plain password)."""
    raw = e.get("CERTCHECK_PASSWORD_HASH", "").strip()
    src = "CERTCHECK_PASSWORD_HASH"
    if not raw:
        f = e.get("CERTCHECK_PASSWORD_HASH_FILE", "").strip()
        p = Path(f) if f else DEFAULT_SECRET
        if not f and not p.exists():
            return None
        try:
            raw = p.read_text(encoding="ascii").strip()
            mode = p.stat().st_mode
        except (OSError, UnicodeDecodeError) as x:
            raise ValueError(f"password hash file {p}: cannot read ({type(x).__name__})") from None
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            # A warning, not a refusal: a compose secret is a bind mount that keeps the host file's mode, and the
            # non-root container user can often read it only through group/other bits. The hash is not the
            # password, but anyone who can read it can run an offline guessing attack, so say so.
            log.warning("password hash file %s is readable by group or other (mode %04o); chmod 600 or chown it "
                        "to the container user", p, stat.S_IMODE(mode))  # fmt: skip
        src = str(p)
    if not raw:
        return None
    if not raw.startswith("$argon2id$") or len(raw) > 512 or any(c.isspace() for c in raw):
        raise ValueError(f"{src} must hold an argon2id hash (make one with: python -m app hash-password)")
    return raw
