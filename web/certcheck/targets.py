"""Saved targets from the mounted config (/config/targets.yaml), read-only.

Format (schema 1; unknown keys are refused, so a typo never silently drops an option):

    schema: 1
    targets:
      - name: Intranet web            # unique, shown in the UI
        host: www.example.test
        port: 443                     # optional, defaults to the profile's port
        profile: HTTPS                # a Service value (GET /api/v1/profiles); default HTTPS
        sni: www.example.test         # optional
        verify_name: www.example.test # optional
        connect_ip: 192.0.2.10        # optional resolve override (like curl --resolve)
        family: any                   # any | ipv4 | ipv6
        platform: Linux nginx         # optional, picks the fix guidance (GET /api/v1/profiles)
        fingerprint_pin: null         # Proxmox VE / PBS only
        legacy: false                 # the M4 options, all off by default
        aia: false
        revocation: false
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .check import Options
from .guidance import Platform
from .probe import Target
from .services import Service

MAX_TARGETS_BYTES = 1024 * 1024
MAX_TARGETS = 1000
_TARGET_KEYS = {"name", "host", "port", "profile", "sni", "verify_name", "connect_ip", "family", "platform",
                "fingerprint_pin"}  # fmt: skip
_OPTION_KEYS = {"legacy", "aia", "revocation"}


@dataclass(frozen=True)
class SavedTarget:
    name: str
    target: Target
    options: Options
    platform: Platform


def config_dir() -> Path:
    return Path(os.environ.get("CERTCHECK_CONFIG", "/config"))


def _opt_str(e: dict[str, Any], k: str, n: int = 253) -> str | None:
    v = e.get(k)
    if v is None:
        return None
    if not isinstance(v, str) or not v or len(v) > n:
        raise ValueError(f"{k} must be a non-empty string of at most {n} characters")
    return v


def parse_entry(e: object) -> SavedTarget:
    if not isinstance(e, dict):
        raise ValueError("each target must be a mapping")
    unknown = set(e) - _TARGET_KEYS - _OPTION_KEYS
    if unknown:
        raise ValueError(f"unknown key(s): {', '.join(sorted(map(str, unknown)))}")
    name = _opt_str(e, "name", 100)
    host = _opt_str(e, "host")
    if not name or not host:
        raise ValueError("name and host are required")
    try:
        service = Service(e.get("profile", Service.HTTPS.value))
    except ValueError:
        raise ValueError(f"unknown profile {e.get('profile')!r}") from None
    port = e.get("port", service.default_port)
    if not isinstance(port, int) or isinstance(port, bool):
        raise ValueError("port must be a number")
    try:
        platform = Platform(e.get("platform", Platform.GENERIC.value))
    except ValueError:
        raise ValueError(f"unknown platform {e.get('platform')!r}") from None
    family = e.get("family", "any")
    if not isinstance(family, str):
        raise ValueError("family must be any, ipv4 or ipv6")
    t = Target(
        host=host,
        port=port,
        sni=_opt_str(e, "sni"),
        verify_name=_opt_str(e, "verify_name"),
        connect_ip=_opt_str(e, "connect_ip", 64),
        family=family,
        service=service,
        fingerprint_pin=_opt_str(e, "fingerprint_pin", 200),
    )
    t.validate()
    return SavedTarget(name, t, Options.from_mapping({k: e[k] for k in _OPTION_KEYS if k in e}), platform)


def load(path: Path | None = None) -> list[SavedTarget]:
    """The saved targets; [] when the file is absent. Any invalid entry fails the whole file (ValueError)."""
    p = path or config_dir() / "targets.yaml"
    if not p.is_file():
        return []
    with p.open("rb") as fh:
        raw = fh.read(MAX_TARGETS_BYTES + 1)
    if len(raw) > MAX_TARGETS_BYTES:
        raise ValueError("targets.yaml is larger than 1 MB")
    doc = yaml.safe_load(raw) or {}
    if not isinstance(doc, dict) or doc.get("schema", 1) != 1 or set(doc) - {"schema", "targets"}:
        raise ValueError("targets.yaml: expected schema: 1 and a targets: list")
    entries = doc.get("targets") or []
    if not isinstance(entries, list) or len(entries) > MAX_TARGETS:
        raise ValueError(f"targets.yaml: targets must be a list of at most {MAX_TARGETS}")
    out: list[SavedTarget] = []
    seen: set[str] = set()
    for i, e in enumerate(entries, 1):
        try:
            st = parse_entry(e)
        except ValueError as err:
            raise ValueError(f"targets.yaml entry {i}: {err}") from None
        if st.name in seen:
            raise ValueError(f"targets.yaml entry {i}: duplicate name {st.name!r}")
        seen.add(st.name)
        out.append(st)
    return out
