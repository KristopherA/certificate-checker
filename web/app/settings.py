"""App settings from the environment (the /config/settings.yaml loader arrives with M6's rate limits)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

MAX_UPLOAD_BYTES = 1024 * 1024  # the spec's 1 MB: the whole request body, all files and fields together


def _int(e: Mapping[str, str], k: str, default: int, lo: int, hi: int) -> int:
    raw = e.get(k, "").strip()
    if not raw:
        return default
    if not (raw.isascii() and raw.isdigit() and lo <= int(raw) <= hi):
        raise ValueError(f"{k}={raw!r} must be a whole number from {lo} to {hi}")
    return int(raw)


@dataclass(frozen=True)
class Settings:
    config_dir: Path = Path("/config")
    max_upload_bytes: int = MAX_UPLOAD_BYTES
    max_concurrent: int = 4  # live checks and file checks running at once; more get 429
    probe_timeout_s: float = 10.0
    anchors: Path | None = None  # a PEM bundle that replaces the system store (tests, internal-only setups)
    allowed_hosts: tuple[str, ...] = ()  # Host header values accepted; empty means any (M6 adds login)
    secure_cookies: bool = False  # set when the UI is served over TLS (M6), or behind a TLS proxy

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        anchors = e.get("CERTCHECK_ANCHORS", "").strip()
        hosts = tuple(h.strip().lower() for h in e.get("CERTCHECK_ALLOWED_HOSTS", "").split(",") if h.strip())
        return cls(
            config_dir=Path(e.get("CERTCHECK_CONFIG", "/config")),
            max_upload_bytes=_int(e, "CERTCHECK_MAX_UPLOAD_BYTES", MAX_UPLOAD_BYTES, 1024, MAX_UPLOAD_BYTES),
            max_concurrent=_int(e, "CERTCHECK_MAX_CONCURRENT", 4, 1, 64),
            probe_timeout_s=float(_int(e, "CERTCHECK_PROBE_TIMEOUT", 10, 1, 60)),
            anchors=Path(anchors) if anchors else None,
            allowed_hosts=hosts,
            secure_cookies=e.get("CERTCHECK_SECURE_COOKIES", "").strip().lower() in ("1", "true", "yes"),
        )
