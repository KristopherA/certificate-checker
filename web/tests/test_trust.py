from __future__ import annotations

import dataclasses
import datetime as dt
import os
import subprocess
from pathlib import Path

import pytest

from certcheck import filecheck, probe, trust
from certcheck.model import Purpose
from certcheck.shared import load_manifest, shared_dir

CA = shared_dir() / "fixtures" / "ca"
NOW = dt.datetime.fromisoformat(load_manifest()["pinned_now"].replace("Z", "+00:00"))


def chain(case: str) -> list:  # type: ignore[type-arg]
    return filecheck.inspect([CA / "cases" / case / "chain.pem"], None, Purpose.ANY, now=NOW).chain


@pytest.mark.parametrize("case", ["ip-only-san-cn-host", "email-only-san-cn-host"])
def test_cn_fallback_never_trusted(case: str) -> None:
    """OpenSSL alone says OK here (CN fallback when the SAN has no DNS name); the policy refuses."""
    host = next(c["hostname"] for c in load_manifest()["cases"] if c["name"] == case)
    r = trust.verify(chain(case), hostname=host, purpose=Purpose.TLS_SERVER, now=NOW, anchors=CA / "root.pem")
    assert r.openssl_ok and not r.trusted
    assert "Common Name is never used" in r.message


def test_ip_needs_ip_san() -> None:
    r = trust.verify(chain("good"), hostname="192.0.2.10", purpose=Purpose.TLS_SERVER, now=NOW, anchors=CA / "root.pem")
    assert not r.trusted


def test_825_day_limit_only_from_2019_07_01() -> None:
    leaf = chain("good")[0]
    old = dataclasses.replace(
        leaf, not_before=dt.datetime(2019, 6, 30, tzinfo=dt.UTC), not_after=dt.datetime(2022, 1, 1, tzinfo=dt.UTC)
    )
    new = dataclasses.replace(old, not_before=dt.datetime(2019, 7, 1, tzinfo=dt.UTC))
    assert trust.tls_policy(old, hostname="good.example.test", purpose=Purpose.TLS_SERVER) == []
    assert any("825" in p for p in trust.tls_policy(new, hostname="good.example.test", purpose=Purpose.TLS_SERVER))


def test_any_eku_only_is_rejected() -> None:
    r = trust.verify(
        chain("any-eku-only"),
        hostname="anyeku.example.test",
        purpose=Purpose.TLS_SERVER,
        now=NOW,
        anchors=CA / "root.pem",
    )
    assert not r.trusted


def test_naive_now_rejected() -> None:
    with pytest.raises(ValueError, match="timezone"):
        trust.verify(chain("good"), hostname=None, purpose=Purpose.ANY, now=NOW.replace(tzinfo=None))


def test_relative_anchor_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(CA)
    r = trust.verify(
        chain("good"), hostname="good.example.test", purpose=Purpose.TLS_SERVER, now=NOW, anchors=Path("root.pem")
    )
    assert r.trusted


def test_timeout_is_untrusted_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    real = subprocess.run

    def fake(argv: list[str], *a: object, **k: object) -> object:
        if "verify" in argv:
            raise subprocess.TimeoutExpired(argv, 10)
        return real(argv, *a, **k)  # type: ignore[call-overload]

    monkeypatch.setattr(subprocess, "run", fake)
    r = filecheck.inspect([CA / "cases" / "good" / "chain.pem"], "good.example.test", Purpose.TLS_SERVER, now=NOW)
    assert r.trust is not None and not r.trust.trusted and "timed out" in r.trust.message
    assert any(f.id == "trust" for f in r.findings)


def test_missing_openssl_is_untrusted_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CERTCHECK_OPENSSL", "/nonexistent/openssl")
    r = filecheck.inspect([CA / "cases" / "good" / "chain.pem"], "good.example.test", Purpose.TLS_SERVER, now=NOW)
    assert r.trust is not None and not r.trust.trusted and "not found" in r.trust.message
    pr = probe.run(probe.Target("good.example.test", 9, connect_ip="192.0.2.1"), timeout=0.01)
    assert pr.findings  # unreachable TEST-NET address: fails cleanly, nothing escapes


@pytest.mark.parametrize(
    ("text", "ok"),
    [
        ("OpenSSL 3.5.7 1 Jul 2026", True),
        ("OpenSSL 4.0.2 7 Oct 2026", True),
        ("OpenSSL 1.1.1w", False),
        ("LibreSSL 3.3.6", False),
    ],
)
def test_version_parse(text: str, ok: bool) -> None:
    m = trust.VERSION.match(text)
    assert bool(m and int(m.group(1)) >= 3) is ok


def test_engine_in_detail() -> None:
    exe, version = trust.openssl_binary()
    r = trust.verify(chain("good"), hostname=None, purpose=Purpose.ANY, now=NOW, anchors=CA / "root.pem")
    assert r.engine == f"OpenSSL {version}"
    detail = trust.finding(r, "offline").detail or ""
    assert r.engine in detail
    assert os.path.isabs(exe) and exe not in detail  # review S7: no local paths in findings


def test_hostname_is_case_insensitive() -> None:
    r = trust.verify(
        chain("good"), hostname="GOOD.Example.TEST.", purpose=Purpose.TLS_SERVER, now=NOW, anchors=CA / "root.pem"
    )
    assert r.trusted, r


def test_openssl_lookup_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    trust._find_openssl.cache_clear()
    first = trust.openssl_binary()
    calls = []
    real = subprocess.run

    def spy(*a: object, **k: object) -> object:
        calls.append(a)
        return real(*a, **k)  # type: ignore[call-overload]

    monkeypatch.setattr(subprocess, "run", spy)
    assert trust.openssl_binary() == first
    assert not calls
