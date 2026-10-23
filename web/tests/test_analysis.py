from __future__ import annotations

import datetime as dt

import pytest

from certcheck.analysis import fmt
from certcheck.trust import OpenSSLMissing, openssl_binary
from certcheck.x509info import wildcard_match


def test_fmt_matches_mac_display_style() -> None:
    assert fmt(dt.datetime(2026, 1, 1, tzinfo=dt.UTC)) == "Jan 1, 2026 at 12:00 AM"
    assert fmt(dt.datetime(2026, 7, 15, 13, 5, tzinfo=dt.UTC)) == "Jul 15, 2026 at 1:05 PM"


@pytest.mark.parametrize(
    ("pattern", "host", "ok"),
    [
        ("*.wild.example.test", "a.wild.example.test", True),
        ("*.wild.example.test", "a.b.wild.example.test", False),
        ("*.wild.example.test", "wild.example.test", False),
        ("*.test", "example.test", False),
        ("Good.Example.Test.", "good.example.test", True),
    ],
)
def test_wildcard_match(pattern: str, host: str, ok: bool) -> None:
    assert wildcard_match(pattern, host) is ok


def test_openssl_is_openssl3(monkeypatch: pytest.MonkeyPatch) -> None:
    assert openssl_binary()
    monkeypatch.setenv("CERTCHECK_OPENSSL", "/nonexistent/openssl")
    with pytest.raises(OpenSSLMissing):
        openssl_binary()
