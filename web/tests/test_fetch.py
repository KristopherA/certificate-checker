"""M4 outbound fetches: TargetPolicy on every hop, http/https only, size, time and redirect caps."""

from __future__ import annotations

import time

import pytest
from m4_pki import web

from certcheck import fetch, probe

LOOP = probe.TargetPolicy(allow_loopback=True)


@pytest.mark.parametrize(
    "url", ["ftp://ca.example.test/x", "file:///etc/hosts", "ldap://ca.example.test/x", "http://u:p@ca.example.test/"]
)
def test_refuses_other_schemes_and_userinfo(url: str) -> None:
    with pytest.raises(fetch.FetchError):
        fetch.fetch(url, purpose="aia", policy=LOOP)


def test_fetches_and_records_contacted() -> None:
    with web() as w:
        u = w.static("/a", b"hello")
        seen: list[str] = []
        got = fetch.fetch(u, purpose="aia", policy=LOOP, contacted=seen)
    assert got.body == b"hello" and got.status == 200
    assert seen == [u]


def test_default_policy_denies_loopback() -> None:
    with web() as w:
        u = w.static("/a", b"x")
        with pytest.raises(probe.TargetDenied):
            fetch.fetch(u, purpose="aia", policy=probe.TargetPolicy())
        assert w.hits == []


def test_follows_a_few_redirects_only() -> None:
    with web() as w:
        w.static("/end", b"done")
        for i in range(5):
            w.static(f"/r{i}", b"", 302, {"Location": "/end" if i == 0 else f"/r{i - 1}"})
        assert fetch.fetch(w.url("/r2"), purpose="aia", policy=LOOP).body == b"done"  # 3 redirects
        with pytest.raises(fetch.FetchError, match="redirect"):
            fetch.fetch(w.url("/r4"), purpose="aia", policy=LOOP)


def test_redirect_hop_is_policy_checked() -> None:
    with web() as w:
        w.static("/r", b"", 302, {"Location": "http://169.254.169.254/latest/meta-data/"})
        with pytest.raises(probe.TargetDenied):
            fetch.fetch(w.url("/r"), purpose="aia", policy=LOOP)
        w.static("/f", b"", 302, {"Location": "ftp://ca.example.test/x"})
        with pytest.raises(fetch.FetchError):
            fetch.fetch(w.url("/f"), purpose="aia", policy=LOOP)


def test_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(fetch.MAX_BYTES, "crl", 1000)
    with web() as w:
        w.static("/big", b"x" * 5000)

        def chunked(h, _req):  # type: ignore[no-untyped-def]
            h.send_response(200)
            h.end_headers()
            h.wfile.write(b"y" * 5000)

        w.routes["/nolen"] = chunked
        with pytest.raises(fetch.FetchError, match="large|limit|bytes"):
            fetch.fetch(w.url("/big"), purpose="crl", policy=LOOP)
        with pytest.raises(fetch.FetchError, match="large|limit|bytes"):
            fetch.fetch(w.url("/nolen"), purpose="crl", policy=LOOP)


def test_time_cap() -> None:
    with web() as w:

        def slow(h, _req):  # type: ignore[no-untyped-def]
            h.send_response(200)
            h.send_header("Content-Length", "10")
            h.end_headers()
            h.wfile.write(b"a")
            h.wfile.flush()
            time.sleep(3)

        w.routes["/slow"] = slow
        t0 = time.monotonic()
        with pytest.raises(fetch.FetchError):
            fetch.fetch(w.url("/slow"), purpose="aia", policy=LOOP, timeout=0.5)
        assert time.monotonic() - t0 < 2.5


def test_non_2xx_is_an_error() -> None:
    with web() as w, pytest.raises(fetch.FetchError, match="404"):
        fetch.fetch(w.url("/missing"), purpose="aia", policy=LOOP)
