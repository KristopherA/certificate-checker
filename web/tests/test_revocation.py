"""M4 revocation: stapled, then OCSP, then CRL; every answer verified; COULD NOT CHECK when nothing answers."""

from __future__ import annotations

import datetime as dt
import http.server
import ssl
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from m4_pki import NOW, Issued, crl, free_port, issue, ocsp_response, tls_server, web, write
from OpenSSL import SSL

from certcheck import check, probe, revocation, trust
from certcheck.revocation import Status
from certcheck.x509info import parse_cert

LOOP = probe.TargetPolicy(allow_loopback=True)


def chain(*xs: Issued) -> list:  # type: ignore[type-arg]
    return [parse_cert(x.der) for x in xs]


@pytest.fixture(scope="module")
def ca() -> Issued:
    return issue("Test Revocation CA", ca=True)


@pytest.fixture
def responder(tmp_path: Path, ca: Issued) -> Iterator[tuple[str, Issued, Issued]]:
    """openssl ocsp -index answering one good and one revoked leaf.

    Review M4 S2: openssl ocsp -port listens on every address and cannot be bound to loopback, so the HTTP side is
    the 127.0.0.1-only test server and openssl signs each request offline (-reqin/-respout)."""
    with web() as w:
        url = w.url("/")
        good = issue("good.example.test", ca, ocsp_url=url)
        bad = issue("revoked.example.test", ca, ocsp_url=url)
        exp = (NOW + dt.timedelta(days=30)).strftime("%y%m%d%H%M%SZ")
        rev = (NOW - dt.timedelta(hours=1)).strftime("%y%m%d%H%M%SZ")
        (tmp_path / "index.txt").write_text(
            f"V\t{exp}\t\t{good.cert.serial_number:X}\tunknown\t/CN=good.example.test\n"
            f"R\t{exp}\t{rev},keyCompromise\t{bad.cert.serial_number:X}\tunknown\t/CN=revoked.example.test\n"
        )
        write(tmp_path, "ca.pem", ca.pem)
        write(tmp_path, "ca.key", ca.key_pem())
        exe, _ = trust.openssl_binary()
        lock = threading.Lock()

        def answer(h: http.server.BaseHTTPRequestHandler, req: bytes) -> None:
            with lock:
                (tmp_path / "req.der").write_bytes(req)
                subprocess.run(  # noqa: S603 - fixed argv
                    [exe, "ocsp", "-index", "index.txt", "-reqin", "req.der", "-respout", "resp.der",
                     "-rsigner", "ca.pem", "-rkey", "ca.key", "-CA", "ca.pem", "-ndays", "1"],
                    cwd=tmp_path, check=True, capture_output=True,
                )  # fmt: skip
                body = (tmp_path / "resp.der").read_bytes()
            h.send_response(200)
            h.send_header("Content-Type", "application/ocsp-response")
            h.send_header("Content-Length", str(len(body)))
            h.end_headers()
            h.wfile.write(body)

        w.routes["/"] = answer
        yield url, good, bad


def test_ocsp_good_and_revoked(responder: tuple[str, Issued, Issued], ca: Issued) -> None:
    url, good, bad = responder
    r = revocation.check(chain(good, ca), stapled=None, now=NOW, policy=LOOP)
    assert r.certs[0].status == Status.GOOD and r.certs[0].method == "OCSP", r.certs[0].notes
    assert r.certs[1].status == Status.NOT_APPLICABLE  # self-signed root
    assert r.contacted == [url]
    r = revocation.check(chain(bad, ca), stapled=None, now=NOW, policy=LOOP)
    assert r.certs[0].status == Status.REVOKED and r.certs[0].revoked_at is not None
    ids = {f.id: f for f in revocation.findings(r)}
    assert ids["rev-0"].severity.label == "fail"


def test_crl_good_and_revoked(ca: Issued) -> None:
    with web() as w:
        u = w.url("/ca.crl")
        good = issue("good.example.test", ca, crl_url=u)
        bad = issue("revoked.example.test", ca, crl_url=u)
        w.static("/ca.crl", crl(ca, [bad.cert]))
        assert revocation.check(chain(good, ca), stapled=None, now=NOW, policy=LOOP).certs[0].status == Status.GOOD
        st = revocation.check(chain(bad, ca), stapled=None, now=NOW, policy=LOOP).certs[0]
        assert st.status == Status.REVOKED and st.method == "CRL" and "superseded" in st.reason.lower()


def test_ocsp_unreachable_falls_back_to_crl_then_could_not_check(ca: Issued) -> None:
    dead = f"http://127.0.0.1:{free_port()}/"
    with web() as w:
        leaf = issue("good.example.test", ca, ocsp_url=dead, crl_url=w.url("/ca.crl"))
        w.static("/ca.crl", crl(ca))
        st = revocation.check(chain(leaf, ca), stapled=None, now=NOW, policy=LOOP, timeout=2).certs[0]
        assert st.status == Status.GOOD and st.method == "CRL"
        assert any(n.startswith("OCSP") for n in st.notes)
    st = revocation.check(chain(leaf, ca), stapled=None, now=NOW, policy=LOOP, timeout=2).certs[0]
    assert st.status == Status.COULD_NOT_CHECK and "OCSP" in st.reason and "CRL" in st.reason


def test_blocked_by_policy_is_could_not_check(ca: Issued) -> None:
    with web() as w:
        leaf = issue("good.example.test", ca, crl_url=w.static("/ca.crl", crl(ca)))
        st = revocation.check(chain(leaf, ca), stapled=None, now=NOW, policy=probe.TargetPolicy()).certs[0]
        assert st.status == Status.COULD_NOT_CHECK and "blocked" in st.reason
        assert w.hits == []


def test_badly_signed_answers_are_ignored(ca: Issued) -> None:
    other = issue("Other CA", ca=True)
    with web() as w:
        leaf = issue("good.example.test", ca, ocsp_url=w.url("/ocsp"), crl_url=w.url("/ca.crl"))
        w.static("/ocsp", ocsp_response(leaf, ca, signer=other))
        w.static("/ca.crl", crl(other))
        st = revocation.check(chain(leaf, ca), stapled=None, now=NOW, policy=LOOP).certs[0]
    assert st.status == Status.COULD_NOT_CHECK


def test_delegated_responder(ca: Issued) -> None:
    resp = issue("ocsp.example.test", ca, ocsp_signing=True)
    with web() as w:
        leaf = issue("good.example.test", ca, ocsp_url=w.url("/ocsp"))
        w.static("/ocsp", ocsp_response(leaf, ca, signer=resp, certs=[resp.cert]))
        assert revocation.check(chain(leaf, ca), stapled=None, now=NOW, policy=LOOP).certs[0].status == Status.GOOD
        notdelegated = issue("www2.example.test", ca)  # serverAuth only
        w.static("/ocsp", ocsp_response(leaf, ca, signer=notdelegated, certs=[notdelegated.cert]))
        st = revocation.check(chain(leaf, ca), stapled=None, now=NOW, policy=LOOP).certs[0]
        assert st.status == Status.COULD_NOT_CHECK


def test_stapled_wins_without_any_fetch(ca: Issued) -> None:
    with web() as w:
        leaf = issue("good.example.test", ca, ocsp_url=w.url("/ocsp"))
        r = revocation.check(chain(leaf, ca), stapled=ocsp_response(leaf, ca, revoked=True), now=NOW, policy=LOOP)
        assert r.certs[0].status == Status.REVOKED and r.certs[0].method == "stapled OCSP"
        assert w.hits == [] and r.contacted == []


def test_issuer_missing_and_no_urls(ca: Issued) -> None:
    leaf = issue("good.example.test", ca)
    assert revocation.check(chain(leaf), stapled=None, now=NOW).certs[0].status == Status.COULD_NOT_CHECK
    st = revocation.check(chain(leaf, ca), stapled=None, now=NOW).certs[0]
    assert st.status == Status.COULD_NOT_CHECK and "no stapled" in st.reason


def _pyopenssl_server(leaf: Issued, ca: Issued, staple: bytes | None) -> SSL.Context:
    ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
    ctx.use_certificate(leaf.cert)
    ctx.add_extra_chain_cert(ca.cert)
    ctx.use_privatekey(leaf.key)
    if staple is not None:
        ctx.set_ocsp_server_callback(lambda _c, _d: staple)
    return ctx


class _PyOpenSSLAdapter:
    """Lets m4_pki.tls_server drive a pyOpenSSL server context."""

    def __init__(self, ctx: SSL.Context) -> None:
        self.ctx = ctx

    def wrap_socket(self, sock, server_side=True):  # type: ignore[no-untyped-def]  # noqa: ARG002
        sock.setblocking(True)
        c = SSL.Connection(self.ctx, sock)
        c.set_accept_state()
        try:
            c.do_handshake()
            c.recv(1)
        except SSL.Error:
            pass

        class _Done:
            def __enter__(self):  # type: ignore[no-untyped-def]
                return self

            def __exit__(self, *_a):  # type: ignore[no-untyped-def]
                return False

            def recv(self, _n):  # type: ignore[no-untyped-def]
                return b""

        return _Done()


@pytest.mark.parametrize("revoked", [False, True])
def test_end_to_end_stapled(ca: Issued, tmp_path: Path, revoked: bool) -> None:
    leaf = issue("www.example.test", ca, ocsp_url="http://127.0.0.1:9/")
    with tls_server(_PyOpenSSLAdapter(_pyopenssl_server(leaf, ca, ocsp_response(leaf, ca, revoked=revoked)))) as port:  # type: ignore[arg-type]
        t = probe.Target("www.example.test", port, connect_ip="127.0.0.1")
        r = check.run(t, check.Options(revocation=True), policy=LOOP, nameservers=[],
                      anchors=write(tmp_path, "a.pem", ca.pem))  # fmt: skip
    assert r.error is None
    f = {x.id: x for x in r.findings}
    assert f["rev-0"].severity.label == ("fail" if revoked else "pass")
    assert "stapled" in f["rev-0"].detail.lower() or "stapled" in f["rev-0"].title.lower()
    assert r.contacted == []


def test_must_staple_without_staple_is_flagged(ca: Issued, tmp_path: Path) -> None:
    leaf = issue("www.example.test", ca, must_staple=True)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(write(tmp_path, "c.pem", leaf.pem + ca.pem), write(tmp_path, "k.pem", leaf.key_pem()))
    with tls_server(sctx) as port:
        t = probe.Target("www.example.test", port, connect_ip="127.0.0.1")
        r = check.run(t, check.Options(revocation=True), policy=LOOP, nameservers=[])
    f = {x.id: x for x in r.findings}
    assert f["must-staple"].severity.label == "warning"
    assert f["rev-0"].severity.label == "info"  # COULD NOT CHECK: no staple, no URLs


def test_revocation_is_opt_in(ca: Issued, tmp_path: Path) -> None:
    leaf = issue("www.example.test", ca, must_staple=True)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(write(tmp_path, "c.pem", leaf.pem + ca.pem), write(tmp_path, "k.pem", leaf.key_pem()))
    with tls_server(sctx) as port:
        r = check.run(probe.Target("www.example.test", port, connect_ip="127.0.0.1"), policy=LOOP, nameservers=[])
    assert not any(x.id.startswith("rev-") or x.id == "must-staple" for x in r.findings)
    assert r.contacted == []
