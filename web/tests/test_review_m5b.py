"""Review fixes for M5b: CRL IDP scope (M4 B1), blocked vs contacted (M4 S1), PFX worker process group and
normalised errors (M3c S1/S2), deterministic 429 (M5 S1), CRL parse-time budget."""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import os
import threading
import time
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from m4_pki import NOW, Issued, crl, issue, web

from app.main import create_app
from app.settings import Settings
from certcheck import fetch, filecheck, pfx, probe, revocation
from certcheck.model import Purpose
from certcheck.revocation import Status
from certcheck.x509info import parse_cert

LOOP = probe.TargetPolicy(allow_loopback=True)


def _idp(*, ca: bool = False, user: bool = False) -> x509.IssuingDistributionPoint:
    return x509.IssuingDistributionPoint(None, None, user, ca, None, False, False)


@pytest.fixture(scope="module")
def ca() -> Issued:
    return issue("Test Scope Root CA", ca=True)


# ---- M4 B1: a CRL whose IDP scope does not cover the certificate is unusable, never GOOD


def test_leaf_against_ca_only_crl_is_not_good(ca: Issued) -> None:
    leaf = issue("good.example.test", ca)
    with pytest.raises(revocation.Invalid, match="onlyContainsCACerts"):
        revocation.check_crl(crl(ca, idp=_idp(ca=True)), parse_cert(leaf.der), parse_cert(ca.der), NOW)


def test_ca_against_user_only_crl_is_not_good(ca: Issued) -> None:
    inter = issue("Test Scope Intermediate", ca, ca=True)
    with pytest.raises(revocation.Invalid, match="onlyContainsUserCerts"):
        revocation.check_crl(crl(ca, idp=_idp(user=True)), parse_cert(inter.der), parse_cert(ca.der), NOW)


def test_matching_scopes_still_answer(ca: Issued) -> None:
    leaf, inter = issue("good.example.test", ca), issue("Test Scope Intermediate", ca, ca=True)
    c = parse_cert(ca.der)
    assert revocation.check_crl(crl(ca, idp=_idp(user=True)), parse_cert(leaf.der), c, NOW).status == Status.GOOD
    assert revocation.check_crl(crl(ca, idp=_idp(ca=True)), parse_cert(inter.der), c, NOW).status == Status.GOOD
    got = revocation.check_crl(crl(ca, [leaf.cert], idp=_idp(user=True)), parse_cert(leaf.der), c, NOW)
    assert got.status == Status.REVOKED


def test_end_to_end_leaf_with_ca_only_crl_could_not_check(ca: Issued) -> None:
    with web() as w:
        leaf = issue("good.example.test", ca, crl_url=w.url("/ca.crl"))
        w.static("/ca.crl", crl(ca, idp=_idp(ca=True)))
        st = revocation.check([parse_cert(leaf.der), parse_cert(ca.der)], stapled=None, now=NOW, policy=LOOP).certs[0]
    assert st.status == Status.COULD_NOT_CHECK and "onlyContainsCACerts" in st.reason


# ---- M4 S1: URLs refused by TargetPolicy are blocked, not contacted


def test_blocked_url_is_not_contacted() -> None:
    with web() as w:
        u = w.static("/a", b"x")
        seen: list[str] = []
        blocked: list[str] = []
        with pytest.raises(probe.TargetDenied):
            fetch.fetch(u, purpose="aia", policy=probe.TargetPolicy(), contacted=seen, blocked=blocked)
        assert w.hits == []
    assert seen == [] and blocked == [u]


def test_revocation_lists_blocked_separately(ca: Issued) -> None:
    with web() as w:
        leaf = issue("good.example.test", ca, crl_url=w.static("/ca.crl", crl(ca)))
        chain = [parse_cert(leaf.der), parse_cert(ca.der)]
        r = revocation.check(chain, stapled=None, now=NOW, policy=probe.TargetPolicy())
    assert r.contacted == [] and r.blocked == [w.url("/ca.crl")]
    detail = next(f.detail for f in revocation.findings(r) if f.id == "rev-urls")
    assert "Blocked by the target policy" in detail and w.url("/ca.crl") in detail


# ---- M3c S1/S2: PFX worker


def test_pfx_timeout_kills_the_worker_process_group(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    marker = tmp_path / "grandchild.pid"
    code = (
        "import subprocess, sys, time; sys.stdin.buffer.read(); "
        "q = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
        f"open({str(marker)!r}, 'w').write(str(q.pid)); time.sleep(60)"
    )
    monkeypatch.setattr(filecheck, "_WORKER_CODE", code)
    monkeypatch.setattr(filecheck, "PFX_TIME_BUDGET_S", 2.0)
    monkeypatch.setattr(pfx, "read_params", lambda d: pfx.Params(iterations=[], mac=None))
    start = time.monotonic()
    with pytest.raises(ValueError, match="took too long"):
        filecheck._pkcs12_worker(b"x", "")
    assert time.monotonic() - start < 8  # a surviving grandchild would hold stdout open for 60 s
    pid = int(marker.read_text())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(pid, 9)
        pytest.fail("grandchild survived the timeout")


@pytest.mark.parametrize(
    "res",
    [
        {"status": "ok", "certs": ["!!not base64!!"]},
        {"status": "ok", "certs": [base64.b64encode(b"\x30\x03\x02\x01\xff").decode()]},
        {"status": "ok", "certs": [], "spki": base64.b64encode(b"\x30\x80garbage").decode()},
    ],
)
def test_hostile_ok_output_gets_one_fixed_message(res: dict[str, object], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pfx, "read_params", lambda d: pfx.Params(iterations=[], mac=None))
    monkeypatch.setattr(filecheck, "_pkcs12_worker", lambda *a: res)
    r = filecheck.inspect_data([("x.p12", b"\x30\x00")], None, Purpose.TLS_SERVER, password="SYNTH-pw")
    details = [f.detail for f in r.findings]
    assert filecheck.PFX_CORRUPT in details and not r.certificates and not r.keys


# ---- M5 S1: excess requests get 429 at once, deterministically


def test_excess_requests_get_429_without_waiting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from certcheck import check

    gate = threading.Event()

    def slow(*_a: object, **_kw: object) -> probe.ProbeResult:
        gate.wait(10)
        return probe.ProbeResult(probe.Target("www.example.test", 443))

    monkeypatch.setattr(check, "run", slow)
    app = create_app(Settings(config_dir=tmp_path, max_concurrent=2, login_required=False), policy=LOOP)
    body = {"host": "www.example.test", "resolve": "10.0.0.1"}

    async def go() -> list[int]:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
            tasks = [asyncio.create_task(c.post("/api/v1/check", json=body)) for _ in range(6)]
            done, _ = await asyncio.wait(tasks, timeout=5)
            early = sorted(t.result().status_code for t in done)
            gate.set()
            rest = [(await t).status_code for t in tasks if t not in done]
            return early + rest

    codes = asyncio.run(go())
    assert codes.count(429) == 4 and codes[:4] == [429] * 4  # the 429s came back while two checks still ran


# ---- CRL parse-time budget (a large CRL near the 10 MB fetch cap)


def test_large_crl_parses_within_budget(ca: Issued) -> None:
    from cryptography.hazmat.primitives import hashes, serialization

    b = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.cert.subject)
        .last_update(NOW - dt.timedelta(minutes=1))
        .next_update(NOW + dt.timedelta(days=1))
    )
    when = NOW - dt.timedelta(hours=1)
    for n in range(1, 120_001):
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(n << 64).revocation_date(when).build()
        )
    data = b.sign(ca.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    leaf = issue("good.example.test", ca)
    start = time.monotonic()
    got = revocation.check_crl(data, parse_cert(leaf.der), parse_cert(ca.der), NOW)
    assert got.status == Status.GOOD and time.monotonic() - start < fetch.FETCH_TIMEOUT_S
