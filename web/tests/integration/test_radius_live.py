"""eapol_test against a real FreeRADIUS in throw-away containers (see shared/tools/integration-radius.sh).

Skipped unless CERTCHECK_IT_RADIUS_HOST is set. The shared secret arrives in CERTCHECK_IT_RADIUS_SECRET (generated
per run, never logged); the throw-away CA is in CERTCHECK_IT_RADIUS_CA. The server sends leaf + intermediate only
(root not sent), which is exactly the case where the Mac's Radius.swift:92-93 reports a false PASS.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from certcheck import filecheck, radius

HOST = os.environ.get("CERTCHECK_IT_RADIUS_HOST", "")
SECRET = os.environ.get("CERTCHECK_IT_RADIUS_SECRET", "")
CA = os.environ.get("CERTCHECK_IT_RADIUS_CA", "")
pytestmark = pytest.mark.skipif(not (HOST and SECRET and CA), reason="run shared/tools/integration-radius.sh")


def sev(r: radius.ProbeResult, fid: str) -> str | None:
    return next((f.severity.label.lower() for f in r.findings if f.id == fid), None)


@pytest.mark.parametrize("method", list(radius.EAPMethod))
def test_chain_read_and_top_unanchored(method: radius.EAPMethod) -> None:
    r = radius.run(HOST, method=method, expected_name="radius.example.test", secret=SECRET, timeout=15)
    assert sev(r, "rad-probe-ok") is not None, r.transcript
    assert len(r.chain) == 2, r.transcript
    # radius.run de-duplicates and orders leaf-first; the raw -o order is pinned in test_eapol_test_o_order below.
    assert r.chain[0].is_ca is not True and r.chain[1].is_ca is True
    assert not any(SECRET in line for line in r.transcript)
    # Top (intermediate) is not self-signed and no anchor given: must not PASS (Mac false PASS case).
    assert sev(r, "rad-chain") == "fail", [f.key() for f in r.findings]


def test_chain_verifies_with_root_anchor() -> None:
    rep = filecheck.FileReport()
    filecheck.load("ca.pem", Path(CA).read_bytes(), rep)
    anchors = rep.certificates
    assert len(anchors) == 1
    r = radius.run(HOST, expected_name="radius.example.test", secret=SECRET, timeout=15, anchors=anchors)
    assert sev(r, "rad-chain") == "pass", [f.key() for f in r.findings]


def test_wrong_secret_reads_no_certificate() -> None:
    r = radius.run(HOST, expected_name="radius.example.test", secret="wrong-" + SECRET[:4], timeout=6)
    assert not r.chain
    assert any(f.severity.label.lower() == "fail" for f in r.findings if f.kind == "probe")


def test_eapol_test_o_order_is_top_first() -> None:
    """Review S7, live: what eapol_test -o itself writes (no reordering). The server sends leaf + intermediate.

    Expected from hostap (eapol_test_cert_cb via tls_openssl.c tls_verify_cb): one PEM per OpenSSL verify-callback
    call, top of the built path first, leaf last, and a certificate may repeat (one call per error plus the final
    call; depth 0 re-emitted when a CA check fails)."""
    tool = radius.locate()
    assert tool is not None
    address = radius.resolve(HOST, 1812, radius.probe.TargetPolicy())[0]
    with tempfile.TemporaryDirectory() as tmp:
        conf, out = Path(tmp, "probe.conf"), Path(tmp, "chain.pem")
        conf.write_text(radius.config(radius.EAPMethod.PEAP))
        args = radius.arguments(str(conf), address, 1812, SECRET, str(out), 15)
        subprocess.run([str(tool), *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=40, check=False)  # noqa: S603
        rep = filecheck.FileReport()
        filecheck.load("chain.pem", out.read_bytes(), rep)
    order = ["ca" if c.is_ca else "leaf" for c in rep.certificates]
    runs = [x for i, x in enumerate(order) if i == 0 or order[i - 1] != x]
    assert runs == ["ca", "leaf"], order  # top first, leaf last: NOT the wire order (leaf, intermediate)
    print("eapol_test -o order:", order)
