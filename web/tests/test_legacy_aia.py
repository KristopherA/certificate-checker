"""M4 legacy TLS 1.0/1.1 (opt-in, isolated contexts), AIA chain completion and CT presence."""

from __future__ import annotations

import ssl
import struct
import warnings
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from m4_pki import Issued, issue, tls_server, web, write

from certcheck import aia, check, legacy, listener, probe
from certcheck.x509info import parse_cert

LOOP = probe.TargetPolicy(allow_loopback=True)


def _tls10_server(tmp: Path, leaf: Issued, extra: bytes = b"") -> ssl.SSLContext:
    s = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    s.set_ciphers("DEFAULT:@SECLEVEL=0")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        s.minimum_version = s.maximum_version = ssl.TLSVersion.TLSv1
    s.load_cert_chain(write(tmp, "c.pem", leaf.pem + extra), write(tmp, "k.pem", leaf.key_pem()))
    return s


def _tls10_possible() -> bool:
    try:
        ctx = legacy.legacy_context("TLSv1")
        return bool(ctx.get_ciphers())
    except ssl.SSLError:
        return False


needs_tls10 = pytest.mark.skipif(not _tls10_possible(), reason="this OpenSSL build cannot do TLS 1.0")


@pytest.fixture(scope="module")
def ca() -> Issued:
    return issue("Test Legacy CA", ca=True)


@needs_tls10
def test_normal_probe_hints_and_legacy_mode_reports_insecure(tmp_path: Path, ca: Issued) -> None:
    leaf = issue("old.example.test", ca)
    with tls_server(_tls10_server(tmp_path, leaf, ca.pem)) as port:
        t = probe.Target("old.example.test", port, connect_ip="127.0.0.1")
        plain = check.run(t, policy=LOOP, nameservers=[])
        legacy_r = check.run(t, check.Options(legacy=True), policy=LOOP, nameservers=[])
    assert plain.error and not plain.legacy
    assert "legacy-hint" in {f.id for f in plain.findings}
    assert legacy_r.error is None and legacy_r.legacy and legacy_r.tls_version == "TLSv1"
    f = {x.id: x for x in legacy_r.findings}
    assert f["legacy-TLSv1"].severity.label == "fail" and "INSECURE" in f["legacy-TLSv1"].title
    assert "legacy-mode" in f and "legacy-TLSv1.1" not in f


def test_modern_server_has_no_legacy(tmp_path: Path, ca: Issued) -> None:
    leaf = issue("www.example.test", ca)
    sctx = listener.server_context(write(tmp_path, "c.pem", leaf.pem), write(tmp_path, "k.pem", leaf.key_pem()))
    with tls_server(sctx) as port:
        t = probe.Target("www.example.test", port, connect_ip="127.0.0.1")
        r = check.run(t, check.Options(legacy=True), policy=LOOP, nameservers=[])
    f = {x.id: x for x in r.findings}
    assert r.error is None and not r.legacy
    assert f["legacy-none"].severity.label == "pass"


@needs_tls10
def test_default_and_listener_contexts_refuse_tls10(tmp_path: Path, ca: Issued) -> None:
    leaf = issue("www.example.test", ca)
    assert probe.default_context().minimum_version == ssl.TLSVersion.TLSv1_2
    sctx = listener.server_context(write(tmp_path, "c.pem", leaf.pem), write(tmp_path, "k.pem", leaf.key_pem()))
    assert sctx.minimum_version == ssl.TLSVersion.TLSv1_2
    with tls_server(sctx) as port:
        res = legacy.scan(probe.Target("www.example.test", port, connect_ip="127.0.0.1"), "127.0.0.1", policy=LOOP)
    assert not any(v.supported for v in res)


def test_legacy_contexts_are_fresh_and_isolated() -> None:
    a, b = legacy.legacy_context("TLSv1"), legacy.legacy_context("TLSv1")
    assert a is not b and a is not probe.default_context()
    assert probe.default_context().minimum_version == ssl.TLSVersion.TLSv1_2  # untouched by legacy use


def test_legacy_scan_respects_policy(ca: Issued) -> None:
    with pytest.raises(probe.TargetDenied):
        legacy.scan(probe.Target("old.example.test", 443, connect_ip="127.0.0.1"), "127.0.0.1",
                    policy=probe.TargetPolicy())  # fmt: skip


def test_options_parse_strict_booleans() -> None:
    assert check.Options.from_mapping({"legacy": True, "revocation": False}) == check.Options(legacy=True)
    with pytest.raises(ValueError, match="true or false"):
        check.Options.from_mapping({"aia": "yes"})
    with pytest.raises(ValueError, match="Unknown"):
        check.Options.from_mapping({"stapling": True})


def test_aia_completes_a_missing_intermediate(tmp_path: Path) -> None:
    root = issue("Test AIA Root", ca=True)
    with web() as w:
        inter = issue("Test AIA Intermediate", root, ca=True)
        leaf = issue("www.example.test", inter, ca_issuers=w.url("/inter.p7c"))
        w.static("/inter.p7c", pkcs7.serialize_certificates([inter.cert], serialization.Encoding.DER))
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(write(tmp_path, "c.pem", leaf.pem), write(tmp_path, "k.pem", leaf.key_pem()))
        anchors = write(tmp_path, "root.pem", root.pem)
        with tls_server(sctx) as port:
            t = probe.Target("www.example.test", port, connect_ip="127.0.0.1")
            before = check.run(t, policy=LOOP, nameservers=[], anchors=anchors)
            after = check.run(t, check.Options(aia=True), policy=LOOP, nameservers=[], anchors=anchors)
    assert before.trust is not None and not before.trust.trusted
    assert after.trust is not None and after.trust.trusted, after.trust
    f = {x.id: x for x in after.findings}
    assert f["aia-fetched"].severity.label == "warning"
    assert after.contacted == [w.url("/inter.p7c")]
    assert "aia-fetched" not in {x.id for x in before.findings} and before.contacted == []


def test_aia_rejects_unrelated_certs_and_never_adds_roots() -> None:
    root = issue("Test AIA Root", ca=True)
    stranger = issue("Some Other CA", ca=True)
    with web() as w:
        inter = issue("Test AIA Intermediate", root, ca=True, ca_issuers=w.url("/root.der"))
        leaf = issue("www.example.test", inter, ca_issuers=w.url("/wrong.der"))
        w.static("/wrong.der", stranger.der)
        comp = aia.complete([parse_cert(leaf.der)], policy=LOOP)
        assert comp.added == []
        w.static("/wrong.der", inter.der)
        w.static("/root.der", root.der)
        comp = aia.complete([parse_cert(leaf.der)], policy=LOOP)
    assert [c.display_name for c in comp.added] == [parse_cert(inter.der).display_name]


def test_aia_fetch_is_policy_checked() -> None:
    root = issue("Test AIA Root", ca=True)
    with web() as w:
        leaf = issue("www.example.test", root, ca_issuers=w.static("/r.der", root.der))
        comp = aia.complete([parse_cert(leaf.der)], policy=probe.TargetPolicy())
        assert comp.added == [] and w.hits == []
        assert any("blocked" in n for n in comp.notes)


def _sct_ext() -> x509.UnrecognizedExtension:
    sct = bytes([0]) + b"\x11" * 32 + struct.pack(">Q", 1_700_000_000_000) + b"\x00\x00" + b"\x04\x03"
    sig = b"\x30\x06\x02\x01\x01\x02\x01\x01"
    sct += struct.pack(">H", len(sig)) + sig
    lst = struct.pack(">H", len(sct)) + sct
    lst = struct.pack(">H", len(lst)) + lst
    return x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"), bytes([0x04, len(lst)]) + lst)


def test_ct_presence() -> None:
    ca = issue("Test CT CA", ca=True)
    with_sct = parse_cert(issue("ct.example.test", ca, extra=[_sct_ext()]).der)
    without = parse_cert(issue("noct.example.test", ca).der)
    assert aia.sct_count(with_sct) == 1 and aia.sct_count(without) == 0
    assert aia.ct_finding(with_sct).severity.label == "info"
    assert "1" in aia.ct_finding(with_sct).title + aia.ct_finding(with_sct).detail
