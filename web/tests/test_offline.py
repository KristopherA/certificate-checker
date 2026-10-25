"""Unit tests for the M3 offline checks, mirroring the Mac's RadiusTests, IPsecTests, StackTests (MTLSPair),
VendorTests (Munki), WireGuardTests, SMIMETests, DKIMTests, SSHHostKeyTests and the FileCheck PKCS#7/PFX
tests. Inputs are the Mac app's own Tests/Fixtures (skipped when the app folder is absent)."""

from __future__ import annotations

import datetime as dt
import stat
import sys
import tempfile
import time
from pathlib import Path

import pytest

from certcheck import chaincheck, filecheck, pfx, probe, radius
from certcheck.model import Finding, Purpose, Severity
from certcheck.offline import dkim, ipsec, mtls, munki, smime, ssh_hostkeys, wireguard
from certcheck.shared import shared_dir

sys.path.insert(0, str(shared_dir() / "tools"))
from swift_root import find_swift_root  # type: ignore[import-not-found]  # noqa: E402

_root = find_swift_root(shared_dir().parent)
FX = _root / "Tests" / "Fixtures" if _root else Path("/nonexistent")
pytestmark = pytest.mark.skipif(_root is None, reason="Mac app Tests/Fixtures not present")
NOW = dt.datetime(2026, 11, 15, tzinfo=dt.UTC)  # PinnedTestCase.pinnedNow


def items(*names: str) -> list[tuple[str, bytes]]:
    return [(n, (FX / n).read_bytes()) for n in names]


def sev(findings: list[Finding], fid: str) -> Severity | None:
    return next((f.severity for f in findings if f.id == fid), None)


# RADIUS (RadiusTests.swift)


def rad(*names: str, name: str | None = None) -> list[Finding]:
    return radius.inspect_data(items(*names), name, now=NOW)[1]


def test_radius_good_server() -> None:
    f = rad("ipsec-server.crt", "ipsec-ca.crt", "ipsec-server.key", name="vpn.example.test")
    assert not [x for x in f if x.severity == Severity.FAIL]
    for i in ["rad-eku", "rad-name", "rad-key", "rad-sig-0", "rad-chain", "rad-valid", "rad-key-0"]:
        assert sev(f, i) == Severity.PASS, i
    assert all(x.topic.value == "radius" and x.kind for x in f)


def test_radius_bad_server() -> None:
    f = rad("ipsec-bad.crt", "ipsec-ca.crt", name="radius.example.test")
    for i in ["rad-eku", "rad-name", "rad-key", "rad-sig-0"]:
        assert sev(f, i) == Severity.FAIL, i
    assert sev(f, "rad-lifetime") == Severity.WARNING
    assert sev(rad("ipsec-bad.crt", name="bad.example.test"), "rad-name") == Severity.INFO


def test_radius_chain_cases() -> None:
    assert sev(rad("ipsec-server.crt"), "rad-chain") == Severity.WARNING
    exp = rad("ipsec-underexp.crt", "ipsec-intexp.crt", "ipsec-ca.crt")
    assert sev(exp, "rad-chain") == Severity.FAIL and sev(exp, "rad-caexp-1") == Severity.FAIL
    assert sev(rad("ipsec-old.crt", "ipsec-ca.crt"), "rad-lifetime") is None
    assert sev(rad("ipsec-server.crt", "ipsec-other.key"), "rad-key-0") == Severity.FAIL


def test_radius_unanchored_top_is_not_a_pass() -> None:
    """Known Mac bug (Radius.swift:92-93): ChainCheck anchors the top certificate as itself, so a chain whose
    root was not sent reports 'Chain verifies'. Web verifies the top's self-signature or a supplied anchor."""
    f = rad("ipsec-rollleaf.crt", "ipsec-roll.crt")
    assert sev(f, "rad-chain") == Severity.FAIL
    assert sev(rad("ipsec-rollleaf.crt", "ipsec-roll.crt", "ipsec-rollroot.crt"), "rad-chain") != Severity.FAIL


def test_chaincheck_strict_top() -> None:
    rep = filecheck.FileReport()
    for n, d in items("ipsec-rollleaf.crt", "ipsec-roll.crt"):
        filecheck.load(n, d, rep)
    assert not chaincheck.verify(rep.certificates, NOW)[0]
    assert chaincheck.verify(rep.certificates, NOW, anchors=rep.certificates[-1:])[0]


def test_chaincheck_path_length() -> None:
    rep = filecheck.FileReport()
    for n, d in items("ipsec-plleaf.crt", "ipsec-plint.crt", "ipsec-pl0-root.crt"):
        filecheck.load(n, d, rep)
    ok, why = chaincheck.verify(rep.certificates, NOW)
    assert not ok and "pathLenConstraint" in why
    assert chaincheck.verify(rep.certificates[1:], NOW)[0]  # intermediate directly under the pathlen:0 root


def test_radius_probe_config_and_arguments() -> None:
    for m in radius.EAPMethod:
        c = radius.config(m)
        assert f"eap={m.value}" in c and 'anonymous_identity="anonymous"' in c
        assert '\tidentity="certchecker-probe@invalid.example"' in c and "ca_cert" not in c
    assert "auth=MSCHAPV2" in radius.config(radius.EAPMethod.PEAP)
    assert "auth=PAP" in radius.config(radius.EAPMethod.TTLS)
    a = radius.arguments("/t/c", "192.0.2.5", 1812, "SYNTH-secret", "/t/o.pem")
    assert a.count("SYNTH-secret") == 1 and a[a.index("-s") + 1] == "SYNTH-secret"
    assert a[a.index("-r") + 1] == "0" and a[a.index("-o") + 1] == "/t/o.pem"


def test_radius_redaction() -> None:
    out = (
        "RADIUS secret: SYNTH-secret\nEAP: Received EAP-Request id=1 SYNTH-secret\n"
        "random noise\nCTRL-EVENT-EAP-FAILURE\n"
    )
    lines = radius.redact(out, "SYNTH-secret")
    assert "secret" not in "".join(lines).lower() and len(lines) == 2
    out2 = (
        "EAP: MPPE keys OK\nMPPE_SEND_KEY - hexdump(len=32): 01\nEAP-TLS: Derived key - hexdump(len=64): aa\n"
        "RADIUS: shared key xSYNTH-mid-42y appears here\nRADIUS: Received Access-Challenge\nCTRL-EVENT-EAP-SUCCESS\n"
    )
    j = "\n".join(radius.redact(out2, "SYNTH-mid-42"))
    assert "MPPE" not in j and "hexdump" not in j.lower() and "SYNTH-mid-42" not in j
    assert "Access-Challenge" in j and "CTRL-EVENT-EAP-SUCCESS" in j


def test_radius_probe_missing_tool_and_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(radius, "locate", lambda: None)
    r = radius.run("192.0.2.1", secret="x")
    assert r.skipped and r.findings[0].kind == "install" and r.findings[0].severity == Severity.INFO
    tool = Path("/bin/true")
    assert radius.run("a b;rm", secret="s", tool=tool).findings[0].id == "rad-probe-input"
    assert radius.run("192.0.2.1", 0, secret="s", tool=tool).findings[0].id == "rad-probe-input"
    assert radius.run("192.0.2.1", secret="", tool=tool).findings[0].id == "rad-probe-input"


LOOP = probe.TargetPolicy(allow_loopback=True)


def test_radius_target_policy_applies(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Review B1: loopback, link-local/metadata and denied ranges are refused before eapol_test runs.
    ran = tmp_path / "ran"
    tool = fake_tool(tmp_path, f'touch "{ran}"\n')
    monkeypatch.delenv("CERTCHECK_PROBE_ALLOW_LOOPBACK", raising=False)
    for host in ("127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1"):  # noqa: S104
        r = radius.run(host, secret="s", tool=tool)
        assert r.findings[0].id == "rad-probe-input" and r.findings[0].severity == Severity.FAIL, host
        assert "disabled" in r.findings[0].detail or "unicast" in r.findings[0].detail
    deny = probe.TargetPolicy(extra_denied=(probe.ipaddress.ip_network("192.0.2.0/24"),))
    assert "denied range" in radius.run("192.0.2.7", secret="s", tool=tool, policy=deny).findings[0].detail
    # A name whose every address is refused is refused too (DNS cannot sidestep the policy).
    monkeypatch.setattr(radius.socket, "getaddrinfo", lambda *a, **k: [(2, 2, 17, "", ("127.0.0.1", 0))])
    assert radius.run("radius.example.test", secret="s", tool=tool).findings[0].id == "rad-probe-input"
    assert radius.resolve("radius.example.test", 1812, LOOP) == ["127.0.0.1"]
    assert not ran.exists(), "eapol_test must not run for a refused target"


def test_radius_resolve_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    # Review S3: the lookup has a timeout and runs on the shared resolver pool.
    monkeypatch.setattr(radius.socket, "getaddrinfo", lambda *a, **k: time.sleep(3) or [])
    start = time.monotonic()
    with pytest.raises(OSError, match="timed out"):
        radius.resolve("slow.example.test", 1812, LOOP, timeout=0.3)
    assert time.monotonic() - start < 2


def test_radius_tool_killed_on_any_exception(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Review S3: an unexpected exception after Popen still kills eapol_test (finally).
    pidfile = tmp_path / "pid"
    tool = fake_tool(tmp_path, f'echo $$ > "{pidfile}"; exec sleep 30\n')

    class Boom:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def start(self) -> None:
            for _ in range(100):
                if pidfile.exists() and pidfile.read_text().strip():
                    break
                time.sleep(0.05)
            raise RuntimeError("synthetic")

    monkeypatch.setattr(radius.threading, "Thread", Boom)
    with pytest.raises(RuntimeError):
        radius.run("127.0.0.1", policy=LOOP, secret="s", tool=tool)
    pid = int(pidfile.read_text())
    import os

    for _ in range(40):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("eapol_test still running")


def fake_tool(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "eapol_test"
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(stat.S_IRWXU)
    return p


def test_radius_probe_reads_chain(tmp_path: Path) -> None:
    # Real eapol_test -o writes top (deepest) first, as the live FreeRADIUS run showed; web reorders leaf-first.
    chain = (FX / "ipsec-ca.crt").read_text() + (FX / "ipsec-server.crt").read_text()
    (tmp_path / "chain.pem").write_text(chain)
    tool = fake_tool(
        tmp_path,
        'while [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done\n'
        f'cp "{tmp_path}/chain.pem" "$out"\necho "EAP: SYNTH-probe-secret"\necho CTRL-EVENT-EAP-FAILURE\n',
    )
    r = radius.run(
        "127.0.0.1", policy=LOOP, secret="SYNTH-probe-secret", tool=tool, expected_name="vpn.example.test", now=NOW
    )
    assert len(r.chain) == 2 and sev(r.findings, "rad-probe-ok") == Severity.INFO
    assert r.chain[0].is_ca is False and sev(r.findings, "rad-order") is None
    assert sev(r.findings, "rad-chain") == Severity.PASS and sev(r.findings, "rad-name") == Severity.PASS
    text = "".join(r.transcript + [x.title + x.detail for x in r.findings])
    assert "SYNTH-probe-secret" not in text and "CTRL-EVENT-EAP-FAILURE" in text


def test_radius_probe_no_certificate(tmp_path: Path) -> None:
    r = radius.run("127.0.0.1", policy=LOOP, secret="s", tool=fake_tool(tmp_path, "echo 'No response'\n"))
    assert sev(r.findings, "rad-probe-nocert") == Severity.FAIL


def test_radius_probe_ignoring_sigterm_is_killed(tmp_path: Path) -> None:
    tool = fake_tool(tmp_path, "trap '' TERM; echo 'EAP: started'; while :; do sleep 1; done\n")
    before = set(Path(tempfile.gettempdir()).glob("certchecker-radius-*"))
    start = time.monotonic()
    r = radius.run("127.0.0.1", policy=LOOP, secret="SYNTH-term", tool=tool, timeout=1, grace=0)
    assert time.monotonic() - start < 10
    t = next(x for x in r.findings if x.id == "rad-probe-timeout")
    assert t.severity == Severity.FAIL and "SIGKILL" in t.title
    assert set(Path(tempfile.gettempdir()).glob("certchecker-radius-*")) == before, "private folder removed"
    assert "SYNTH-term" not in "".join(r.transcript + [x.title + x.detail for x in r.findings])


# IPsec, mTLS, Munki


def test_ipsec_pfsense_27() -> None:
    r = ipsec.inspect_data(items("SYNTHETIC-pfsense-2.7-config.xml"), "vpn.example.test", now=NOW)
    assert r.servers and r.cas
    assert not any("PRIVATE KEY" in (x.title + x.detail) for x in r.findings)


def test_ipsec_config_supplied_top_anchors() -> None:
    # Since 0.10.1 build 19 a top that IS one of the config's own CAs anchors (as the Mac); see test_build19.
    f = ipsec.inspect_data(items("ipsec-rollleaf.crt", "ipsec-roll.crt"), None, now=NOW).findings
    assert sev(f, "srv0-chain") == Severity.PASS


def test_ipsec_rejects_doctype() -> None:
    r = ipsec.inspect_data([("x.xml", b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e "x">]><pfsense/>')], None, now=NOW)
    assert not r.servers and any(x.severity == Severity.FAIL for x in r.findings)


def test_mtls_contexts() -> None:
    good = mtls.inspect_data(
        items("SYNTHETIC-beats-client.pem", "SYNTHETIC-beats-client.key"), items("SYNTHETIC-stack-ca.pem"), now=NOW
    )[1]
    assert sev(good, "mtls-ca") == Severity.PASS and sev(good, "mtls-eku") == Severity.PASS
    other = mtls.inspect_data(
        items("SYNTHETIC-beats-otherca.pem", "SYNTHETIC-beats-otherca.key"), items("SYNTHETIC-stack-ca.pem"), now=NOW
    )[1]
    assert sev(other, "mtls-ca") == Severity.FAIL
    srv = mtls.inspect_data(
        items("SYNTHETIC-beats-serveronly.pem", "SYNTHETIC-beats-serveronly.key"),
        items("SYNTHETIC-stack-ca.pem"),
        now=NOW,
    )[1]
    assert sev(srv, "mtls-eku") == Severity.FAIL
    assert not any("SecIdentity" in x.detail for x in good)


def test_munki_reads_only_uploads() -> None:
    m = munki.parse((FX / "SYNTHETIC-ManagedInstalls.plist").read_bytes())
    assert m.repo_url == "https://munki.example.test/repo"
    f = munki.inspect(m, None, None, None, now=NOW)[1]
    assert sev(f, "munki-pair") in (Severity.INFO, None)
    cert, key, other, ca = items(
        "SYNTHETIC-munki-client.pem",
        "SYNTHETIC-munki-client.key",
        "SYNTHETIC-munki-other.key",
        "SYNTHETIC-vendor-ca.pem",
    )
    pair = munki.inspect(m, cert, key, ca, now=NOW)[1]
    assert sev(pair, "mtls-key-0") == Severity.PASS and all(x.topic.value == "vendor" for x in pair)
    bad = munki.inspect(m, cert, other, ca, now=NOW)[1]
    assert sev(bad, "mtls-key-0") == Severity.FAIL


def test_munki_refuses_entities() -> None:
    with pytest.raises(ValueError):
        munki.parse(b'<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY a "b">]><plist><dict/></plist>')


# WireGuard, S/MIME, DKIM, SSH


def test_wireguard_files() -> None:
    _, bad = wireguard.inspect_data(items("wg-bad.conf"))
    assert sev(bad, "wg0-peer0-endpoint") == Severity.FAIL and sev(bad, "wg0-peer2-self") == Severity.FAIL
    cfgs, f = wireguard.inspect_data(items("wg-client.conf", "wg-server.conf"))
    assert len(cfgs) == 2 and not any("PrivateKey =" in x.detail for x in f)
    cfgs, _ = wireguard.inspect_data(items("SYNTHETIC-pfsense-wireguard-export.xml"))
    assert cfgs


def _smime(n: str, **kw: object) -> list[Finding]:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    from certcheck.x509info import parse_cert

    c = x509.load_pem_x509_certificate((FX / f"SYNTHETIC-smime-{n}.pem").read_bytes())
    return smime.inspect(parse_cert(c.public_bytes(Encoding.DER)), now=NOW, **kw)  # type: ignore[arg-type]


def test_smime() -> None:
    assert sev(_smime("good"), "smime-eku") == Severity.PASS
    assert sev(_smime("good", address="nobody@example.test"), "smime-address") == Severity.FAIL
    assert sev(_smime("server"), "smime-eku") == Severity.FAIL
    assert sev(_smime("weak"), "smime-key") in (Severity.FAIL, Severity.WARNING)


def test_dkim() -> None:
    r = dkim.record_file((FX / "SYNTHETIC-dkim-2048.txt").read_bytes())
    assert (
        sev(dkim.inspect(r, dkim.private_key_public_half((FX / "SYNTHETIC-dkim-2048.key").read_bytes())), "dkim-match")
        == Severity.PASS
    )
    assert (
        sev(dkim.inspect(r, dkim.private_key_public_half((FX / "SYNTHETIC-dkim-1024.key").read_bytes())), "dkim-match")
        == Severity.FAIL
    )
    assert (
        sev(dkim.inspect(dkim.record_file((FX / "SYNTHETIC-dkim-revoked.txt").read_bytes())), "dkim-revoked")
        == Severity.WARNING
    )
    for bad in ["v=DKIM1; k=rsa", "v=DKIM1; p=!!!", "p=AA; p=BB"]:
        with pytest.raises(ValueError):
            dkim.parse(bad)
    assert sev(dkim.inspect(dkim.parse("v=DKIM2; p=")), "dkim-version") == Severity.FAIL
    assert sev(dkim.inspect(dkim.parse("k=dsa; p=AAAA")), "dkim-type") == Severity.FAIL


def test_ssh_host_keys() -> None:
    keys = ssh_hostkeys.parse_host_keys((FX / "SYNTHETIC-ssh-host.pub").read_text())
    assert keys
    line = f"host1.example.test {keys[0].type} " + __import__("base64").b64encode(bytes(keys[0].blob)).decode()
    f = ssh_hostkeys.inspect(keys, ssh_hostkeys.parse_known_hosts(line), "host1.example.test")
    assert sev(f, "ssh-known") in (Severity.PASS, Severity.WARNING)
    weak = ssh_hostkeys.inspect(
        ssh_hostkeys.parse_host_keys((FX / "SYNTHETIC-ssh-rsa1024.pub").read_text()), None, None
    )
    assert any(x.severity == Severity.FAIL for x in weak)
    assert ssh_hostkeys.host_token("H.example.test", 2222) == "[h.example.test]:2222"


# FileCheck: PKCS#7, PFX/P12, encrypted keys


def test_pkcs7_bundle() -> None:
    from certcheck import analysis

    certs = filecheck.pkcs7_certificates((FX / "bundle.p7b").read_bytes())
    assert len(certs) == 3
    o = analysis.ordered_chain(certs)
    assert o[0].is_ca is not True and all(c.is_ca for c in o[1:]) and o[-1].issuer == o[-1].subject
    assert all(a.issuer == b.subject for a, b in zip(o, o[1:], strict=False))


def test_pfx_in_memory() -> None:
    r = filecheck.inspect_data(items("leaf.p12"), None, Purpose.TLS_SERVER, password="fixture-only")
    assert len(r.certificates) == 2 and sev(r.findings, "keymatch-0") == Severity.PASS
    bad = filecheck.inspect_data(items("leaf.p12"), None, Purpose.TLS_SERVER, password="wrong")
    assert not bad.certificates
    assert any(x.severity == Severity.FAIL and "password" in x.detail for x in bad.findings)
    assert "wrong" not in "".join(x.title + x.detail for x in bad.findings)


def test_encrypted_key_is_reported_not_opened() -> None:
    r = filecheck.inspect_data(items("encrypted.key"), None, Purpose.TLS_SERVER)
    assert any(x.severity == Severity.FAIL for x in r.findings) and not r.keys


def test_gitleaks_encoded_key_blocks() -> None:
    """gitleaks 8.30+ decodes base64 and reports the 6 keys inside pfSense <prv> fields; the allowlist tool sees
    the same blocks (and no PEM block), so the file is pinned as encoded-only."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gitleaks_allowlist", shared_dir() / "tools" / "gitleaks_allowlist.py"
    )
    assert spec and spec.loader
    gl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gl)
    p = FX / "SYNTHETIC-pfsense-2.7-config.xml"
    assert len(gl.encoded_key_blocks(p.read_bytes())) == 6 and gl.encoded_only(p)
    assert not gl.encoded_key_blocks((FX / "leaf.key").read_bytes())


# Review B2 / S1 / S5: deep and DTD-bearing XML fails closed


def deep_xml(depth: int = 300_000) -> bytes:
    return b'<?xml version="1.0"?><pfsense>' + b"<a>" * depth + b"</a>" * depth + b"</pfsense>"


def test_ipsec_and_wireguard_refuse_300k_deep_xml() -> None:
    r = ipsec.inspect_data([("deep.xml", deep_xml())], now=NOW)
    note = next(x for x in r.findings if x.id == "parse-deep.xml")
    assert note.severity == Severity.FAIL and "deeper" in note.detail
    _, ns = wireguard.inspect_data([("deep.xml", deep_xml())])
    assert ns[0].id == "wg-read-deep.xml" and ns[0].severity == Severity.FAIL


def test_with_ancestors_is_iterative() -> None:
    import xml.etree.ElementTree as ET

    root = ET.Element("pfsense")
    n = root
    for _ in range(300_000):
        n = ET.SubElement(n, "a")
    ET.SubElement(n, "cert")
    ET.SubElement(ET.SubElement(root, "ca"), "cert")  # inside the excluded <ca>: not returned
    got = ipsec._with_ancestors(root, "cert", "ca")
    assert len(got) == 1
    for i in range(300_000):  # unlink iteratively so teardown cannot recurse either
        nxt = list(n)
        n.clear()
        del nxt
        if i > 10:
            break
    root.clear()


def test_recursion_error_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> None:
        raise RecursionError

    monkeypatch.setattr(ipsec, "pfsense", boom)
    r = ipsec.inspect_data([("x.xml", b"<?xml version='1.0'?><pfsense/>")], now=NOW)
    assert any(x.id == "parse-x.xml" and x.severity == Severity.FAIL for x in r.findings)
    monkeypatch.setattr(wireguard, "pfsense", boom)
    assert wireguard.inspect_data([("x.xml", b"<?xml version='1.0'?><pfsense/>")])[1][0].severity == Severity.FAIL


def test_dtd_refused_at_expat_level() -> None:
    # UTF-16 hides "<!DOCTYPE" from the byte-level check; expat still sees it and the handler refuses it.
    doc = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE p [<!ENTITY e "x">]><pfsense>&e;</pfsense>'
    data = doc.encode("utf-16")
    with pytest.raises(ValueError, match="DOCTYPE"):
        wireguard.parse_xml(data)
    r = ipsec.inspect_data([("u16.xml", data)], now=NOW)
    assert any(x.id == "parse-u16.xml" and "DOCTYPE" in x.detail for x in r.findings)


@pytest.mark.parametrize(
    "decl",
    [
        b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://example.test/x.dtd">',
        b"<!DOCTYPE plist>",
        b"<!DOCTYPE plist [<!ELEMENT plist ANY>]>",
        b'<!ENTITY e "x">',
    ],
)
def test_munki_refuses_doctype_or_entity(decl: bytes) -> None:
    body = b'<?xml version="1.0"?>' + decl + b'<plist version="1.0"><dict></dict></plist>'
    with pytest.raises(ValueError):
        munki.parse(body)


# Review S2 / S6: PKCS#12 iteration cap and corrupt-vs-password


def _p12(rounds: int) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import PrivateFormat, pkcs12

    k, c, _ = pkcs12.load_key_and_certificates((FX / "leaf.p12").read_bytes(), b"fixture-only")
    enc = (
        PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(rounds)
        .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
        .hmac_hash(hashes.SHA256())
        .build(b"SYNTH-pw")
    )
    return pkcs12.serialize_key_and_certificates(b"x", k, c, None, enc)


def test_pfx_iteration_cap_read_before_decrypting(monkeypatch: pytest.MonkeyPatch) -> None:

    data = _p12(100_000)
    assert 100_000 in pfx.read_params(data).iterations
    huge = data.replace(bytes.fromhex("02030186a0"), bytes.fromhex("02037f0000"))  # 100000 -> 8323072
    assert max(pfx.read_params(huge).iterations) == 0x7F0000
    called = []
    monkeypatch.setattr(filecheck, "_pkcs12_worker", lambda *a: called.append(1))
    r = filecheck.inspect_data([("huge.p12", huge)], None, Purpose.TLS_SERVER, password="SYNTH-pw")
    assert any("iterations" in x.detail and x.severity == Severity.FAIL for x in r.findings)
    assert not called, "refused before cryptography decrypts anything"


def test_pfx_corrupt_vs_wrong_password() -> None:
    good = (FX / "leaf.p12").read_bytes()

    def detail(data: bytes, pw: str) -> str:
        r = filecheck.inspect_data([("t.p12", data)], None, Purpose.TLS_SERVER, password=pw)
        want = (filecheck.PFX_PASSWORD, filecheck.PFX_CORRUPT)
        return next(x.detail for x in r.findings if x.severity == Severity.FAIL and x.detail in want)

    assert detail(good, "wrong") == filecheck.PFX_PASSWORD
    assert detail(good[:300], "fixture-only") == filecheck.PFX_CORRUPT  # truncated DER
    assert detail(b"\x30\x03\x02\x01\x03", "x") == filecheck.PFX_CORRUPT
    p = pfx.read_params(good)
    assert pfx.mac_matches(p, "fixture-only") is True and pfx.mac_matches(p, "wrong") is False


# Review S4: anchors outside the chain and keyCertSign


def test_chaincheck_outside_anchor_path_len_and_key_cert_sign() -> None:
    import dataclasses

    rep = filecheck.FileReport()
    for n, d in items("ipsec-plleaf.crt", "ipsec-plint.crt", "ipsec-pl0-root.crt"):
        filecheck.load(n, d, rep)
    leaf, inter, root = rep.certificates
    # The pathlen:0 root is not sent but given as anchor: it still forbids the intermediate below it.
    ok, why = chaincheck.verify([leaf, inter], NOW, [root])
    assert not ok and "anchor" in why and "pathLenConstraint" in why
    assert chaincheck.verify([inter], NOW, [root])[0]
    no_sign = dataclasses.replace(root, key_usage_bits=bytes([0x80]))  # digitalSignature only
    ok, why = chaincheck.verify([inter, no_sign], NOW)
    assert not ok and "keyCertSign" in why
    ok, why = chaincheck.verify([inter], NOW, [no_sign])
    assert not ok and "anchor" in why
    assert chaincheck.cert_sign_allowed(dataclasses.replace(root, key_usage_bits=None))


def test_pfx_decryption_has_a_time_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    # Review M3c: counts inside encrypted SafeContents are invisible to read_params (simulated here by hiding
    # all of them), so decryption runs in a worker that is killed at PFX_TIME_BUDGET_S.
    slow = _p12(999_999)
    monkeypatch.setattr(pfx, "read_params", lambda d: pfx.Params(iterations=[], mac=None))
    monkeypatch.setattr(filecheck, "PFX_TIME_BUDGET_S", 0.5)
    # Stand-in for a decryption that never ends (real inner counts are machine-speed dependent): the worker
    # reads its input and then hangs; it must be killed at the budget.
    monkeypatch.setattr(filecheck, "_WORKER_CODE", "import sys, time; sys.stdin.buffer.read(); time.sleep(60)")
    start = time.monotonic()
    r = filecheck.inspect_data([("slow.p12", slow)], None, Purpose.TLS_SERVER, password="SYNTH-pw")
    assert time.monotonic() - start < 3
    assert any(x.detail == filecheck.PFX_TIMEOUT and x.severity == Severity.FAIL for x in r.findings)
    assert not r.certificates


def test_pfx_worker_opens_fixture_within_budget() -> None:
    r = filecheck.inspect_data(items("leaf.p12"), None, Purpose.TLS_SERVER, password="fixture-only")
    assert len(r.certificates) == 2 and r.keys and "fixture-only" not in repr(r.findings)


# M3c: munki DTD check sees through BOMs and UTF-16/32

_STD = b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'


@pytest.mark.parametrize("enc", ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-8-sig"])
@pytest.mark.parametrize(
    "decl", ['<!DOCTYPE plist [<!ENTITY e "x">]>', '<!DOCTYPE plist SYSTEM "http://example.test/x.dtd">']
)
def test_munki_refuses_dtd_in_any_encoding(enc: str, decl: str) -> None:
    name = enc.replace("-sig", "").upper()
    body = f'<?xml version="1.0" encoding="{name}"?>{decl}<plist version="1.0"><dict/></plist>'.encode(enc)
    assert munki.xml_text(body).lstrip("\ufeff").startswith("<?xml")
    with pytest.raises(ValueError, match="Not a ManagedInstalls"):
        munki.parse(body)


def test_munki_standard_doctype_still_read_with_utf8_bom() -> None:
    data = (FX / "SYNTHETIC-ManagedInstalls.plist").read_bytes()
    assert _STD in data
    assert munki.parse(b"\xef\xbb\xbf" + data).repo_url == munki.parse(data).repo_url
