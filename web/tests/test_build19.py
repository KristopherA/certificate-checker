"""Mac 0.10.1 build 19 parity: no MD5/SHA-1 link is proof of issuance, and IPsec anchors only the config's own CAs."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from certcheck import chaincheck, radius
from certcheck.offline import ipsec
from certcheck.x509info import Cert, parse_cert
from tests.test_offline_parity import FX, NOW, pytestmark  # noqa: F401  (skip when the Mac fixtures are absent)


def certs(n: str) -> list[Cert]:
    assert FX is not None
    return [parse_cert(c.public_bytes(Encoding.DER)) for c in x509.load_pem_x509_certificates((FX / n).read_bytes())]


def item(n: str) -> tuple[str, bytes]:
    assert FX is not None
    return n, (FX / n).read_bytes()


def sev(findings: list, fid: str) -> str | None:  # type: ignore[type-arg]
    return next((str(f.severity.name) for f in findings if f.id == fid), None)


def test_sha1_link_fails_with_a_truthful_message() -> None:
    leaf, ca = certs("ipsec-bad.crt")[0], certs("ipsec-ca.crt")[0]
    for anchors in ((), (ca,)):
        ok, msg = chaincheck.verify([leaf, ca], NOW, anchors)
        assert not ok
        assert "SHA-1" in msg and "sha1WithRSA" in msg and "does not verify" not in msg
    rf = radius.inspect_data([item("ipsec-bad.crt"), item("ipsec-ca.crt")], "radius.example.test", now=NOW)[1]
    assert sev(rf, "rad-chain") == "FAIL"
    assert (
        sev(ipsec.inspect_data([item("ipsec-bad.crt"), item("ipsec-ca.crt")], now=NOW).findings, "srv0-chain") == "FAIL"
    )


def test_ipsec_anchors_only_the_configs_own_ca() -> None:
    leaf, roll = certs("ipsec-rollleaf.crt")[0], certs("ipsec-roll.crt")[0]
    assert not chaincheck.verify([leaf, roll], NOW)[0]
    assert chaincheck.user_supplied(roll, [roll]) and not chaincheck.user_supplied(roll, [leaf])
    assert not chaincheck.user_supplied(roll, certs("SYNTHETIC-genuine-root.pem"))
    f = ipsec.inspect_data([item("ipsec-rollleaf.crt"), item("ipsec-roll.crt")], now=NOW).findings
    assert sev(f, "srv0-chain") == "PASS" and sev(f, "srv0-chain-top") == "WARNING"
    assert sev(radius.evaluate([leaf, roll], (), None, now=NOW), "rad-chain") == "FAIL"


def test_forged_top_outside_the_config_does_not_anchor() -> None:
    c = certs("SYNTHETIC-forged-radius.pem")
    assert not chaincheck.user_supplied(c[1], certs("SYNTHETIC-genuine-root.pem"))
    assert not chaincheck.verify(c, NOW)[0]
