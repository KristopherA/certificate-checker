"""Unit tests for the downgrade rule and helpers in certcheck.adjust (golden parity is in test_adjust_parity)."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from certcheck import adjust
from certcheck.model import Finding, Severity, Topic
from certcheck.services import Service
from certcheck.shared import shared_dir
from certcheck.x509info import Cert, parse_cert

FX = shared_dir() / "fixtures" / "adjust"
NOW = dt.datetime(2027, 1, 15, tzinfo=dt.UTC)


def chain(name: str) -> list[Cert]:
    return [parse_cert(c.public_bytes(Encoding.DER)) for c in x509.load_pem_x509_certificates((FX / name).read_bytes())]


@dataclass
class T:
    service: Service
    host: str
    port: int = 443
    fingerprint_pin: str | None = None

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def expected_name(self) -> str:
        return self.host


TRUST_FAIL = Finding("trust", Severity.FAIL, Topic.TRUST, "Not trusted (self-signed)")
EKU_FAIL = Finding("eku", Severity.FAIL, Topic.EKU, "No serverAuth")


def test_normalize_pin() -> None:
    plain = "ab" * 32
    assert adjust.normalize_pin(plain) == ":".join(["AB"] * 32)
    assert adjust.normalize_pin(":".join(["ab"] * 32)) == ":".join(["AB"] * 32)
    for bad in ("", "zz" * 32, "ab" * 31, "x" * 300):
        assert adjust.normalize_pin(bad) is None


def test_downgrade_rule() -> None:
    c = chain("rdp-selfsigned.pem")
    assert adjust.may_downgrade([TRUST_FAIL], c, "rdp.example.test", NOW)
    assert not adjust.may_downgrade([TRUST_FAIL], c, "other.example.test", NOW)  # SAN must cover the host
    assert not adjust.may_downgrade([TRUST_FAIL, EKU_FAIL], c, "rdp.example.test", NOW)  # never on EKU failure
    later = dt.datetime(2028, 1, 1, tzinfo=dt.UTC)
    assert not adjust.may_downgrade([TRUST_FAIL], c, "rdp.example.test", later)  # out of date
    assert not adjust.may_downgrade([TRUST_FAIL], chain("rdp-nosan.pem"), "rdp.example.test", NOW)


def test_san_covers_never_matches_ip_hosts() -> None:
    leaf = chain("SYNTHETIC-barracuda-default.pem")[0]  # SAN has IP 127.0.0.1 and DNS localhost
    assert adjust.san_covers(leaf, "localhost")
    assert not adjust.san_covers(leaf, "127.0.0.1")


def test_signatures_verify() -> None:
    assert adjust.signatures_verify(chain("winrm-cn.pem"))
    assert adjust.signatures_verify(list(reversed(chain("winrm-cn.pem"))))  # presented out of order
    leaf = chain("winrm-cn.pem")[0]
    other_ca = chain("SYNTHETIC-pve-default.pem")[1]
    assert not adjust.signatures_verify([leaf, other_ca])


def test_handshake_failure_notes() -> None:
    def ids(t: T) -> list[str]:
        return [f.id for f in adjust.handshake_failure_notes(t)]

    assert ids(T(Service.LOGSTASH_BEATS, "logstash.example.test", 5044)) == ["mtls-required"]
    assert ids(T(Service.RETROSPECT_CONSOLE, "retro.example.test", 22024)) == ["retro-port"]
    assert ids(T(Service.FILEMAKER, "fms.example.test", 5003)) == ["fms-port"]
    assert ids(T(Service.HTTPS, "www.example.test")) == []


def test_vendor_detectors() -> None:
    assert adjust.is_hp_default(chain("SYNTHETIC-hp-default.pem")[0])
    assert not adjust.is_hp_default(chain("SYNTHETIC-hpc-lookalike.pem")[0])
    assert adjust.is_filemaker_default(chain("SYNTHETIC-fms-default.pem")[0])
    assert not adjust.is_filemaker_default(chain("SYNTHETIC-fms-custom.pem")[0])
    assert adjust.is_barracuda_default(chain("SYNTHETIC-barracuda-default.pem")[0])
    assert adjust.is_retrospect_default(chain("SYNTHETIC-retrospect-default.pem")[0])
    assert adjust.is_generic_default(chain("SYNTHETIC-openssl-default.pem")[0])


# --- review B1: a forged issuer name must not unlock a downgrade ---------------------------------


def test_leaf_alone_without_its_issuer_never_verifies() -> None:
    leaf = chain("winrm-cn.pem")[0]  # CA-issued leaf, its CA not sent
    assert not leaf.is_self_issued
    assert not adjust.signatures_verify([leaf])
    for name in ("forged-synology.pem", "forged-pve.pem"):
        assert not adjust.signatures_verify(chain(name)), name


def test_supplied_anchor_completes_the_chain() -> None:
    leaf, ca = chain("winrm-cn.pem")
    assert adjust.signatures_verify([leaf], [ca])  # issuer supplied separately (CA file)
    assert adjust.signatures_verify([leaf, ca], [ca])
    assert not adjust.signatures_verify([leaf], chain("rdp-selfsigned.pem"))  # an unrelated anchor does not help
    forged = chain("forged-synology.pem")
    assert not adjust.signatures_verify(forged, chain("SYNTHETIC-dsm-default.pem"))


def test_self_signed_top_must_verify_its_own_signature() -> None:
    assert adjust.signatures_verify(chain("rdp-selfsigned.pem"))


def test_forged_issuer_still_detected_but_not_downgraded() -> None:
    """The reviewer's repro: an O=Synology Inc. (or PVE cluster CA) issuer name on a leaf for the host,
    signed by an unrelated key and sent alone. Every other rule holds (in date, DNS SAN, EKU), so only the
    signature anchor stops the FAIL -> WARNING downgrade."""
    cases = [
        ("forged-synology.pem", Service.SYNOLOGY_DSM, "nas.example.test", adjust.is_synology_default, "dsm-default"),
        ("forged-pve.pem", Service.PROXMOX_VE, "pve.example.test", adjust.is_pve_default, "pve-default"),
    ]
    for name, svc, host, detect, fid in cases:
        c = chain(name)
        assert len(c) == 1 and not c[0].is_self_issued
        assert detect(c[0]), name  # the name-only detector still fires (Mac parity: the finding is shown)
        assert all(adjust.in_date(x, NOW) for x in c) and adjust.san_covers(c[0], host)
        assert not adjust.may_downgrade([TRUST_FAIL], c, host, NOW), name
        out = adjust.appliance_adjust([TRUST_FAIL], c, T(svc, host, svc.default_port), NOW)
        keys = {f.key() for f in out}
        assert ("trust", "fail", "trust") in keys, (name, keys)
        assert any(f.id == fid for f in out), (name, keys)


def test_pinned_lone_leaf_keeps_its_note_and_its_fail() -> None:
    """Review S10: a matching pin on a lone CA-issued leaf passes with the 'sent only its own certificate'
    note in the detail, and the trust FAIL stays (the pin downgrade needs signatures_verify, so no leaf-only
    downgrade wording exists any more)."""
    c = chain("forged-pve.pem")
    t = T(Service.PROXMOX_VE, "pve.example.test", 8006, fingerprint_pin=c[0].sha256)
    out = adjust.appliance_adjust([TRUST_FAIL], c, t, NOW)
    pin = next(f for f in out if f.id == "pve-pin")
    assert pin.severity == Severity.PASS and "sent only its own certificate" in pin.detail
    tr = next(f for f in out if f.id == "trust")
    assert tr.severity == Severity.FAIL and "pin" not in tr.detail.lower()
