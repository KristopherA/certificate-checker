from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509

from certcheck.shared import SEVERITIES, load_golden, load_manifest

MANIFEST = load_manifest()
CASES = [c["name"] for c in MANIFEST["cases"]]
CA = Path(__file__).resolve().parents[2] / "shared" / "fixtures" / "ca"


def pinned() -> dt.datetime:
    return dt.datetime.fromisoformat(MANIFEST["pinned_now"].replace("Z", "+00:00"))


def test_ca_tree() -> None:
    root = x509.load_pem_x509_certificate((CA / "root.pem").read_bytes())
    inter = x509.load_pem_x509_certificate((CA / "intermediate.pem").read_bytes())
    inter.verify_directly_issued_by(root)
    for c in (root, inter):
        assert c.not_valid_before_utc <= pinned() <= c.not_valid_after_utc


@pytest.mark.parametrize("name", CASES)
def test_case_files_exist(name: str) -> None:
    case = next(c for c in MANIFEST["cases"] if c["name"] == name)
    for f in case["files"]:
        assert (CA / "cases" / name / f).is_file()
    host = case["hostname"]
    assert host.endswith(".example.test") or host.startswith("192.0.2.")


@pytest.mark.parametrize("name", CASES)
def test_golden_recorded(name: str) -> None:
    g = load_golden(name)
    assert g["schema"] == 1 and g["case"] == name and g["pinned_now"] == MANIFEST["pinned_now"]
    assert g["findings"], "every case yields findings"
    for f in g["findings"]:
        assert f["severity"] in SEVERITIES
    assert isinstance(g["trust_fixture_anchor"]["trusted"], bool)


def by_id(name: str) -> dict[str, str]:
    return {f["id"]: f["severity"] for f in load_golden(name)["findings"]}


@pytest.mark.parametrize(
    ("name", "fid", "sev"),
    [
        ("good", "host", "pass"),
        ("good", "eku", "pass"),
        ("good", "keymatch-0", "pass"),
        ("expired", "exp-0", "fail"),
        ("not-yet-valid", "nb-0", "fail"),
        ("expiring-soon", "exp-0", "warning"),
        ("weak-rsa1024", "key-0", "fail"),
        ("sha1-signature", "sig-0", "fail"),
        ("no-san", "san", "warning"),
        ("wrong-host", "host", "fail"),
        ("client-eku-only", "eku", "fail"),
        ("client-purpose", "eku", "pass"),
        ("no-eku", "eku", "info"),
        ("long-validity", "lifetime", "info"),
        ("ca-as-leaf", "ca-leaf", "warning"),
        ("key-mismatch", "keymatch-0", "fail"),
        ("wildcard", "host", "pass"),
        ("wildcard-too-deep", "host", "fail"),
        ("ip-san", "host", "pass"),
    ],
)
def test_golden_expected_verdicts(name: str, fid: str, sev: str) -> None:
    """Sanity: the recorded Mac verdicts say what each fixture was built to show."""
    assert by_id(name).get(fid) == sev


def test_fixture_anchor_trust() -> None:
    trusted = {c: load_golden(c)["trust_fixture_anchor"]["trusted"] for c in CASES}
    assert trusted["good"] and trusted["misordered"]
    for bad in ("expired", "not-yet-valid", "wrong-host", "self-signed", "leaf-only", "client-eku-only"):
        assert not trusted[bad], bad
