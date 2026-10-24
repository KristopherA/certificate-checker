"""Golden parity for the service adjusters (Remote/Appliance/Stack/Vendor) on shared/fixtures/adjust.

The Mac golden (shared/golden/adjust) runs Analysis, Trust (no network, system store) and the four adjusters
offline with no TLS version. Web runs probe.assess with the same inputs; tlsver is dropped on the web side
because the Mac recorder never adds it. Differences must be listed under adjust_differences in
known-differences.yaml, and stale entries fail.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from certcheck import probe
from certcheck.services import Service
from certcheck.shared import shared_dir
from certcheck.x509info import parse_cert

FX = shared_dir() / "fixtures" / "adjust"
GOLDEN = shared_dir() / "golden" / "adjust"
MANIFEST: dict[str, Any] = json.loads((FX / "cases.json").read_text("utf-8"))
NOW = dt.datetime.fromisoformat(MANIFEST["pinned_now"].replace("Z", "+00:00"))
KNOWN: dict[str, Any] = yaml.safe_load((shared_dir() / "known-differences.yaml").read_text("utf-8"))
CASES = {c["name"]: c for c in MANIFEST["cases"]}


def pem_ders(path: Path) -> list[bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    return [c.public_bytes(Encoding.DER) for c in x509.load_pem_x509_certificates(path.read_bytes())]


def web_keys(c: dict[str, Any]) -> set[tuple[str, str, str]]:
    chain = [parse_cert(d) for f in c["files"] for d in pem_ders(FX / f)]
    svc = Service(c["service"])
    t = probe.Target(host=c["hostname"], port=svc.default_port, service=svc, fingerprint_pin=c.get("fingerprint_pin"))
    _, f = probe.assess(chain, t, tls_version=None, now=NOW)
    return {x.key() for x in f if x.id != "tlsver"}


def test_every_case_has_a_golden() -> None:
    assert sorted(p.stem for p in GOLDEN.glob("*.json")) == sorted(CASES)


@pytest.mark.parametrize("name", sorted(CASES))
def test_adjusted_findings_match_golden(name: str) -> None:
    c = CASES[name]
    g = json.loads((GOLDEN / f"{name}.json").read_text("utf-8"))
    assert g["service"] == c["service"] and g["hostname"] == c["hostname"]
    mac = {(f["id"], f["severity"], f["topic"]) for f in g["findings"]}
    web = web_keys(c)
    d = next((x for x in KNOWN.get("adjust_differences", []) if x["case"] == name), None)
    if d is None:
        assert sorted(web) == sorted(mac), f"{name}: mac-only {sorted(mac - web)}, web-only {sorted(web - mac)}"
    else:
        assert sorted(mac - web) == sorted(tuple(k) for k in d["mac"]), f"{name}: update known-differences.yaml"
        assert sorted(web - mac) == sorted(tuple(k) for k in d["web"]), f"{name}: update known-differences.yaml"


def test_no_stale_adjust_differences() -> None:
    for d in KNOWN.get("adjust_differences", []):
        assert d["case"] in CASES, f"known-differences.yaml lists unknown adjust case {d['case']}"
