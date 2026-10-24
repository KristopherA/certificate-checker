"""Golden parity for the offline checks (M3) on the Mac app's own fixtures (Tests/Fixtures).

The manifest is shared/fixtures/offline/cases.json; the Mac recorder (GoldenExportTests.testRecordOfflineGolden)
writes shared/golden/offline/<case>.json. Each kind maps to one web checker with the same inputs. Differences
must be listed under offline_differences in known-differences.yaml, and stale entries fail.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from certcheck import radius
from certcheck.offline import dkim, ipsec, mtls, munki, smime, ssh_hostkeys, wireguard
from certcheck.shared import shared_dir
from certcheck.x509info import parse_cert

ROOT = shared_dir()
MANIFEST: dict[str, Any] = json.loads((ROOT / "fixtures" / "offline" / "cases.json").read_text("utf-8"))
NOW = dt.datetime.fromisoformat(MANIFEST["pinned_now"].replace("Z", "+00:00"))
GOLDEN = ROOT / "golden" / "offline"
KNOWN: dict[str, Any] = yaml.safe_load((ROOT / "known-differences.yaml").read_text("utf-8"))
CASES = {c["name"]: c for c in MANIFEST["cases"]}


def fixtures_dir() -> Path | None:
    import sys

    sys.path.insert(0, str(ROOT / "tools"))
    from swift_root import find_swift_root  # type: ignore[import-not-found]

    r = find_swift_root(ROOT.parent)
    return r / "Tests" / "Fixtures" if r else None


FX = fixtures_dir()
pytestmark = pytest.mark.skipif(FX is None, reason="Mac app Tests/Fixtures not present")


def _item(n: str) -> tuple[str, bytes]:
    assert FX is not None
    return n, (FX / n).read_bytes()


def run(c: dict[str, Any]) -> set[tuple[str, str, str]]:
    k, files = c["kind"], c.get("files", [])
    if k == "radius":
        f = radius.inspect_data([_item(n) for n in files], c["expected"], now=NOW)[1]
    elif k == "ipsec":
        f = ipsec.inspect_data([_item(n) for n in files], c["expected"], now=NOW).findings
    elif k == "mtls":
        ctx = mtls.MUNKI if c["context"] == "munki" else mtls.BEATS
        f = mtls.inspect_data([_item(n) for n in files], [_item(n) for n in c["ca"]], now=NOW, context=ctx)[1]
    elif k == "munki":
        m = munki.parse(_item(c["plist"])[1])
        opt = {x: _item(c[x]) if x in c else None for x in ("cert", "key", "ca_file")}
        f = munki.inspect(m, opt["cert"], opt["key"], opt["ca_file"], now=NOW)[1]
    elif k == "wireguard":
        f = wireguard.inspect_data([_item(n) for n in files], c["expected"])[1]
    elif k == "smime":
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        der = x509.load_pem_x509_certificates(_item(files[0])[1])[0].public_bytes(Encoding.DER)
        f = smime.inspect(parse_cert(der), c["expected"], now=NOW)
    elif k == "dkim":
        r = dkim.record_file(_item(files[0])[1])
        f = dkim.inspect(r, dkim.private_key_public_half(_item(c["key"])[1]) if "key" in c else None)
    elif k == "ssh":
        keys = ssh_hostkeys.parse_host_keys(_item(files[0])[1].decode())
        kh = ssh_hostkeys.parse_known_hosts(_item(c["known_hosts"])[1].decode()) if "known_hosts" in c else None
        f = ssh_hostkeys.inspect(keys, kh, c.get("host"), c.get("port", 22))
    else:
        raise AssertionError(f"unknown kind {k}")
    return {x.key() for x in f}


@pytest.mark.parametrize("name", sorted(CASES))
def test_web_runs(name: str) -> None:
    assert run(CASES[name])


def test_every_case_has_a_golden() -> None:
    if not GOLDEN.is_dir():
        pytest.skip("shared/golden/offline not recorded yet (run shared/tools/record-golden.sh on the Mac)")
    assert sorted(p.stem for p in GOLDEN.glob("*.json")) == sorted(CASES)


def _keys(rows: Any) -> set[tuple[str, str, str]]:
    return {(a, b, c) for a, b, c in rows}


@pytest.mark.parametrize("name", sorted(CASES))
def test_offline_findings_match_golden(name: str) -> None:
    p = GOLDEN / f"{name}.json"
    if not p.exists():
        pytest.skip("golden not recorded")
    g = json.loads(p.read_text("utf-8"))
    assert g["kind"] == CASES[name]["kind"]
    mac = {(f["id"], f["severity"], f["topic"]) for f in g["findings"]}
    web = run(CASES[name])
    d = next((x for x in KNOWN.get("offline_differences", []) if x["case"] == name), None)
    if d is None:
        assert sorted(web) == sorted(mac), f"{name}: mac-only {sorted(mac - web)}, web-only {sorted(web - mac)}"
    else:
        assert sorted(mac - web) == sorted(_keys(d["mac"])), f"{name}: mac side changed: {sorted(mac - web)}"
        assert sorted(web - mac) == sorted(_keys(d["web"])), f"{name}: web side changed: {sorted(web - mac)}"
