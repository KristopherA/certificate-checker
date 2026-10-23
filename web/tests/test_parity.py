"""Golden parity: the web engine must reproduce the Mac verdicts on id, severity and topic."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import pytest
import yaml

from certcheck import filecheck, trust
from certcheck.model import Purpose
from certcheck.shared import load_golden, load_manifest, shared_dir

MANIFEST = load_manifest()
CASES = [c["name"] for c in MANIFEST["cases"]]
CA = shared_dir() / "fixtures" / "ca"
KNOWN: dict[str, Any] = yaml.safe_load((shared_dir() / "known-differences.yaml").read_text("utf-8"))
NOW = dt.datetime.fromisoformat(MANIFEST["pinned_now"].replace("Z", "+00:00"))


def case(name: str) -> dict[str, Any]:
    c: dict[str, Any] = next(c for c in MANIFEST["cases"] if c["name"] == name)
    return c


def purpose(c: dict[str, Any]) -> Purpose:
    return Purpose.TLS_CLIENT if c["purpose"] == "client" else Purpose.TLS_SERVER


def paths(c: dict[str, Any]) -> list[Path]:
    return [CA / "cases" / c["name"] / f for f in c["files"]]


def known(name: str, check: str) -> dict[str, Any] | None:
    return next((d for d in KNOWN["fixture_differences"] if d["case"] == name and d["check"] == check), None)


@pytest.mark.parametrize("name", CASES)
def test_findings_match_golden(name: str) -> None:
    c = case(name)
    r = filecheck.inspect(paths(c), c["hostname"], purpose(c), now=NOW)
    web = {f.key() for f in r.findings}
    mac = {(f["id"], f["severity"], f["topic"]) for f in load_golden(name)["findings"]}
    d = known(name, "findings")
    if d is None:
        assert sorted(web) == sorted(mac)
    else:
        # mac/web list exactly the keys only that side produces; stale or partial entries fail.
        assert sorted(mac - web) == sorted(tuple(k) for k in d["mac"]), f"{name}: update known-differences.yaml"
        assert sorted(web - mac) == sorted(tuple(k) for k in d["web"]), f"{name}: update known-differences.yaml"


@pytest.mark.parametrize("name", CASES)
def test_chain_matches_golden(name: str) -> None:
    """Same chain, same order, same validity dates (catches goldens recorded from other fixtures)."""
    c = case(name)
    g = load_golden(name)
    chain = filecheck.inspect(paths(c), c["hostname"], purpose(c), now=NOW).chain
    assert [x.sha256 for x in chain] == g["chain_sha256"]
    iso = [
        {
            "not_before": x.not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_after": x.not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        for x in chain
    ]
    assert iso == g["chain_validity"]


@pytest.mark.parametrize("name", CASES)
def test_fixture_anchor_trust_matches_golden(name: str) -> None:
    c = case(name)
    chain = filecheck.inspect(paths(c), c["hostname"], purpose(c), now=NOW).chain
    web = trust.verify(chain, hostname=c["hostname"], purpose=purpose(c), now=NOW, anchors=CA / "root.pem").trusted
    mac = load_golden(name)["trust_fixture_anchor"]["trusted"]
    d = known(name, "trust_fixture_anchor")
    if d is None:
        assert web == mac, f"{name}: web {web}, mac {mac}; fix trust.py or record it in known-differences.yaml"
    else:
        assert (d["mac"], d["web"]) == (mac, web), f"{name}: known difference no longer matches; update the yaml"


def test_known_differences_name_real_cases() -> None:
    for d in KNOWN["fixture_differences"]:
        assert d["case"] in CASES and d["check"] in ("findings", "trust_fixture_anchor") and d["reason"].strip()
        assert "mac" in d and "web" in d, d
        if d["check"] == "findings":
            assert d["mac"] or d["web"], d
            assert all(len(k) == 3 for k in d["mac"] + d["web"]), d
