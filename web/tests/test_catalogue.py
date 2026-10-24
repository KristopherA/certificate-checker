from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from certcheck.shared import SEVERITIES, load_catalogue, load_web_catalogue


def test_catalogue_loads_and_is_consistent() -> None:
    cat = load_catalogue()
    assert len(cat.entries) > 250
    for e in cat.entries:
        assert e.severity in SEVERITIES
        assert e.id and e.title
        assert e.topic in cat.topics, e
    keys = [(e.id, e.severity, e.topic, e.title) for e in cat.entries]
    assert len(keys) == len(set(keys))


def test_core_analysis_ids_present() -> None:
    ids = {e.id for e in load_catalogue().entries}
    for needed in (
        "exp-{i}",
        "nb-{i}",
        "sig-{i}",
        "key-{i}",
        "keymatch-{k}",
        "eku",
        "san",
        "host",
        "lifetime",
        "ca-leaf",
        "order",
    ):
        assert needed in ids, needed


def test_mac_only_findings_flagged() -> None:
    cat = load_catalogue()
    assert any(e.mac_only and e.kind == "codesign" for e in cat.entries)
    assert not any(e.mac_only for e in cat.entries if e.source == "Core/Analysis.swift")


def swift_root_module(shared: Path) -> ModuleType:
    """shared/tools/swift_root.py, the one root finder the tools share."""
    spec = importlib.util.spec_from_file_location("swift_root", shared / "tools" / "swift_root.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_swift_root_both_layouts(shared: Path, tmp_path: Path) -> None:
    find = swift_root_module(shared).find_swift_root
    public, working, neither, both = (tmp_path / n for n in ("public", "working", "neither", "both"))
    (public / "Sources").mkdir(parents=True)
    (working / "Source" / "Sources").mkdir(parents=True)
    neither.mkdir()
    (both / "Sources").mkdir(parents=True)
    (both / "Source" / "Sources").mkdir(parents=True)
    assert find(public) == public.resolve()
    assert find(working) == (working / "Source").resolve()
    assert find(neither) is None
    assert find(both) == both.resolve()  # <root>/Sources wins


def test_swift_root_refuses_symlinked_sources(shared: Path, tmp_path: Path) -> None:
    mod = swift_root_module(shared)
    real = tmp_path / "elsewhere" / "Sources"
    real.mkdir(parents=True)
    public, working = tmp_path / "public", tmp_path / "working"
    public.mkdir()
    (public / "Sources").symlink_to(real, target_is_directory=True)
    (working / "Source").mkdir(parents=True)
    (working / "Source" / "Sources").symlink_to(real, target_is_directory=True)
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "Source").symlink_to(real.parent, target_is_directory=True)
    for repo in (public, working, linked):
        with pytest.raises(mod.SymlinkedSources):
            mod.find_swift_root(repo)
        r = subprocess.run(
            [sys.executable, str(shared / "tools" / "swift_root.py"), str(repo)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert r.returncode == 1 and "symlink" in r.stderr and "Traceback" not in r.stderr


def test_export_default_path_uses_finder(shared: Path, tmp_path: Path) -> None:
    """With no arguments the exporter fails cleanly (not with a traceback) when no layout matches."""
    tools = tmp_path / "shared" / "tools"
    tools.mkdir(parents=True)
    for n in ("export_findings.py", "swift_root.py"):
        (tools / n).write_bytes((shared / "tools" / n).read_bytes())
    r = subprocess.run(
        [sys.executable, str(tools / "export_findings.py"), "--check"], capture_output=True, text=True, check=False
    )
    assert r.returncode == 1 and "no Swift sources" in r.stderr and "Traceback" not in r.stderr


def test_export_is_current(shared: Path) -> None:
    """When the Swift sources are present (public repo or working copy), findings.yaml must match a
    fresh export. Under CI a missing app folder is a failure, not a skip."""
    app = swift_root_module(shared).find_swift_root(shared.parent)
    if app is None:
        if os.environ.get("CI"):
            pytest.fail(
                "CI is set but neither Sources/ nor Source/Sources/ exists: the catalogue drift gate cannot run"
            )
        pytest.skip("Swift sources not present (neither Sources/ nor Source/Sources/)")
    sources = app / "Sources"
    r = subprocess.run(
        [
            sys.executable,
            str(shared / "tools" / "export_findings.py"),
            str(sources),
            str(shared / "findings.yaml"),
            "--check",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr


def test_ternary_findings_have_every_variant() -> None:
    """Both branches of a ternary severity/topic are catalogued (regression for the fail-open exporter)."""
    rows = {(e.id, e.severity, e.topic) for e in load_catalogue().entries}
    for row in [
        ("trust", "pass", "trust"),
        ("trust", "fail", "trust"),
        ("keymatch-{k}", "pass", "keyMismatch"),
        ("keymatch-{k}", "warning", "keyMismatch"),
        ("probe", "fail", "startTLS"),
        ("probe", "fail", "connection"),
        ("dkim-hash", "warning", "weakSignature"),
        ("dkim-hash", "fail", "weakSignature"),
        ("smime-ku-sign", "warning", "eku"),
        ("smime-ku-encrypt", "info", "eku"),
        ("waf-default", "fail", "vendor"),
        ("waf-selfsigned", "warning", "vendor"),
        ("ipsec-noserver", "fail", "ipsec"),
        ("cs-runtime", "warning", "general"),
        ("cs-notarized", "warning", "trust"),
        ("{p}empty-{field}", "fail", "wireguard"),
    ]:
        assert row in rows, row
    assert any(e.id.startswith("{pp}overlap-") for e in load_catalogue().entries)


def test_row_correlated_ternaries_are_resolved() -> None:
    """Ternaries inside interpolation are resolved per row (e.g. waf-selfsigned), not left as {…}."""
    titles = {e.title for e in load_catalogue().entries if "Barracuda" in e.title}
    assert "Barracuda management UI presents a self-signed certificate" in titles
    assert "Barracuda service presents a self-signed certificate" in titles
    assert not any("?" in t for t in titles)


def gitleaks_allowlist_module(shared: Path) -> ModuleType:
    """shared/tools/gitleaks_allowlist.py (imports swift_root from its own folder)."""
    spec = importlib.util.spec_from_file_location("gitleaks_allowlist", shared / "tools" / "gitleaks_allowlist.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_gitleaks_config_found_in_both_layouts(shared: Path, tmp_path: Path) -> None:
    """find_config sees Source/.gitleaks.toml (working copy) and <root>/.gitleaks.toml (public repo)."""
    find = gitleaks_allowlist_module(shared).find_config
    working, public, root_only = (tmp_path / n for n in ("working", "public", "root_only"))
    (working / "Source" / "Sources").mkdir(parents=True)
    (working / "Source" / ".gitleaks.toml").write_text("")
    (public / "Sources").mkdir(parents=True)
    (public / ".gitleaks.toml").write_text("")
    (root_only / "Source" / "Sources").mkdir(parents=True)
    (root_only / ".gitleaks.toml").write_text("")
    assert find(working) == (working / "Source" / ".gitleaks.toml").resolve()
    assert find(public) == public / ".gitleaks.toml" or find(public) == (public / ".gitleaks.toml").resolve()
    assert find(root_only) == root_only / ".gitleaks.toml"
    assert find(tmp_path) is None


def test_gitleaks_allowlist_matches_fixtures(shared: Path) -> None:
    """.gitleaks.toml is valid, keeps the default rules, allowlists only exact existing files, and its
    private-key list pins exactly the fixture key blocks (shared/tools/gitleaks_allowlist.py --check)."""
    if gitleaks_allowlist_module(shared).find_config(shared.parent) is None:
        if os.environ.get("CI"):
            pytest.fail("CI is set but .gitleaks.toml (Source/ or repo root) is missing: the allowlist gate cannot run")
        pytest.skip(".gitleaks.toml not present")
    app = swift_root_module(shared).find_swift_root(shared.parent)
    if app is None or not (app / "Tests" / "Fixtures").is_dir():
        if os.environ.get("CI"):
            pytest.fail("CI is set but Tests/Fixtures (repo root or Source/) is missing: the allowlist gate cannot run")
        pytest.skip("Mac app Tests/Fixtures not present (web/shared-only tree): the allowlist covers those keys")
    r = subprocess.run(
        [sys.executable, str(shared / "tools" / "gitleaks_allowlist.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr


def test_every_web_finding_id_is_catalogued() -> None:
    """Every literal Finding("id", ...) in web/certcheck has a catalogue entry (ids with {holes} match by prefix)."""
    import re

    pkg = Path(__file__).resolve().parents[1] / "certcheck"
    cat = load_catalogue().entries + load_web_catalogue()
    exact = {e.id for e in cat}
    prefixes = {e.id.split("{")[0] for e in cat if "{" in e.id}
    lit = re.compile(r'Finding\(\s*f?"([a-z0-9][a-z0-9-]*)')
    missing = set()
    for p in pkg.glob("*.py"):
        for i in lit.findall(p.read_text("utf-8")):
            if i not in exact and not any(i.startswith(x) for x in prefixes if x):
                missing.add(f"{p.name}:{i}")
    assert not missing, sorted(missing)


def test_web_only_catalogue_is_consistent() -> None:
    cat = load_catalogue()
    web = load_web_catalogue()
    swift_ids = {e.id for e in cat.entries}
    assert web and not ({e.id for e in web} & swift_ids)
    swift_prefixes = {i.split("{")[0] for i in swift_ids}
    for e in web:
        assert e.severity in SEVERITIES and e.topic in cat.topics, e
        assert e.id.split("{")[0] not in swift_prefixes, e.id
