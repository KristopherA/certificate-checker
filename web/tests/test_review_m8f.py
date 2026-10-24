"""M8f: no container registry. No workflow may publish images or hold registry or OIDC permissions."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
GITHUB = ROOT / ".github"


def _workflow_files() -> list[Path]:
    if not WORKFLOWS.is_dir():
        pytest.skip(f"{WORKFLOWS} not in this layout")
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def _permissions(doc: dict[Any, Any]) -> list[Any]:
    perms = [doc.get("permissions")]
    perms += [job.get("permissions") for job in doc.get("jobs", {}).values()]
    return [p for p in perms if p is not None]


BANNED = (
    re.compile(r"packages\s*:\s*write"),
    re.compile(r"id-token\s*:\s*write"),
    re.compile(r"docker\s+login|docker/login-action"),
    re.compile(r"docker\s+(?:image\s+)?push|buildx\s+.*--push"),
    re.compile(r"\bpush\s*:\s*['\"]?true\b", re.IGNORECASE),
    re.compile(r"type\s*=\s*registry"),
    re.compile(r"type\s*=\s*image\b[^\n]*push\s*=\s*true"),
    re.compile(r"\b(?:podman\s+push|skopeo\s+copy|oras\s+push)\b"),
    re.compile(r"ghcr\.io", re.IGNORECASE),
    re.compile(r"\b(?:cosign|crane)\b"),
    re.compile(r"environment\s*:\s*release"),
)


def offences(text: str) -> list[str]:
    joined = re.sub(r"\\[ \t]*\r?\n", " ", text)  # shell line continuations: one logical line
    return [b.pattern for b in BANNED if b.search(joined)]


def _uses_problem(uses: str) -> str | None:
    """No docker:// images, no local ./ or ../ actions, and a full 40-hex commit SHA."""
    if uses.startswith("docker://"):
        return "docker:// image"
    if uses.startswith("./") or uses.startswith("../"):
        return "local action"
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}", uses):
        return "not pinned to a commit SHA"
    return None


def _all_uses(doc: dict[Any, Any]) -> list[str]:
    out: list[str] = []
    for job in doc.get("jobs", {}).values():
        if "uses" in job:  # reusable workflow call
            out.append(str(job["uses"]))
        out += [str(s["uses"]) for s in job.get("steps", []) if "uses" in s]
    return out


def test_every_uses_is_pinned_and_remote() -> None:
    problems = []
    for p in _workflow_files():
        for uses in _all_uses(yaml.safe_load(p.read_text())):
            if (why := _uses_problem(uses)) is not None:
                problems.append(f"{p.name}: {uses}: {why}")
    assert not problems, problems


@pytest.mark.parametrize(
    "uses",
    ["docker://alpine:3", "docker://alpine@sha256:" + "0" * 64, "./.github/actions/x", "../x", "actions/checkout@v7"],
)
def test_uses_check_rejects_docker_local_and_unpinned(uses: str) -> None:
    assert _uses_problem(uses) is not None


def test_uses_check_accepts_a_pinned_action() -> None:
    assert _uses_problem("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1") is None


def test_every_workflow_declares_top_level_permissions() -> None:
    for p in _workflow_files():
        assert "permissions" in yaml.safe_load(p.read_text()), p.name


def test_web_trivy_is_checksum_pinned_without_trivy_action() -> None:
    p = WORKFLOWS / "web.yml"
    if not p.exists():
        pytest.skip(f"{p} not in this layout")
    web = p.read_text()
    assert "aquasecurity/trivy-action" not in web and "setup-trivy" not in web
    assert re.findall(r'TRIVY_SHA256: "([0-9a-f]{64})"', web)
    assert web.count("sha256sum -c -") == 2  # gitleaks, trivy


def test_no_workflow_can_publish_images() -> None:
    files = [p for p in GITHUB.rglob("*") if p.is_file()] if GITHUB.is_dir() else []
    if not files:
        pytest.skip(f"{GITHUB} not in this layout")
    hits = {str(p.relative_to(ROOT)): o for p in files if (o := offences(p.read_text(errors="replace")))}
    assert not hits, hits


def test_no_release_workflow() -> None:
    names = [p.name for p in _workflow_files()]
    assert "web-release.yml" not in names
    assert not (ROOT / "web" / "docker" / "RELEASE.md").exists()


def test_workflow_permissions_are_read_only() -> None:
    for p in _workflow_files():
        doc = yaml.safe_load(p.read_text())
        for perms in _permissions(doc):
            if isinstance(perms, str):
                assert perms in ("read-all", "{}"), (p.name, perms)
                continue
            for scope, level in perms.items():
                assert level in ("read", "none"), (p.name, scope, level)


def test_no_tag_triggers() -> None:
    for p in _workflow_files():
        on = yaml.safe_load(p.read_text())[True]  # PyYAML reads the key "on" as True
        push = on.get("push") if isinstance(on, dict) else None
        assert not (isinstance(push, dict) and "tags" in push), p.name


def test_web_image_builds_are_not_pushed() -> None:
    p = WORKFLOWS / "web.yml"
    if not p.exists():
        pytest.skip(f"{p} not in this layout")
    doc = yaml.safe_load(p.read_text())
    builds = [s for j in doc["jobs"].values() for s in j.get("steps", []) if "build-push-action" in s.get("uses", "")]
    assert builds
    for s in builds:
        assert s["with"].get("push") is False, s.get("name")


def test_web_trivy_step_is_strict() -> None:
    p = WORKFLOWS / "web.yml"
    if not p.exists():
        pytest.skip(f"{p} not in this layout")
    web = yaml.safe_load(p.read_text())
    runs = [s["run"] for j in web["jobs"].values() for s in j.get("steps", []) if 'trivy" image' in s.get("run", "")]
    assert runs and all(r.lstrip().startswith("set -euo pipefail") for r in runs)


@pytest.mark.parametrize(
    "text",
    [
        "permissions:\n  packages: write",
        "permissions:\n  id-token: write",
        "run: docker login ghcr.example.test",
        "uses: docker/login-action@0123",
        "run: docker push certcheck-web:local",
        "run: docker buildx build --push .",
        "image: GHCR.io/x/y",
        "run: cosign sign x",
        "environment: release",
        "with:\n  push: true",
        "with:\n  push: 'true'",
        "outputs: type=registry,name=x",
        "outputs: type=image,name=x,push=true",
        "run: |\n  docker buildx build \\\n    --platform linux/amd64 \\\n    --push .",
        "run: podman push x",
        "run: skopeo copy oci:x docker://y",
        "run: oras push x f",
    ],
)
def test_offence_check_catches(text: str) -> None:
    assert offences(text)


def test_offence_check_allows_current_build() -> None:
    assert not offences("uses: docker/build-push-action@0123\nwith:\n  push: false\npermissions:\n  contents: read")
