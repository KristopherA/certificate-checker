"""Access to the repo's shared/ tree: findings catalogue, fixture CA manifest and golden verdicts."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SEVERITIES = ("pass", "info", "warning", "fail")


def shared_dir() -> Path:
    """shared/ beside web/, or CERTCHECK_SHARED when set (e.g. inside a container)."""
    env = os.environ.get("CERTCHECK_SHARED")
    return Path(env) if env else Path(__file__).resolve().parents[2] / "shared"


@dataclass(frozen=True)
class CatalogueEntry:
    id: str
    severity: str
    topic: str
    kind: str
    title: str
    detail: str
    source: str
    mac_only: bool


@dataclass(frozen=True)
class Catalogue:
    topics: tuple[str, ...]
    entries: tuple[CatalogueEntry, ...]


def load_catalogue(path: Path | None = None) -> Catalogue:
    doc: dict[str, Any] = yaml.safe_load((path or shared_dir() / "findings.yaml").read_text(encoding="utf-8"))
    if doc.get("schema") != 1:
        raise ValueError("unsupported findings.yaml schema")
    entries = tuple(CatalogueEntry(**e) for e in doc["findings"])
    if doc.get("count") != len(entries):
        raise ValueError("findings.yaml count does not match its entries")
    return Catalogue(topics=tuple(doc["topics"]), entries=entries)


def load_manifest(root: Path | None = None) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(((root or shared_dir() / "fixtures" / "ca") / "cases.json").read_text("utf-8"))
    return data


def load_golden(case: str, root: Path | None = None) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(((root or shared_dir() / "golden") / f"{case}.json").read_text("utf-8"))
    return data
