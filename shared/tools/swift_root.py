#!/usr/bin/env python3
"""Locate the Mac app (the folder holding Sources/, Tests/, project.yml) from the repo root.

Two layouts are supported:
  public repo:   <root>/Sources, <root>/Tests, <root>/shared, <root>/web
  working copy:  <root>/Source/Sources, <root>/Source/Tests, <root>/shared, <root>/web
<root>/Sources is tried first, then <root>/Source/Sources. A symlinked Sources/ or Source/ is
refused (SymlinkedSources). Standard library only; used by
export_findings.py, record-golden.sh (via the CLI) and web/tests/test_catalogue.py.

CLI: swift_root.py [REPO_ROOT]  prints the app folder, or exits 1 with a message when neither exists.
REPO_ROOT defaults to the parent of shared/.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CANDIDATES = (".", "Source")


class SymlinkedSources(ValueError):
    """Sources/ (or the Source/ folder) is a symlink: refused, so tools never read or export another tree."""


def find_swift_root(repo: Path = REPO_ROOT) -> Path | None:
    """The app folder, or None when neither layout exists. Raises SymlinkedSources when the matching
    Sources/ or Source/ is a symlink (checked before resolving, so a link cannot redirect the tools)."""
    for rel in CANDIDATES:
        app = repo / rel
        sources = app / "Sources"
        if not sources.is_dir():
            continue
        for p in (app, sources) if rel != "." else (sources,):
            if p.is_symlink():
                raise SymlinkedSources(f"{p} is a symlink; refusing to use it as the Swift sources")
        return app.resolve()
    return None


def main(argv: list[str]) -> int:
    repo = Path(argv[0]) if argv else REPO_ROOT
    try:
        app = find_swift_root(repo)
    except SymlinkedSources as e:
        print(e, file=sys.stderr)
        return 1
    if app is None:
        print(f"no Swift sources: neither {repo}/Sources nor {repo}/Source/Sources exists", file=sys.stderr)
        return 1
    print(app)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
