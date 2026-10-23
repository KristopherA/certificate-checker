from __future__ import annotations

from pathlib import Path

import pytest

from certcheck.shared import shared_dir


@pytest.fixture(scope="session")
def shared() -> Path:
    return shared_dir()
