from __future__ import annotations

import time
from pathlib import Path

import pytest

from certcheck import filecheck
from certcheck.model import Purpose
from certcheck.shared import shared_dir

GOOD = shared_dir() / "fixtures" / "ca" / "cases" / "good" / "chain.pem"


@pytest.mark.parametrize(
    "data",
    [
        b"-----BEGIN CERTIFICATE-----\n" * 70_000,  # repeated BEGIN, no END (was quadratic)
        (b"-----BEGIN CERTIFICATE-----\n" * 35_000) + b"-----END X-----\n",  # one far END with another label
        (b"-----BEGIN A-----\n-----END B-----\n") * 30_000,
    ],
)
def test_pem_scan_is_linear(data: bytes) -> None:
    assert len(data) <= filecheck.MAX_FILE_SIZE
    t0 = time.monotonic()
    r = filecheck.inspect_data([("x.pem", data)], None, Purpose.ANY)
    assert time.monotonic() - t0 < 1.0
    assert any(f.id == "parse-x.pem" for f in r.findings)


def test_block_cap() -> None:
    block = b"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n"
    assert len(filecheck.pem_blocks(block * filecheck.MAX_PEM_BLOCKS)) == filecheck.MAX_PEM_BLOCKS
    with pytest.raises(ValueError, match="PEM blocks"):
        filecheck.pem_blocks(block * (filecheck.MAX_PEM_BLOCKS + 1))


def test_pem_blocks_pairs_begin_with_next_end() -> None:
    data = GOOD.read_bytes()
    assert [label for label, _ in filecheck.pem_blocks(b"junk\n" + data + b"trailing")] == ["CERTIFICATE"] * 2


def test_size_limit_in_inspect_data() -> None:
    r = filecheck.inspect_data([("big.pem", b"A" * (filecheck.MAX_FILE_SIZE + 1))], None, Purpose.ANY)
    assert any(f.id == "parse-big.pem" and "2 MB" in (f.detail or "") for f in r.findings)


def test_size_limit_reads_at_most_max_plus_one(tmp_path: Path) -> None:
    p = tmp_path / "big.pem"
    p.write_bytes(b"A" * (filecheck.MAX_FILE_SIZE + 10))
    r = filecheck.inspect([p], None, Purpose.ANY)
    assert any(f.id == "read-big.pem" for f in r.findings)


def test_duplicates_removed_order_kept() -> None:
    data = GOOD.read_bytes()
    r = filecheck.inspect_data([("a.pem", data), ("b.pem", data)], None, Purpose.ANY)
    assert len(r.certificates) == 2
