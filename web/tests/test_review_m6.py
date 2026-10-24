"""Review M6 suggestions folded into M7: RateLimit cap, /config/ca symlink and size refusal, password-hash file
mode warning, AEAD-only listener context, dummy verify for empty or overlong passwords."""

from __future__ import annotations

import logging
import os
import ssl
import time
from pathlib import Path

import pytest
from m4_pki import issue

from app import auth, cabundle
from app.settings import password_hash
from certcheck import listener

HASH = auth.hash_password("correct horse battery staple")


def test_rate_limit_is_bounded_for_fresh_peers() -> None:
    now = [0.0]
    rl = auth.RateLimit(5, clock=lambda: now[0])
    for i in range(auth.MAX_TRACKED * 3):  # every peer is fresh and active within the same minute
        now[0] += 0.001
        assert rl.take(f"10.0.{i // 256}.{i % 256}#{i}") == 0
        assert len(rl._log) <= auth.MAX_TRACKED + 1
    # the newest peer survives a purge, and its window still counts
    rl2 = auth.RateLimit(1, clock=lambda: now[0])
    for i in range(auth.MAX_TRACKED + 1):
        rl2.take(f"p{i}")
    assert rl2.take(f"p{auth.MAX_TRACKED}") > 0


def test_cabundle_refuses_symlinks(tmp_path: Path) -> None:
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    real = tmp_path / "elsewhere.pem"
    real.write_bytes(issue("Internal Link CA", ca=True).pem)
    (ca_dir / "link.pem").symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        cabundle.build(ca_dir)
    (ca_dir / "link.pem").unlink()
    (ca_dir / "dangling.crt").symlink_to(tmp_path / "missing.crt")
    with pytest.raises(ValueError, match="symlink"):
        cabundle.build(ca_dir)


def test_cabundle_caps_file_size(tmp_path: Path) -> None:
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    pem = issue("Internal Big CA", ca=True).pem
    (ca_dir / "big.pem").write_bytes(pem * (cabundle.MAX_CA_FILE // len(pem) + 2))
    with pytest.raises(ValueError, match="larger than"):
        cabundle.build(ca_dir)
    (ca_dir / "big.pem").write_bytes(pem)
    built = cabundle.build(ca_dir)
    assert built
    import shutil

    shutil.rmtree(built[1])


def test_cabundle_skips_fifo_without_blocking(tmp_path: Path) -> None:
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    os.mkfifo(ca_dir / "pipe.pem")
    assert cabundle.build(ca_dir) is None  # not a regular file: skipped, never opened


@pytest.mark.parametrize(("mode", "warns"), [(0o600, False), (0o400, False), (0o640, True), (0o644, True)])
def test_hash_file_mode_warning(tmp_path: Path, caplog: pytest.LogCaptureFixture, mode: int, warns: bool) -> None:
    f = tmp_path / "hash"
    f.write_text(HASH)
    f.chmod(mode)
    with caplog.at_level(logging.WARNING, logger="certcheck.settings"):
        assert password_hash({"CERTCHECK_PASSWORD_HASH_FILE": str(f)}) == HASH
    assert any("readable by group or other" in r.getMessage() for r in caplog.records) is warns
    assert all(HASH not in r.getMessage() for r in caplog.records)


def test_listener_context_is_aead_only(tmp_path: Path) -> None:
    leaf = issue("ui.example.test")
    (tmp_path / "c.pem").write_bytes(leaf.pem)
    (tmp_path / "k.pem").write_bytes(leaf.key_pem())
    ctx = listener.server_context(tmp_path / "c.pem", tmp_path / "k.pem")
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    for c in ctx.get_ciphers():
        assert c["aead"], c["name"]
        if c["protocol"] == "TLSv1.2":
            assert c["kea"] == "kx-ecdhe", c["name"]


def test_dummy_verify_for_empty_and_overlong() -> None:
    def t(pw: str) -> float:
        start = time.perf_counter()
        assert auth.verify_password(HASH, pw) is False
        return time.perf_counter() - start

    t("")  # make the dummy hash
    wrong = min(t("wrong password") for _ in range(3))
    for pw in ("", "x" * (auth.MAX_PASSWORD + 1)):
        assert min(t(pw) for _ in range(3)) > wrong * 0.3, pw  # same order of cost, not an instant return
    assert auth.verify_password(HASH, "correct horse battery staple")
