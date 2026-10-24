"""M7 end to end: the built image, run with the deployment hardening by shared/tools/integration-m7.sh.

Skipped unless the runner exports CERTCHECK_IT_M7_PORT (the published UI port on 127.0.0.1), CERTCHECK_IT_M7_DIR
(holding the generated login password) and CERTCHECK_IT_M7_CONTAINER, plus DOCKER_CONTEXT for the docker exec
checks. The probe target, www.example.test:4432, is an OpenSSL server on the container's private network whose
CA is trusted only through /config/ca.
"""

from __future__ import annotations

import os
import re
import socket
import ssl
import subprocess
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest


def _env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        pytest.skip(f"{name} not set (run shared/tools/integration-m7.sh)")
    return v


def _docker(*args: str) -> subprocess.CompletedProcess[str]:
    ctx = _env("DOCKER_CONTEXT")
    return subprocess.run(["docker", "--context", ctx, *args], capture_output=True, text=True, check=False, timeout=60)


def _exec(*args: str) -> subprocess.CompletedProcess[str]:
    return _docker("exec", _env("CERTCHECK_IT_M7_CONTAINER"), *args)


def _unverified() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


@pytest.fixture(scope="module")
def password() -> str:
    return (Path(_env("CERTCHECK_IT_M7_DIR")) / "password").read_text()


@pytest.fixture(scope="module")
def client(password: str) -> Iterator[httpx.Client]:
    port = int(_env("CERTCHECK_IT_M7_PORT"))
    with httpx.Client(base_url=f"https://127.0.0.1:{port}", verify=_unverified(), timeout=60) as c:
        assert c.get("/").status_code == 303
        m = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").text)
        assert m
        r = c.post("/login", data={"csrf_token": m.group(1), "password": password})
        assert r.status_code == 303 and r.headers["location"] == "/"
        yield c


def test_health_and_docker_healthcheck() -> None:
    port = int(_env("CERTCHECK_IT_M7_PORT"))
    r = httpx.get(f"https://127.0.0.1:{port}/api/v1/health", verify=_unverified(), timeout=10)
    assert r.status_code == 200
    s = _docker("inspect", "-f", "{{.State.Health.Status}}", _env("CERTCHECK_IT_M7_CONTAINER"))
    assert s.stdout.strip() == "healthy"


def test_live_probe_trusted_by_config_ca(client: httpx.Client) -> None:
    d = client.post("/api/v1/check", json={"host": "www.example.test", "port": 4432}).json()
    assert d["error"] is None, d
    assert d["trust"]["trusted"], d
    assert "Test M7 CA" in d["chain"][-1]["subject"]


def test_non_root_read_only_no_caps() -> None:
    assert _exec("id", "-u").stdout.strip() == "10001"
    assert _exec("id", "-g").stdout.strip() == "10001"
    assert _exec("touch", "/opt/certcheck/x").returncode != 0
    assert _exec("touch", "/etc/x").returncode != 0
    assert _exec("touch", "/tmp/x").returncode == 0  # noqa: S108 - the tmpfs, inside the container
    assert _exec("touch", "/data/x").returncode == 0  # the state volume
    assert _exec("touch", "/config/x").returncode != 0  # mounted read-only
    status = _exec("cat", "/proc/1/status").stdout
    for cap in ("CapEff", "CapPrm", "CapBnd"):
        m = re.search(rf"^{cap}:\s*([0-9a-f]+)$", status, re.M)
        assert m and int(m.group(1), 16) == 0, f"{cap} not empty"
    m = re.search(r"^NoNewPrivs:\s*(\d)$", status, re.M)
    assert m and m.group(1) == "1"


def _handshake(port: int, version: ssl.TLSVersion, ciphers: str = "ALL") -> str:
    ctx = _unverified()
    ctx.minimum_version = ctx.maximum_version = version
    if version <= ssl.TLSVersion.TLSv1_2:
        ctx.set_ciphers(ciphers)
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s, ctx.wrap_socket(s) as t:
        c = t.cipher()
        return f"{t.version()} {c[0] if c else ''}"


def test_tls_aead_only() -> None:
    port = int(_env("CERTCHECK_IT_M7_PORT"))
    assert _handshake(port, ssl.TLSVersion.TLSv1_3).startswith("TLSv1.3")
    got = _handshake(port, ssl.TLSVersion.TLSv1_2)
    assert got.startswith("TLSv1.2 ECDHE") and ("GCM" in got or "CHACHA20" in got), got
    with pytest.raises((ssl.SSLError, ConnectionError)):
        _handshake(port, ssl.TLSVersion.TLSv1_2, "ECDHE+AES+SHA:ECDHE+AES+SHA256:ECDHE+AES+SHA384:!AESGCM")


def test_logs_warn_on_hash_mode_and_never_show_password(client: httpx.Client, password: str) -> None:
    logs = _docker("logs", _env("CERTCHECK_IT_M7_CONTAINER"))
    out = logs.stdout + logs.stderr
    assert "readable by group or other" in out, out[-2000:]
    assert password not in out
