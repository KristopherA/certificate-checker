"""M5 end to end: the served app (python -m app, uvicorn on loopback) against a real OpenSSL server in a
throw-away container (see shared/tools/integration-m5.sh).

Skipped unless the runner exports CERTCHECK_IT_M5_PORT (the server's port) and CERTCHECK_IT_M5_DIR (its
ca.pem, leaf.pem and leaf.key). The PFX password is generated here and lives only in this process and the
request; the test asserts it never appears in a response or in the server's log output.
"""

from __future__ import annotations

import os
import re
import secrets
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, load_pem_private_key, pkcs12

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m4_pki import free_port, wait_port  # noqa: E402


def _env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        pytest.skip(f"{name} not set (run shared/tools/integration-m5.sh)")
    return v


@pytest.fixture(scope="module")
def served() -> Iterator[tuple[httpx.Client, int, subprocess.Popen[bytes]]]:
    d = Path(_env("CERTCHECK_IT_M5_DIR"))
    port = free_port()
    env = {**os.environ, "CERTCHECK_PORT": str(port), "CERTCHECK_ANCHORS": str(d / "ca.pem"),
           "CERTCHECK_PROBE_ALLOW_LOOPBACK": "1", "CERTCHECK_CONFIG": str(d)}  # fmt: skip
    (d / "targets.yaml").write_text(
        f"schema: 1\ntargets:\n  - name: lab\n    host: www.example.test\n    port: {_env('CERTCHECK_IT_M5_PORT')}\n"
        "    connect_ip: 127.0.0.1\n"
    )
    p = subprocess.Popen([sys.executable, "-m", "app"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        wait_port(port, 20)
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=60) as c:
            yield c, port, p
    finally:
        p.terminate()
        p.wait(10)


def _token(c: httpx.Client, path: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', c.get(path).text)
    assert m
    return m.group(1)


def test_api_probe_real_openssl(served: tuple[httpx.Client, int, subprocess.Popen[bytes]]) -> None:
    c, _, _ = served
    port = int(_env("CERTCHECK_IT_M5_PORT"))
    d = c.post("/api/v1/check", json={"host": "www.example.test", "port": port, "resolve": "127.0.0.1"}).json()
    assert d["error"] is None and d["trust"]["trusted"], d
    assert d["connected_ip"] == "127.0.0.1" and d["tls_version"] in ("TLSv1.2", "TLSv1.3")
    assert "Test M5 CA" in d["chain"][-1]["subject"]


def test_ui_probe_and_saved_target(served: tuple[httpx.Client, int, subprocess.Popen[bytes]]) -> None:
    c, _, _ = served
    port = _env("CERTCHECK_IT_M5_PORT")
    t = _token(c, "/")
    form = {"csrf_token": t, "host": "www.example.test", "port": port, "resolve": "127.0.0.1", "revocation": "1"}
    r = c.post("/ui/check", data=form, headers={"HX-Request": "true"})
    assert r.status_code == 200 and "www.example.test" in r.text and "<html" not in r.text
    assert "default-src 'none'" in r.headers["content-security-policy"]
    r = c.post("/ui/targets/run", data={"csrf_token": _token(c, "/targets"), "name": "lab"})
    assert r.status_code == 200 and "Test M5 CA" in r.text
    assert c.post("/ui/check", data={"host": "www.example.test"}).status_code == 403  # no CSRF token
    evil = c.post(
        "/ui/check", data={"csrf_token": t, "host": "x.example.test"}, headers={"Origin": "http://evil.example"}
    )
    assert evil.status_code == 403


def test_app_refuses_to_probe_itself(served: tuple[httpx.Client, int, subprocess.Popen[bytes]]) -> None:
    c, own, _ = served
    d = c.post("/api/v1/check", json={"host": "localhost", "port": own, "resolve": "127.0.0.1"}).json()
    assert d["error"] and d["connected_ip"] is None


def test_pfx_upload_of_server_key(served: tuple[httpx.Client, int, subprocess.Popen[bytes]]) -> None:
    c, _, p = served
    d = Path(_env("CERTCHECK_IT_M5_DIR"))
    pw = secrets.token_urlsafe(18)
    key = load_pem_private_key((d / "leaf.key").read_bytes(), None)
    leaf = x509.load_pem_x509_certificate((d / "leaf.pem").read_bytes())
    ca = x509.load_pem_x509_certificate((d / "ca.pem").read_bytes())
    pfx = pkcs12.serialize_key_and_certificates(b"m5", key, leaf, [ca], BestAvailableEncryption(pw.encode()))  # type: ignore[arg-type]
    j = c.post("/api/v1/files/verify", data={"password": pw, "hostname": "www.example.test"},
               files=[("files", ("server.pfx", pfx))], headers={"X-CertCheck-Request": "1"})  # fmt: skip
    assert j.status_code == 200 and pw not in j.text
    doc = j.json()
    assert doc["chain"] and doc["trust"]["trusted"] and doc["keys"], doc
    r = c.post("/ui/files/verify", data={"csrf_token": _token(c, "/files"), "password": pw},
               files=[("files", ("server.pfx", pfx))])  # fmt: skip
    assert r.status_code == 200 and pw not in r.text
    big = c.post("/api/v1/files/verify", files=[("files", ("big.pem", b"A" * (1024 * 1024 + 1)))],
                 headers={"X-CertCheck-Request": "1"})  # fmt: skip
    assert big.status_code == 413
    p.terminate()
    out, _ = p.communicate(timeout=10)
    assert pw.encode() not in out and b"POST /api/v1/files/verify" in out
