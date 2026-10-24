"""M6 auth and security: login, sessions, CSRF on login, lockout, rate limits, settings.yaml, LAN-only, /config/ca,
the self-signed UI certificate, and the real UI listener refusing TLS 1.0 and 1.1."""

from __future__ import annotations

import contextlib
import ipaddress
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography import x509
from fastapi.testclient import TestClient
from m4_pki import issue

from app import auth, cabundle, security, tlsboot
from app.main import create_app
from app.settings import Settings, password_hash
from certcheck import probe

WEB = Path(__file__).resolve().parents[1]
LOOP = probe.TargetPolicy(allow_loopback=True)
PW = "correct horse battery staple"
HASH = auth.hash_password(PW)
LAN = ("10.0.0.5", 50000)


def app_client(
    tmp_path: Path, peer: tuple[str, int] = LAN, base: str = "http://testserver", **kw: object
) -> TestClient:
    kw.setdefault("password_hash", HASH)
    st = Settings(config_dir=tmp_path, **kw)  # type: ignore[arg-type]
    return TestClient(create_app(st, policy=LOOP), client=peer, base_url=base, follow_redirects=False)


def csrf(c: TestClient) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").text)
    assert m
    return m.group(1)


def login(c: TestClient, pw: str = PW) -> int:
    return c.post("/login", data={"csrf_token": csrf(c), "password": pw}).status_code


# ---- password hashing ---------------------------------------------------------------------------------


def test_argon2id_and_fail_closed() -> None:
    assert HASH.startswith("$argon2id$")
    assert auth.verify_password(HASH, PW)
    assert not auth.verify_password(HASH, PW + "x")
    assert not auth.verify_password(HASH, "")
    assert not auth.verify_password(HASH, "a" * (auth.MAX_PASSWORD + 1))
    assert not auth.verify_password("not-a-hash", PW)


def test_password_hash_sources(tmp_path: Path) -> None:
    assert password_hash({"CERTCHECK_PASSWORD_HASH": HASH}) == HASH
    f = tmp_path / "h"
    f.write_text(HASH + "\n")
    assert password_hash({"CERTCHECK_PASSWORD_HASH_FILE": str(f)}) == HASH
    with pytest.raises(ValueError):
        password_hash({"CERTCHECK_PASSWORD_HASH": "plaintext"})


def test_app_refuses_to_start_without_hash(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        create_app(Settings(config_dir=tmp_path, password_hash=None), policy=LOOP)


# ---- login flow ---------------------------------------------------------------------------------------


def test_everything_but_login_and_health_needs_a_session(tmp_path: Path) -> None:
    c = app_client(tmp_path)
    assert c.get("/api/v1/health").status_code == 200
    assert c.get("/static/app.css").status_code == 200
    assert c.get("/login").status_code == 200
    r = c.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert c.get("/api/v1/openapi.json").status_code == 401
    r = c.post("/api/v1/check", json={"host": "www.example.test"}, headers={security.API_HEADER: "1"})
    assert r.status_code == 401
    r = c.get("/targets", headers={"HX-Request": "true"})
    assert r.status_code == 401 and r.headers["HX-Redirect"] == "/login"


def test_login_sets_fresh_session_and_csrf(tmp_path: Path) -> None:
    c = app_client(tmp_path, base="https://testserver", secure_cookies=True)
    before = csrf(c)
    r = c.post("/login", data={"csrf_token": before, "password": PW})
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookies = r.headers.get_list("set-cookie")
    sess = [h for h in cookies if h.startswith(auth.SESSION_COOKIE + "=")][0].lower()
    for flag in ("httponly", "secure", "samesite=strict", "path=/"):
        assert flag in sess
    assert r.cookies.get(security.CSRF_COOKIE) not in (None, before)  # rotated at login
    assert c.get("/").status_code == 200
    assert "logout" in c.get("/").text


def test_login_needs_csrf_and_right_password(tmp_path: Path) -> None:
    c = app_client(tmp_path)
    csrf(c)
    assert c.post("/login", data={"csrf_token": "forged", "password": PW}).status_code == 403
    assert login(c, "wrong password") == 401
    assert auth.SESSION_COOKIE not in c.cookies


def test_logout_ends_session(tmp_path: Path) -> None:
    c = app_client(tmp_path)
    assert login(c) == 303
    sid = c.cookies.get(auth.SESSION_COOKIE)
    assert sid
    m = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/").text)
    assert m
    assert c.post("/logout", data={"csrf_token": m.group(1)}).status_code == 303
    c.cookies.set(auth.SESSION_COOKIE, sid)  # replaying the old cookie does not work
    assert c.get("/").status_code == 303


def test_lockout_after_failures(tmp_path: Path) -> None:
    c = app_client(tmp_path, lockout_failures=3)
    assert login(c, "bad1") == 401
    assert login(c, "bad2") == 401
    r = c.post("/login", data={"csrf_token": csrf(c), "password": "bad3"})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    assert login(c) == 429  # even the right password, while locked
    other = app_client(tmp_path, peer=("10.0.0.6", 50000), lockout_failures=3)
    assert login(other) in (303, 429)


def test_lockout_unit_global_and_expiry() -> None:
    now = [0.0]
    lk = auth.Lockout(failures=2, window_s=60, lockout_s=100, clock=lambda: now[0])
    lk.fail("10.0.0.1")
    assert lk.retry_after("10.0.0.1") == 0
    lk.fail("10.0.0.1")
    assert lk.retry_after("10.0.0.1") == 100 and lk.retry_after("10.0.0.2") == 0
    now[0] = 101
    assert lk.retry_after("10.0.0.1") == 0
    for i in range(2 * auth.GLOBAL_FACTOR):
        lk.fail(f"10.0.0.{10 + i}")
    assert lk.retry_after("10.0.0.99") > 0  # spreading guesses over addresses hits the global limit


def test_sessions_idle_absolute_and_cap() -> None:
    now = [0.0]
    s = auth.Sessions(idle_s=10, max_s=25, clock=lambda: now[0])
    sid = s.create()
    assert sid not in str(s._s)  # only a hash is stored
    for t in (8, 16, 24):
        now[0] = t
        assert s.valid(sid)
    now[0] = 26
    assert not s.valid(sid)  # absolute lifetime
    sid = s.create()
    now[0] = 37
    assert not s.valid(sid)  # idle
    for _ in range(auth.MAX_SESSIONS + 5):
        s.create()
    assert len(s) == auth.MAX_SESSIONS
    assert not s.valid(None) and not s.valid("x" * 100)


def test_rate_limit_unit() -> None:
    now = [0.0]
    rl = auth.RateLimit(2, clock=lambda: now[0])
    assert rl.take("a") == 0 and rl.take("a") == 0
    assert rl.take("a") > 0 and rl.take("b") == 0
    now[0] = 60
    assert rl.take("a") == 0


def test_rate_limit_on_checks(tmp_path: Path) -> None:
    c = app_client(tmp_path, login_required=False, checks_per_minute=2)
    hdr = {security.API_HEADER: "1"}
    body = {"host": "www.example.test", "resolve": "169.254.169.254"}
    codes = [c.post("/api/v1/check", json=body, headers=hdr) for _ in range(3)]
    assert [r.status_code != 429 for r in codes[:2]] == [True, True]
    assert codes[2].status_code == 429 and int(codes[2].headers["Retry-After"]) > 0


# ---- LAN only ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("addr", "ok"),
    [("10.0.0.1", True), *((str(ipaddress.IPv4Address(n)), True) for n in (0xC0A80102, 0xAC100001, 0x64400001)),
     ("127.0.0.1", True), ("::1", True),
     ("fe80::1", True), ("fd00::1", True), ("::ffff:10.0.0.1", True),
     ("192.0.2.1", False), ("224.0.0.1", False), ("::ffff:198.51.100.1", False),
     ("2001:db8::1", False),
     ("testclient", False)],
)  # fmt: skip
def test_lan_client(addr: str, ok: bool) -> None:
    assert security.lan_client((addr, 1)) is ok


def test_non_lan_refused(tmp_path: Path) -> None:
    assert app_client(tmp_path, peer=("203.0.113.9", 1)).get("/api/v1/health").status_code == 403
    assert app_client(tmp_path, peer=("203.0.113.9", 1), lan_only=False).get("/api/v1/health").status_code == 200


# ---- settings.yaml -----------------------------------------------------------------------------------


def test_settings_yaml(tmp_path: Path) -> None:
    (tmp_path / "settings.yaml").write_text(
        "limits: {max_concurrent: 2, checks_per_minute: 7, max_upload_kb: 64}\n"
        "timeouts: {probe_s: 5, session_idle_min: 10, session_max_hours: 2}\n"
        "login: {max_failures: 3, window_min: 5, lockout_min: 20}\n"
        "network: {allowed_hosts: [certcheck.example.test], lan_only: true}\n"
        "denylist: [10.0.0.0/29]\n"
    )
    s = Settings.from_env({"CERTCHECK_CONFIG": str(tmp_path), "CERTCHECK_PASSWORD_HASH": HASH})
    assert (s.max_concurrent, s.checks_per_minute, s.max_upload_bytes) == (2, 7, 64 * 1024)
    assert (s.probe_timeout_s, s.session_idle_s, s.session_max_s) == (5, 600, 7200)
    assert (s.lockout_failures, s.lockout_window_s, s.lockout_s) == (3, 300, 1200)
    assert s.allowed_hosts == ("certcheck.example.test",) and s.denylist == ("10.0.0.0/29",)
    assert s.secure_cookies and s.login_required and "argon2" not in repr(s)


@pytest.mark.parametrize(
    "doc",
    ["limits: {max_concurent: 2}\n", "surprise: 1\n", "denylist: [not-a-cidr]\n", "limits: [1]\n", "- a\n"],
)
def test_settings_yaml_strict(tmp_path: Path, doc: str) -> None:
    (tmp_path / "settings.yaml").write_text(doc)
    with pytest.raises(ValueError):
        Settings.from_env({"CERTCHECK_CONFIG": str(tmp_path)})


def test_denylist_blocks_probe(tmp_path: Path) -> None:
    c = app_client(tmp_path, login_required=False, denylist=("10.0.0.0/29",))
    r = c.post("/api/v1/check", json={"host": "www.example.test", "resolve": "10.0.0.3"},
               headers={security.API_HEADER: "1"})  # fmt: skip
    assert r.status_code in (200, 400, 403) and "10.0.0.3" in r.text
    assert "refus" in r.text.lower() or "not allowed" in r.text.lower() or "denied" in r.text.lower()


# ---- /config/ca --------------------------------------------------------------------------------------


def test_cabundle(tmp_path: Path) -> None:
    ca_dir = tmp_path / "ca"
    assert cabundle.build(ca_dir) is None
    ca_dir.mkdir()
    ca = issue("Internal Test CA", ca=True)
    (ca_dir / "internal.pem").write_bytes(ca.pem)
    (ca_dir / "notes.txt").write_text("ignored")
    built = cabundle.build(ca_dir)
    assert built
    bundle, d = built
    try:
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        certs = x509.load_pem_x509_certificates(bundle.read_bytes())
        assert certs[-1].subject.rfc4514_string().endswith("Internal Test CA")
        assert b"PRIVATE KEY" not in bundle.read_bytes()
    finally:
        shutil.rmtree(d)
    (ca_dir / "broken.crt").write_bytes(b"junk")
    with pytest.raises(ValueError):
        cabundle.build(ca_dir)


# ---- UI certificate and listener ---------------------------------------------------------------------


def test_selfsigned_generated_then_reused(tmp_path: Path) -> None:
    a = tlsboot.ensure(tmp_path / "config", tmp_path / "state", ["certcheck.example.test", "10.0.0.7"])
    assert a.source == "generated"
    assert stat.S_IMODE(a.key.stat().st_mode) == 0o600
    assert stat.S_IMODE(a.key.parent.stat().st_mode) == 0o700
    cert = x509.load_pem_x509_certificate(a.cert.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "certcheck.example.test" in san.get_values_for_type(x509.DNSName)
    b = tlsboot.ensure(tmp_path / "config", tmp_path / "state", ["x"])
    assert b.source == "reused" and b.fingerprint == a.fingerprint


def test_mounted_cert_preferred(tmp_path: Path) -> None:
    tls = tmp_path / "config" / "tls"
    tls.mkdir(parents=True)
    (tls / "cert.pem").write_bytes(issue("ui.example.test").pem)
    with pytest.raises(ValueError):
        tlsboot.ensure(tmp_path / "config", tmp_path / "state", [])
    (tls / "key.pem").write_text("y")
    assert tlsboot.ensure(tmp_path / "config", tmp_path / "state", []).source == "mounted"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


CBC_TLS12 = (
    "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:"
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA256:AES256-SHA256:AES128-SHA:AES128-GCM-SHA256"
)


def _handshake(port: int, version: ssl.TLSVersion, ciphers: str = "ALL") -> str:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ctx.maximum_version = version
    with contextlib.suppress(ssl.SSLError):
        ctx.set_ciphers(ciphers + ":@SECLEVEL=0")  # let the client offer old suites, so only the server can refuse
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        try:
            with ctx.wrap_socket(raw) as t:
                if version == ssl.TLSVersion.TLSv1_2:
                    return f"{t.version()} {t.cipher()[0]}"  # type: ignore[index]
                return str(t.version())
        except (ssl.SSLError, ConnectionError) as e:
            return f"refused: {e}"


def test_ui_listener_refuses_tls10_and_11(tmp_path: Path) -> None:
    """Start the real server (python -m app) and handshake at each protocol version."""
    port = _free_port()
    env = {**os.environ, "CERTCHECK_BIND": "127.0.0.1", "CERTCHECK_PORT": str(port),
           "CERTCHECK_CONFIG": str(tmp_path / "config"), "CERTCHECK_STATE": str(tmp_path / "state"),
           "CERTCHECK_PASSWORD_HASH": HASH}  # fmt: skip
    env.pop("CERTCHECK_TLS", None)
    proc = subprocess.Popen([sys.executable, "-m", "app"], cwd=WEB, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # fmt: skip
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                assert proc.poll() is None and time.monotonic() < deadline, "server did not start"
                time.sleep(0.1)
        got = _handshake(port, ssl.TLSVersion.TLSv1_2)
        assert got.startswith("TLSv1.2 ECDHE-") and ("GCM" in got or "CHACHA20" in got), got
        # AEAD only (review M6 #4): a client offering nothing but CBC suites (and static-RSA GCM) is refused.
        assert _handshake(port, ssl.TLSVersion.TLSv1_2, CBC_TLS12).startswith("refused")
        assert _handshake(port, ssl.TLSVersion.TLSv1_2, "ECDHE+CHACHA20").startswith("TLSv1.2 ECDHE-")
        assert _handshake(port, ssl.TLSVersion.TLSv1_3) == "TLSv1.3"
        assert _handshake(port, ssl.TLSVersion.TLSv1).startswith("refused")
        assert _handshake(port, ssl.TLSVersion.TLSv1_1).startswith("refused")
    finally:
        proc.terminate()
        proc.wait(10)


def test_main_refuses_unsafe_binds(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.__main__ import main

    monkeypatch.setenv("CERTCHECK_BIND", "0.0.0.0")  # noqa: S104
    monkeypatch.setenv("CERTCHECK_TLS", "off")
    assert main([]) == 2
    monkeypatch.delenv("CERTCHECK_TLS")
    monkeypatch.setenv("CERTCHECK_NO_LOGIN", "1")
    assert main([]) == 2
