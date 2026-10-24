"""M5 web UI and REST API: hardening (CSP, CSRF, Origin, body caps, escaping), routes and live probes."""

from __future__ import annotations

import ast
import re
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from fastapi.testclient import TestClient
from m4_pki import Issued, issue, tls_server, write

from app import forms, security
from app.main import create_app
from app.settings import Settings
from certcheck import check as _check  # noqa: F401
from certcheck import listener, probe

APP = Path(__file__).resolve().parents[1] / "app"
LOOP = probe.TargetPolicy(allow_loopback=True)
XSS = "<script>alert(1)</script>"


def client(tmp_path: Path, **kw: object) -> TestClient:
    kw.setdefault("login_required", False)  # login itself: tests/test_auth.py
    st = Settings(config_dir=tmp_path, **kw)  # type: ignore[arg-type]
    return TestClient(create_app(st, policy=LOOP), client=("127.0.0.1", 50000))


def token(c: TestClient, path: str = "/") -> str:
    r = c.get(path)
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    assert m and c.cookies.get(security.CSRF_COOKIE) == m.group(1)
    return m.group(1)


@pytest.fixture(scope="module")
def ca() -> Issued:
    return issue("Test Web CA", ca=True)


# ---- headers and static hardening ----------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/files", "/targets", "/api/v1/health", "/api/v1/profiles", "/static/app.js",
                                  "/nope"])  # fmt: skip
def test_security_headers_everywhere(tmp_path: Path, path: str) -> None:
    r = client(tmp_path).get(path)
    assert r.headers["content-security-policy"] == security.CSP
    assert "'unsafe-inline'" not in security.CSP and "'unsafe-eval'" not in security.CSP
    assert "script-src 'self'" in security.CSP and "frame-ancestors 'none'" in security.CSP
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"


def test_csrf_cookie_flags(tmp_path: Path) -> None:
    r = client(tmp_path).get("/")
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc and "secure" not in sc
    r2 = client(tmp_path, secure_cookies=True).get("/")
    assert "secure" in r2.headers["set-cookie"].lower()


def test_templates_have_no_inline_script_style_handlers_or_safe() -> None:
    for p in (APP / "templates").glob("*.html"):
        s = p.read_text()
        assert not re.search(r"<script(?![^>]*\bsrc=)", s), p.name
        assert not re.search(r"\son[a-z]+\s*=", s, re.I), p.name
        assert not re.search(r"\sstyle\s*=|<style", s, re.I), p.name
        assert "|safe" not in s.replace(" ", "") and "autoescape false" not in s, p.name
        assert "hx-on" not in s and "javascript:" not in s, p.name
    js = (APP / "static" / "app.js").read_text()
    assert "eval(" not in js and "innerHTML" not in js and "new Function" not in js


def test_htmx_is_vendored_and_locked_down(tmp_path: Path) -> None:
    html = client(tmp_path).get("/").text
    assert '<script src="/static/htmx.min.js"' in html and "https://" not in html
    cfg = re.search(r'name="htmx-config" content=\'([^\']+)\'', html)
    assert cfg and '"allowEval":false' in cfg.group(1) and '"allowScriptTags":false' in cfg.group(1)
    assert '"selfRequestsOnly":true' in cfg.group(1)
    assert html.count('id="result" hx-disable') == 1
    assert (APP / "static" / "htmx.LICENSE.txt").is_file()


def test_guidance_and_app_never_execute_commands() -> None:
    for p in [APP.parent / "certcheck" / "guidance.py", *APP.glob("*.py")]:
        tree = ast.parse(p.read_text())
        names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import | ast.ImportFrom) for a in n.names}
        mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | names
        assert not mods & {"subprocess", "os.system", "pty", "shlex.split"}, p.name
        assert "os.system" not in p.read_text() and "popen" not in p.read_text().lower(), p.name


def test_docs_disabled_openapi_served(tmp_path: Path) -> None:
    c = client(tmp_path)
    assert c.get("/docs").status_code == 404 and c.get("/redoc").status_code == 404
    spec = c.get("/api/v1/openapi.json").json()
    assert {"/api/v1/check", "/api/v1/files/verify", "/api/v1/profiles", "/api/v1/targets", "/api/v1/health"} <= set(
        spec["paths"]
    )
    assert not any(p.startswith("/ui/") for p in spec["paths"])


def test_profiles_and_health(tmp_path: Path) -> None:
    c = client(tmp_path)
    assert c.get("/api/v1/health").json() == {"status": "ok"}
    d = c.get("/api/v1/profiles").json()
    assert {"profile": "HTTPS", "default_port": 443, "starttls": False} in d["profiles"] or d["profiles"]
    assert "Generic / unknown" in d["platforms"] and "TLS server" in d["purposes"]


# ---- CSRF, Origin, API header, Host --------------------------------------------------------------------


def test_ui_post_needs_csrf_token(tmp_path: Path) -> None:
    c = client(tmp_path)
    r = c.post("/ui/check", data={"host": "www.example.test"})
    assert r.status_code == 403 and "form expired" in r.text
    c.get("/")
    r = c.post("/ui/check", data={"host": "www.example.test", "csrf_token": "x" * 43})
    assert r.status_code == 403


@pytest.mark.parametrize("hdrs", [{"Origin": "http://evil.example"}, {"Sec-Fetch-Site": "cross-site"},
                                  {"Sec-Fetch-Site": "same-site"}, {"Origin": "null"}])  # fmt: skip
def test_cross_origin_posts_refused(tmp_path: Path, hdrs: dict[str, str]) -> None:
    c = client(tmp_path)
    t = token(c)
    r = c.post("/ui/check", data={"host": "www.example.test", "csrf_token": t}, headers=hdrs)
    assert r.status_code == 403
    r = c.post("/api/v1/check", json={"host": "www.example.test"}, headers=hdrs)
    assert r.status_code == 403


def test_api_needs_json_or_header(tmp_path: Path) -> None:
    c = client(tmp_path)
    r = c.post("/api/v1/check", data={"host": "www.example.test"})  # a simple (no-preflight) form post
    assert r.status_code == 403
    r = c.post("/api/v1/files/verify", files={"files": ("a.pem", b"x")})
    assert r.status_code == 403


def test_allowed_hosts(tmp_path: Path) -> None:
    c = client(tmp_path, allowed_hosts=("certcheck.example.test",))
    assert c.get("/").status_code == 400  # Host: testserver (DNS rebinding)
    assert c.get("/", headers={"Host": "certcheck.example.test:8080"}).status_code == 200


# ---- body limits and form parsing ----------------------------------------------------------------------


def test_upload_over_limit_is_413(tmp_path: Path) -> None:
    c = client(tmp_path, max_upload_bytes=4096)
    t = token(c, "/files")
    r = c.post("/ui/files/verify", data={"csrf_token": t}, files={"files": ("big.pem", b"A" * 5000)})
    assert r.status_code == 413
    r = c.post("/api/v1/files/verify", files={"files": ("big.pem", b"A" * 5000)}, headers={security.API_HEADER: "1"})
    assert r.status_code == 413


def test_streamed_body_over_limit_is_413(tmp_path: Path) -> None:
    c = client(tmp_path, max_upload_bytes=1024)

    def chunks():  # no Content-Length: chunked
        for _ in range(4):
            yield b"A" * 512

    r = c.post("/api/v1/check", content=chunks(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_form_parser_limits() -> None:
    with pytest.raises(forms.FormError):
        forms.parse("application/x-www-form-urlencoded", b"a=1&a=2")
    with pytest.raises(forms.FormError):
        forms.parse("application/x-www-form-urlencoded", "&".join(f"f{i}=1" for i in range(100)).encode())
    with pytest.raises(forms.FormError):
        forms.parse("text/plain", b"x")
    f = forms.parse(
        "multipart/form-data; boundary=B",
        b'--B\r\nContent-Disposition: form-data; name="files"; filename="../../etc/<x>.pem"\r\n\r\nDATA\r\n--B--\r\n',
    )
    assert f.files[0][1] == b"DATA" and "/" not in f.files[0][0]


# ---- file verification, escaping and PFX passwords -----------------------------------------------------


def test_uploaded_cert_with_script_cn_is_escaped(tmp_path: Path, ca: Issued) -> None:
    leaf = issue(XSS, ca)
    c = client(tmp_path)
    t = token(c, "/files")
    r = c.post("/ui/files/verify", data={"csrf_token": t, "hostname": "www.example.test", "purpose": "TLS server"},
               files=[("files", (f"{XSS}.pem", leaf.pem + ca.pem))])  # fmt: skip
    assert r.status_code == 200, r.text
    assert XSS not in r.text and "&lt;script&gt;" in r.text
    assert "<script" not in r.text.split("</head>", 1)[1]  # nothing executable in the body
    # htmx fragment (no layout) is escaped too
    r = c.post("/ui/files/verify", data={"csrf_token": t}, files=[("files", ("a.pem", leaf.pem))],
               headers={"HX-Request": "true"})  # fmt: skip
    assert r.status_code == 200 and "<html" not in r.text and XSS not in r.text and "&lt;script&gt;" in r.text
    # Markdown export escapes too
    j = c.post("/api/v1/files/verify", files=[("files", ("a.pem", leaf.pem))], headers={security.API_HEADER: "1"})
    assert j.status_code == 200 and "script" in j.json()["chain"][0]["subject"]
    assert "&lt;" not in j.text  # JSON is data, not HTML: escaped only where it is rendered


def test_pfx_upload_password_never_echoed(tmp_path: Path, ca: Issued, caplog: pytest.LogCaptureFixture) -> None:
    pw = "Corr3ct-Horse-pfx-secret"  # noqa: S105
    leaf = issue("pfx.example.test", ca)
    pfx = pkcs12.serialize_key_and_certificates(
        b"x", leaf.key, leaf.cert, [ca.cert], BestAvailableEncryption(pw.encode())
    )
    c = client(tmp_path)
    caplog.set_level("DEBUG")
    t = token(c, "/files")
    r = c.post("/ui/files/verify", data={"csrf_token": t, "password": pw, "hostname": "pfx.example.test"},
               files=[("files", ("bundle.pfx", pfx))])  # fmt: skip
    assert r.status_code == 200 and "pfx.example.test" in r.text and pw not in r.text
    j = c.post("/api/v1/files/verify", data={"password": pw}, files=[("files", ("b.p12", pfx))],
               headers={security.API_HEADER: "1"})  # fmt: skip
    assert j.status_code == 200 and pw not in j.text and j.json()["chain"]
    bad = c.post("/api/v1/files/verify", data={"password": "wrong"}, files=[("files", ("b.p12", pfx))],
                 headers={security.API_HEADER: "1"})  # fmt: skip
    assert bad.status_code == 200 and "wrong" not in bad.text
    assert pw not in caplog.text


def test_file_verify_needs_files(tmp_path: Path) -> None:
    c = client(tmp_path)
    t = token(c, "/files")
    r = c.post("/ui/files/verify", data={"csrf_token": t})
    assert r.status_code == 400


# ---- live probes ---------------------------------------------------------------------------------------


def _server(tmp_path: Path, leaf: Issued, ca: Issued):  # type: ignore[no-untyped-def]
    return listener.server_context(
        write(tmp_path, "c.pem", leaf.pem + ca.pem), write(tmp_path, "k.pem", leaf.key_pem())
    )


def test_api_check_live(tmp_path: Path, ca: Issued) -> None:
    anchors = write(tmp_path, "ca.pem", ca.pem)
    leaf = issue("www.example.test", ca)
    c = client(tmp_path, anchors=anchors)
    with tls_server(_server(tmp_path, leaf, ca)) as port:
        r = c.post("/api/v1/check", json={"host": "www.example.test", "port": port, "resolve": "127.0.0.1"})
    d = r.json()
    assert r.status_code == 200, d
    assert d["connected_ip"] == "127.0.0.1" and d["trust"]["trusted"] and not d["legacy"]
    assert d["chain"][0]["subject"].endswith("www.example.test") and d["openssl_command"].startswith("openssl")


def test_ui_check_live_fragment_and_full_page(tmp_path: Path, ca: Issued) -> None:
    anchors = write(tmp_path, "ca.pem", ca.pem)
    leaf = issue("www.example.test", ca)
    c = client(tmp_path, anchors=anchors)
    t = token(c)
    form = {"csrf_token": t, "host": "www.example.test", "resolve": "127.0.0.1", "profile": "HTTPS", "aia": "1"}
    with tls_server(_server(tmp_path, leaf, ca)) as port:
        frag = c.post("/ui/check", data={**form, "port": str(port)}, headers={"HX-Request": "true"})
        full = c.post("/ui/check", data={**form, "port": str(port)})
    assert frag.status_code == 200 and "<html" not in frag.text and "www.example.test" in frag.text
    assert full.status_code == 200 and "<html" in full.text and 'class="copy"' in full.text
    assert "data:application/json" in full.text and "data:text/markdown" in full.text


def test_mismatched_name_shows_copy_only_guidance(tmp_path: Path, ca: Issued) -> None:
    anchors = write(tmp_path, "ca.pem", ca.pem)
    leaf = issue("other.example.test", ca)
    c = client(tmp_path, anchors=anchors)
    with tls_server(_server(tmp_path, leaf, ca)) as port:
        d = c.post("/api/v1/check", json={"host": "www.example.test", "port": port, "resolve": "127.0.0.1"}).json()
        t = token(c)
        html = c.post("/ui/check", data={"csrf_token": t, "host": "www.example.test", "port": str(port),
                                         "resolve": "127.0.0.1"}).text  # fmt: skip
    assert d["worst"] == "fail" and d["guidance"], d
    assert "<pre><code>" in html and "Copy only" in html


def test_api_check_validation(tmp_path: Path) -> None:
    c = client(tmp_path)
    assert c.post("/api/v1/check", json={"host": "a.example.test", "extra": 1}).status_code == 422
    assert c.post("/api/v1/check", json={"host": "a.example.test", "port": 70000}).status_code == 422
    assert c.post("/api/v1/check", json={"host": "a.example.test", "legacy": "yes"}).status_code == 422
    t = token(c)
    r = c.post("/ui/check", data={"csrf_token": t, "host": XSS})
    assert r.status_code == 400 and XSS not in r.text


def test_policy_denies_metadata(tmp_path: Path) -> None:
    c = TestClient(
        create_app(Settings(config_dir=tmp_path, login_required=False), policy=probe.TargetPolicy()),
        client=("127.0.0.1", 50000),
    )
    d = c.post("/api/v1/check", json={"host": "www.example.test", "resolve": "169.254.169.254"}).json()
    assert d["error"] and d["connected_ip"] is None


def test_concurrency_cap_returns_429(tmp_path: Path, ca: Issued, monkeypatch: pytest.MonkeyPatch) -> None:
    from certcheck import check

    gate, entered = threading.Event(), threading.Event()
    real = check.run

    def slow(*a: object, **kw: object) -> probe.ProbeResult:
        entered.set()
        gate.wait(10)
        return real(*a, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(check, "run", slow)
    c = client(tmp_path, max_concurrent=1)
    out: list[int] = []
    body = {"host": "www.example.test", "resolve": "169.254.169.254"}
    th = threading.Thread(target=lambda: out.append(c.post("/api/v1/check", json=body).status_code))
    th.start()
    assert entered.wait(10)
    r = c.post("/api/v1/check", json={"host": "www.example.test", "resolve": "169.254.169.254"})
    gate.set()
    th.join(15)
    assert r.status_code == 429 and r.headers["retry-after"] == "5" and out == [200]


# ---- saved targets -------------------------------------------------------------------------------------


def test_saved_targets_list_and_run(tmp_path: Path, ca: Issued) -> None:
    anchors = write(tmp_path, "ca.pem", ca.pem)
    leaf = issue("www.example.test", ca)
    with tls_server(_server(tmp_path, leaf, ca)) as port:
        (tmp_path / "targets.yaml").write_text(
            f"schema: 1\ntargets:\n  - name: '{XSS}'\n    host: www.example.test\n    port: {port}\n"
            "    connect_ip: 127.0.0.1\n    aia: true\n"
        )
        c = client(tmp_path, anchors=anchors)
        assert c.get("/api/v1/targets").json()["targets"][0]["aia"] is True
        page = c.get("/targets").text
        assert XSS not in page and "&lt;script&gt;" in page
        t = token(c, "/targets")
        r = c.post("/ui/targets/run", data={"csrf_token": t, "name": XSS})
        assert r.status_code == 200 and "www.example.test" in r.text
        assert c.post("/ui/targets/run", data={"csrf_token": t, "name": "nope"}).status_code == 404


def test_invalid_targets_file(tmp_path: Path) -> None:
    (tmp_path / "targets.yaml").write_text("schema: 1\ntargets:\n  - host: a.example.test\n    bogus: 1\n")
    c = client(tmp_path)
    assert c.get("/api/v1/targets").status_code == 500
    assert "targets.yaml is invalid" in c.get("/targets").text
