"""Certificate Checker Web: FastAPI app with server-rendered Jinja2 templates and htmx (no JS build chain).

Routes (spec section 4): the REST API under /api/v1 and four UI pages (Probe, File verify, Results, Saved
targets), plus /login and /logout (M6). Every route is hardened as if anyone on the LAN can reach it
(security.py), and every route except /login, /api/v1/health and /static/ needs a logged-in session (auth.py).

Concurrency: the app assumes ONE event loop per process (one uvicorn worker, the default for python -m app).
The busy counter, sessions, lockout and rate-limit tables are plain in-memory objects mutated only from that
loop, with no await between a test and its update; they are not safe if several threads each run an event
loop over the same app object, and each extra worker process would get its own separate copies.
"""

from __future__ import annotations

import atexit
import datetime as dt
import ipaddress
import logging
import shutil
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from certcheck import check, filecheck, probe
from certcheck import targets as saved
from certcheck.guidance import Platform, default_platform
from certcheck.model import Purpose
from certcheck.services import Service

from . import auth, cabundle, forms, render, security
from .settings import Settings

HERE = Path(__file__).resolve().parent
log = logging.getLogger("certcheck.web")


class Busy(Exception):
    def __init__(self, message: str = "Too many checks are running. Try again in a moment.", retry: int = 5) -> None:
        super().__init__(message)
        self.message, self.retry = message, retry


PUBLIC_PATHS = frozenset({"/login", "/api/v1/health"})


def _client(scope_or_request: Request) -> str:
    c = scope_or_request.client
    return c.host if c else "local"


class AuthGate:
    """Pure ASGI: every request outside PUBLIC_PATHS and /static/ needs a valid session cookie. Unauthenticated
    page loads are sent to /login, htmx requests get 401 with HX-Redirect, API calls get a 401 JSON body."""

    def __init__(self, app: security.ASGIApp, *, sessions: auth.Sessions, required: bool) -> None:
        self.inner, self.sessions, self.required = app, sessions, required

    async def __call__(self, scope: security.Scope, receive: security.Receive, send: security.Send) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or not self.required or path in PUBLIC_PATHS or path.startswith("/static/"):
            await self.inner(scope, receive, send)
            return
        request = Request(scope)
        if self.sessions.valid(request.cookies.get(auth.SESSION_COOKIE)):
            await self.inner(scope, receive, send)
            return
        resp: Response
        if path.startswith("/api/"):
            resp = JSONResponse({"detail": "Log in first."}, status_code=401)
        elif request.headers.get("hx-request") == "true":
            resp = PlainTextResponse("Log in first.", status_code=401, headers={"HX-Redirect": "/login"})
        elif scope["method"] in ("GET", "HEAD"):
            resp = RedirectResponse("/login", status_code=303)
        else:
            resp = PlainTextResponse("Log in first.", status_code=401)
        await resp(scope, receive, send)


class CheckRequest(BaseModel):
    """POST /api/v1/check. Unknown fields are refused; booleans must be real booleans."""

    model_config = ConfigDict(extra="forbid", strict=True)
    host: Annotated[str, Field(min_length=1, max_length=253)]
    port: Annotated[int, Field(ge=1, le=65535)] | None = None
    profile: Service = Service.HTTPS
    sni: Annotated[str, Field(min_length=1, max_length=253)] | None = None
    verify_name: Annotated[str, Field(min_length=1, max_length=253)] | None = None
    resolve: Annotated[str, Field(min_length=1, max_length=64)] | None = None  # connect to this IP (curl --resolve)
    family: Literal["any", "ipv4", "ipv6"] = "any"
    fingerprint_pin: Annotated[str, Field(max_length=200)] | None = None
    platform: Platform | None = None  # default: the profile's platform (guidance.default_platform)
    legacy: bool = False
    aia: bool = False
    revocation: bool = False

    def guidance_platform(self) -> Platform:
        return self.platform or default_platform(self.profile) or Platform.GENERIC

    def target(self) -> tuple[probe.Target, check.Options]:
        t = probe.Target(
            host=self.host.strip(),
            port=self.port or self.profile.default_port,
            sni=self.sni,
            verify_name=self.verify_name,
            connect_ip=self.resolve,
            family=self.family,
            service=self.profile,
            fingerprint_pin=self.fingerprint_pin or None,
        )
        t.validate()
        return t, check.Options(legacy=self.legacy, aia=self.aia, revocation=self.revocation)


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(HERE / "templates"),
        autoescape=True,  # every template, whatever its extension; no template uses |safe (tests/test_app.py)
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env


def create_app(settings: Settings | None = None, policy: probe.TargetPolicy | None = None) -> FastAPI:
    st = settings or Settings.from_env()
    if st.login_required and not st.password_hash:
        raise ValueError("Login is required but no password hash is set: set CERTCHECK_PASSWORD_HASH or "
                         "CERTCHECK_PASSWORD_HASH_FILE (make one with: python -m app hash-password)")  # fmt: skip
    # Review M5 S1 / M5b suggestion 2: running checks. A full house answers 429 at once, never queues. This counter
    # is only correct with one event loop per process (see the module docstring); it is not thread-safe.
    slots = {"busy": 0, "verifying": 0}
    pol = policy or probe.TargetPolicy.from_env()  # fails closed on a bad CERTCHECK_PORT / CERTCHECK_PROBE_DENY
    if st.denylist:  # settings.yaml denylist: added to (never replacing) the built-in and env denials
        pol = replace(pol, extra_denied=pol.extra_denied + tuple(ipaddress.ip_network(c, strict=False)
                                                                 for c in st.denylist))  # fmt: skip
    sessions = auth.Sessions(st.session_idle_s, st.session_max_s)
    lockout = auth.Lockout(st.lockout_failures, st.lockout_window_s, st.lockout_s)
    rate = auth.RateLimit(st.checks_per_minute)
    anchors = st.anchors
    ca_dir: Path | None = None
    if anchors is None:
        built = cabundle.build(st.config_dir / "ca")  # system store + /config/ca; fails closed on an unreadable file
        if built is not None:
            anchors, ca_dir = built
            atexit.register(shutil.rmtree, ca_dir, True)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if ca_dir is not None:
                shutil.rmtree(ca_dir, ignore_errors=True)

    app = FastAPI(
        title="Certificate Checker Web",
        version="0.6.0",
        openapi_url="/api/v1/openapi.json",
        docs_url=None,  # Swagger/ReDoc load scripts from a CDN and use inline script: not with this CSP
        redoc_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(AuthGate, sessions=sessions, required=st.login_required)  # inner: runs after Hardening
    app.add_middleware(security.Hardening, max_body=st.max_upload_bytes, allowed_hosts=st.allowed_hosts,
                       lan_only=st.lan_only)  # fmt: skip
    templates = Jinja2Templates(env=_environment())
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    async def limited[T](request: Request, fn: Callable[[], T]) -> T:
        # Review M5 S1: take a slot without waiting (no locked()-then-acquire race); no slot means 429 now.
        # Atomic only because one event loop runs this and nothing awaits between the test and the increment.
        if slots["busy"] >= st.max_concurrent:
            raise Busy
        wait = rate.take(_client(request))  # per-address checks per minute (settings.yaml limits)
        if wait:
            raise Busy(f"Too many checks from this address. Try again in {wait} s.", wait)
        slots["busy"] += 1
        try:
            return await run_in_threadpool(fn)
        finally:
            slots["busy"] -= 1

    @app.exception_handler(Busy)
    async def busy(request: Request, e: Busy) -> Response:
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": e.message}, status_code=429, headers={"Retry-After": str(e.retry)})
        r = page(request, "_error.html", {"message": e.message}, 429)
        r.headers["Retry-After"] = str(e.retry)
        return r

    @app.exception_handler(Exception)
    async def internal(request: Request, e: Exception) -> Response:
        log.error("internal error on %s %s: %s", request.method, request.url.path, type(e).__name__)
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "Internal error."}, status_code=500)
        return page(request, "_error.html", {"message": "Internal error."}, 500)

    def page(request: Request, name: str, ctx: dict[str, Any], status: int = 200) -> Response:
        token = security.csrf_token(request)
        full = request.headers.get("hx-request") != "true" or name.startswith("page_")
        signed_in = st.login_required and sessions.valid(request.cookies.get(auth.SESSION_COOKIE))
        body = {"csrf_token": token, "full": full, "nav": ctx.pop("nav", ""), "signed_in": signed_in, **ctx}
        tpl = name if name.startswith("page_") else ("page_fragment.html" if full else name)
        resp = templates.TemplateResponse(request, tpl, {**body, "fragment": name}, status_code=status)
        resp.set_cookie(security.CSRF_COOKIE, token, httponly=True, samesite="strict", secure=st.secure_cookies,
                        path="/")  # fmt: skip
        return resp

    async def read_form(request: Request) -> forms.Form:
        body = await request.body()
        return forms.parse(request.headers.get("content-type", ""), body)

    def run_probe(t: probe.Target, o: check.Options) -> probe.ProbeResult:
        return check.run(t, o, timeout=st.probe_timeout_s, anchors=anchors, policy=pol)

    def run_files(items: list[tuple[str, bytes]], host: str | None, purpose: Purpose, pw: str | None) -> Any:
        return filecheck.inspect_data(items, host, purpose, anchors=anchors, now=dt.datetime.now(dt.UTC),
                                      password=pw)  # fmt: skip

    # ---- API -------------------------------------------------------------------------------------------

    @app.get("/api/v1/health", tags=["api"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/v1/profiles", tags=["api"])
    async def profiles() -> dict[str, Any]:
        return {
            "profiles": [
                {"profile": s.value, "default_port": s.default_port, "starttls": s.uses_upgrade} for s in Service
            ],  # fmt: skip
            "platforms": [p.value for p in Platform],
            "purposes": [p.value for p in Purpose],
        }

    @app.get("/api/v1/targets", tags=["api"])
    async def api_targets() -> Response:
        try:
            ts = saved.load(st.config_dir / "targets.yaml")
        except (ValueError, OSError) as e:
            return JSONResponse({"detail": str(e)}, status_code=500)
        return JSONResponse({"targets": [target_dict(x) for x in ts]})

    @app.post("/api/v1/check", tags=["api"])
    async def api_check(request: Request, req: CheckRequest) -> Response:
        try:
            t, o = req.target()
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        r = await limited(request, lambda: run_probe(t, o))
        return JSONResponse(render.probe_doc(r, req.guidance_platform()))

    @app.post(
        "/api/v1/files/verify",
        tags=["api"],
        openapi_extra={"requestBody": {"required": True, "content": {"multipart/form-data": {"schema": {
            "type": "object",
            "properties": {
                "files": {"type": "array", "items": {"type": "string", "format": "binary"},
                          "description": "Certificates, keys, chains, CSRs, PKCS#7 or PFX/P12 (1 MB in total)"},
                "password": {"type": "string", "format": "password", "description": "PFX/P12 password (memory only)"},
                "hostname": {"type": "string"},
                "purpose": {"type": "string", "enum": [p.value for p in Purpose]},
            },
        }}}}},
    )  # fmt: skip
    async def api_files(request: Request) -> Response:
        try:
            f = await read_form(request)
            items, host, purpose, pw = file_inputs(f)
        except (forms.FormError, ValueError) as e:
            return JSONResponse({"detail": str(e)}, status_code=422)
        r = await limited(request, lambda: run_files(items, host, purpose, pw))
        return JSONResponse(render.file_doc(r, [n for n, _ in items], host, purpose.value))

    # ---- login ------------------------------------------------------------------------------------------

    @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
    async def ui_login(request: Request) -> Response:
        if not st.login_required or sessions.valid(request.cookies.get(auth.SESSION_COOKIE)):
            return RedirectResponse("/", status_code=303)
        return page(request, "page_login.html", {"nav": "login", "message": None})

    @app.post("/login", response_class=HTMLResponse, include_in_schema=False)
    async def ui_login_post(request: Request) -> Response:
        if not st.login_required:
            return RedirectResponse("/", status_code=303)
        try:
            f = await read_form(request)
        except forms.FormError as e:
            return page(request, "page_login.html", {"nav": "login", "message": str(e)}, 400)
        if not security.check_csrf(request, f.fields.get(security.CSRF_FIELD)):
            return page(request, "page_login.html", {"nav": "login", "message": "The form expired. Try again."}, 403)
        addr = _client(request)
        wait = lockout.retry_after(addr)
        if wait:
            return locked(request, wait)
        if slots["verifying"] >= 2:  # argon2 is deliberately expensive: at most two checks at once
            return locked(request, 2)
        slots["verifying"] += 1
        try:
            assert st.password_hash is not None
            ok = await run_in_threadpool(auth.verify_password, st.password_hash, f.fields.get("password") or "")
        finally:
            slots["verifying"] -= 1
        if not ok:
            lockout.fail(addr)
            log.warning("failed login from %s", addr)  # never the submitted password
            wait = lockout.retry_after(addr)
            if wait:
                return locked(request, wait)
            return page(request, "page_login.html", {"nav": "login", "message": "Wrong password."}, 401)
        lockout.success(addr)
        sessions.drop(request.cookies.get(auth.SESSION_COOKIE))  # no session fixation: always a fresh id
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(auth.SESSION_COOKIE, sessions.create(), httponly=True, samesite="strict",
                        secure=st.secure_cookies, path="/")  # fmt: skip
        resp.set_cookie(security.CSRF_COOKIE, security.new_token(), httponly=True, samesite="strict",
                        secure=st.secure_cookies, path="/")  # fmt: skip
        log.warning("login from %s", addr)
        return resp

    def locked(request: Request, wait: int) -> Response:
        mins = max(1, (wait + 59) // 60)
        msg = f"Too many failed logins. Try again in {mins} minute{'s' if mins != 1 else ''}."
        r = page(request, "page_login.html", {"nav": "login", "message": msg}, 429)
        r.headers["Retry-After"] = str(wait)
        return r

    @app.post("/logout", include_in_schema=False)
    async def ui_logout(request: Request) -> Response:
        try:
            f = await read_form(request)
        except forms.FormError as e:
            return page(request, "_error.html", {"message": str(e)}, 400)
        if not security.check_csrf(request, f.fields.get(security.CSRF_FIELD)):
            return page(request, "_error.html", {"message": "The form expired. Reload the page and try again."}, 403)
        sessions.drop(request.cookies.get(auth.SESSION_COOKIE))
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(auth.SESSION_COOKIE, path="/", secure=st.secure_cookies, httponly=True, samesite="strict")
        resp.set_cookie(security.CSRF_COOKIE, security.new_token(), httponly=True, samesite="strict",
                        secure=st.secure_cookies, path="/")  # fmt: skip
        return resp

    # ---- UI --------------------------------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def ui_probe(request: Request) -> Response:
        return page(request, "page_probe.html", {"nav": "probe", **choices()})

    @app.get("/files", response_class=HTMLResponse, include_in_schema=False)
    async def ui_files(request: Request) -> Response:
        return page(request, "page_files.html", {"nav": "files", "purposes": [p.value for p in Purpose],
                                                 "max_kb": st.max_upload_bytes // 1024})  # fmt: skip

    @app.get("/targets", response_class=HTMLResponse, include_in_schema=False)
    async def ui_targets(request: Request) -> Response:
        try:
            ts, err = saved.load(st.config_dir / "targets.yaml"), None
        except (ValueError, OSError) as e:
            ts, err = [], str(e)
        return page(request, "page_targets.html", {"nav": "targets", "targets": ts, "error": err})

    @app.post("/ui/check", response_class=HTMLResponse, include_in_schema=False)
    async def ui_check(request: Request) -> Response:
        try:
            f = await read_form(request)
        except forms.FormError as e:
            return page(request, "_error.html", {"message": str(e)}, 400)
        if not security.check_csrf(request, f.fields.get(security.CSRF_FIELD)):
            return page(request, "_error.html", {"message": "The form expired. Reload the page and try again."}, 403)
        try:
            req = CheckRequest(
                host=f.get("host").strip(),
                port=int(f.get("port")) if f.get("port").strip() else None,
                profile=Service(f.get("profile", Service.HTTPS.value)),
                sni=f.get("sni").strip() or None,
                verify_name=f.get("verify_name").strip() or None,
                resolve=f.get("resolve").strip() or None,
                family=f.get("family", "any"),  # type: ignore[arg-type]
                fingerprint_pin=f.get("fingerprint_pin").strip() or None,
                platform=Platform(f.get("platform")) if f.get("platform") else None,
                legacy=f.flag("legacy"),
                aia=f.flag("aia"),
                revocation=f.flag("revocation"),
            )
            t, o = req.target()
        except ValueError as e:
            return page(request, "_error.html", {"message": _first_error(e)}, 400)
        r = await limited(request, lambda: run_probe(t, o))
        doc = render.probe_doc(r, req.guidance_platform())
        return page(request, "_result.html", {"doc": doc, "exports": render.exports(doc)})

    @app.post("/ui/targets/run", response_class=HTMLResponse, include_in_schema=False)
    async def ui_target_run(request: Request) -> Response:
        try:
            f = await read_form(request)
        except forms.FormError as e:
            return page(request, "_error.html", {"message": str(e)}, 400)
        if not security.check_csrf(request, f.fields.get(security.CSRF_FIELD)):
            return page(request, "_error.html", {"message": "The form expired. Reload the page and try again."}, 403)
        try:
            ts = saved.load(st.config_dir / "targets.yaml")
        except (ValueError, OSError) as e:
            return page(request, "_error.html", {"message": str(e)}, 500)
        hit = next((x for x in ts if x.name == f.get("name")), None)
        if hit is None:
            return page(request, "_error.html", {"message": "No saved target with that name."}, 404)
        r = await limited(request, lambda: run_probe(hit.target, hit.options))
        doc = render.probe_doc(r, hit.platform)
        return page(request, "_result.html", {"doc": doc, "exports": render.exports(doc)})

    @app.post("/ui/files/verify", response_class=HTMLResponse, include_in_schema=False)
    async def ui_files_verify(request: Request) -> Response:
        try:
            f = await read_form(request)
        except forms.FormError as e:
            return page(request, "_error.html", {"message": str(e)}, 400)
        if not security.check_csrf(request, f.fields.get(security.CSRF_FIELD)):
            return page(request, "_error.html", {"message": "The form expired. Reload the page and try again."}, 403)
        try:
            items, host, purpose, pw = file_inputs(f)
        except ValueError as e:
            return page(request, "_error.html", {"message": str(e)}, 400)
        r = await limited(request, lambda: run_files(items, host, purpose, pw))
        doc = render.file_doc(r, [n for n, _ in items], host, purpose.value)
        return page(request, "_result.html", {"doc": doc, "exports": render.exports(doc)})

    return app


def file_inputs(f: forms.Form) -> tuple[list[tuple[str, bytes]], str | None, Purpose, str | None]:
    if not f.files:
        raise ValueError("Choose at least one file.")
    host = f.get("hostname").strip() or None
    if host is not None and (len(host) > 253 or any(c.isspace() or c in "/\\@" for c in host)):
        raise ValueError("Hostname must be a DNS name or IP address.")
    try:
        purpose = Purpose(f.get("purpose", Purpose.TLS_SERVER.value))
    except ValueError:
        raise ValueError("Unknown purpose.") from None
    pw = f.fields.get("password") or None  # memory only: never logged, rendered or returned
    return f.files, host, purpose, pw


def target_dict(x: saved.SavedTarget) -> dict[str, Any]:
    t = x.target
    return {"name": x.name, "host": t.host, "port": t.port, "profile": t.service.value, "sni": t.sni,
            "verify_name": t.verify_name, "connect_ip": t.connect_ip, "family": t.family,
            "platform": x.platform.value, "legacy": x.options.legacy, "aia": x.options.aia,
            "revocation": x.options.revocation}  # fmt: skip


def choices() -> dict[str, Any]:
    return {"profiles": [(s.value, s.default_port) for s in Service], "platforms": [p.value for p in Platform]}


def _first_error(e: ValueError) -> str:
    errs = getattr(e, "errors", None)
    if callable(errs):
        try:
            first = errs()[0]
            return f"{'.'.join(str(x) for x in first.get('loc', ())) or 'input'}: {first.get('msg', 'invalid')}"
        except (IndexError, TypeError):
            pass
    return str(e).splitlines()[0][:300]


def asgi() -> FastAPI:
    """Factory for uvicorn (python -m app)."""
    return create_app()
