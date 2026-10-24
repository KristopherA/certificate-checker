"""Certificate Checker Web: FastAPI app with server-rendered Jinja2 templates and htmx (no JS build chain).

Routes (spec section 4): the REST API under /api/v1 and four UI pages (Probe, File verify, Results, Saved
targets). Every route is hardened as if anyone on the LAN can reach it (security.py); login is M6.
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
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

from . import forms, render, security
from .settings import Settings

HERE = Path(__file__).resolve().parent
log = logging.getLogger("certcheck.web")


class Busy(Exception):
    pass


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
    slots = {"busy": 0}  # review M5 S1: running checks; a full house answers 429 at once, never queues
    pol = policy or probe.TargetPolicy.from_env()  # fails closed on a bad CERTCHECK_PORT / CERTCHECK_PROBE_DENY

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(
        title="Certificate Checker Web",
        version="0.5.0",
        openapi_url="/api/v1/openapi.json",
        docs_url=None,  # Swagger/ReDoc load scripts from a CDN and use inline script: not with this CSP
        redoc_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(security.Hardening, max_body=st.max_upload_bytes, allowed_hosts=st.allowed_hosts)
    templates = Jinja2Templates(env=_environment())
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    async def limited[T](fn: Callable[[], T]) -> T:
        # Review M5 S1: take a slot without waiting (no locked()-then-acquire race); no slot means 429 now.
        # asyncio is single-threaded and nothing awaits between the test and the increment, so this is atomic.
        if slots["busy"] >= st.max_concurrent:
            raise Busy
        slots["busy"] += 1
        try:
            return await run_in_threadpool(fn)
        finally:
            slots["busy"] -= 1

    @app.exception_handler(Busy)
    async def busy(request: Request, _: Busy) -> Response:
        msg = "Too many checks are running. Try again in a moment."
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": msg}, status_code=429, headers={"Retry-After": "5"})
        return page(request, "_error.html", {"message": msg}, 429)

    @app.exception_handler(Exception)
    async def internal(request: Request, e: Exception) -> Response:
        log.error("internal error on %s %s: %s", request.method, request.url.path, type(e).__name__)
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "Internal error."}, status_code=500)
        return page(request, "_error.html", {"message": "Internal error."}, 500)

    def page(request: Request, name: str, ctx: dict[str, Any], status: int = 200) -> Response:
        token = security.csrf_token(request)
        full = request.headers.get("hx-request") != "true" or name.startswith("page_")
        body = {"csrf_token": token, "full": full, "nav": ctx.pop("nav", ""), **ctx}
        tpl = name if name.startswith("page_") else ("page_fragment.html" if full else name)
        resp = templates.TemplateResponse(request, tpl, {**body, "fragment": name}, status_code=status)
        resp.set_cookie(security.CSRF_COOKIE, token, httponly=True, samesite="strict", secure=st.secure_cookies,
                        path="/")  # fmt: skip
        return resp

    async def read_form(request: Request) -> forms.Form:
        body = await request.body()
        return forms.parse(request.headers.get("content-type", ""), body)

    def run_probe(t: probe.Target, o: check.Options) -> probe.ProbeResult:
        return check.run(t, o, timeout=st.probe_timeout_s, anchors=st.anchors, policy=pol)

    def run_files(items: list[tuple[str, bytes]], host: str | None, purpose: Purpose, pw: str | None) -> Any:
        return filecheck.inspect_data(items, host, purpose, anchors=st.anchors, now=dt.datetime.now(dt.UTC),
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
    async def api_check(req: CheckRequest) -> Response:
        try:
            t, o = req.target()
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        r = await limited(lambda: run_probe(t, o))
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
        r = await limited(lambda: run_files(items, host, purpose, pw))
        return JSONResponse(render.file_doc(r, [n for n, _ in items], host, purpose.value))

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
        r = await limited(lambda: run_probe(t, o))
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
        r = await limited(lambda: run_probe(hit.target, hit.options))
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
        r = await limited(lambda: run_files(items, host, purpose, pw))
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
