"""Code review M7b follow-ups (IPv4-mapped peers, IPv6 gateways, opt-in refusal) and M8 version checks."""

from __future__ import annotations

import asyncio
import logging
import re
import tomllib
from pathlib import Path
from typing import Any

import pytest

from app import security
from app.settings import Settings

WEB = Path(__file__).resolve().parents[1]
WORKFLOWS = WEB.parent / ".github" / "workflows"
V6_ROUTE = (
    "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
    "20010db8000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"
    "20010db8000000000000000000000000 40 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
)


def test_default_gateways_reads_ipv6_route(tmp_path: Path) -> None:
    v4, v6 = tmp_path / "route", tmp_path / "ipv6_route"
    v4.write_text("Iface\tDestination\tGateway\tFlags\nlo\t0000007F\t00000000\t0001\n")
    v6.write_text(V6_ROUTE)
    assert security.default_gateways(v4, v6) == frozenset({"2001:db8::1"})
    assert security.default_gateways(tmp_path / "none", tmp_path / "none6") == frozenset()


@pytest.mark.parametrize(
    ("peer", "want"),
    [("::ffff:10.0.0.1", "10.0.0.1"), ("10.0.0.1", "10.0.0.1"), ("2001:db8::1%eth0", "2001:db8::1"),
     ("not-an-ip", None)],
)  # fmt: skip
def test_peer_ip_unwraps_mapped_and_zone(peer: str, want: str | None) -> None:
    ip = security.peer_ip((peer, 1))
    assert (None if ip is None else str(ip)) == want


def _warnings(caplog: pytest.LogCaptureFixture, watch: security.GatewayPeerWatch, peers: list[str]) -> list[str]:
    with caplog.at_level(logging.WARNING, logger="certcheck.security"):
        for p in peers:
            watch.observe((p, 1))
    return [r.getMessage() for r in caplog.records if r.name == "certcheck.security"]


def test_mapped_peer_counts_as_ipv4_gateway(caplog: pytest.LogCaptureFixture) -> None:
    w = security.GatewayPeerWatch(frozenset({"10.0.0.1"}), threshold=3)
    msgs = _warnings(caplog, w, ["::ffff:10.0.0.1", "10.0.0.1", "::ffff:10.0.0.1"])
    assert len(msgs) == 1
    assert "first 3 non-loopback requests" in msgs[0] and "10.0.0.1" in msgs[0] and "Docker host" in msgs[0]


def test_ipv6_gateway_warns(caplog: pytest.LogCaptureFixture) -> None:
    w = security.GatewayPeerWatch(frozenset({"2001:db8::1"}), threshold=2)
    assert len(_warnings(caplog, w, ["2001:db8::1", "2001:db8:0::1"])) == 1


def test_mapped_real_peer_stops_watch(caplog: pytest.LogCaptureFixture) -> None:
    w = security.GatewayPeerWatch(frozenset({"10.0.0.1"}), threshold=2)
    assert _warnings(caplog, w, ["::ffff:10.0.0.30", "10.0.0.1", "10.0.0.1"]) == []


async def _ok(scope: Any, receive: Any, send: Any) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _status(h: security.Hardening, peer: str) -> int:
    scope = {"type": "http", "method": "GET", "path": "/", "headers": [(b"host", b"x")], "client": (peer, 1)}
    out: list[int] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m: Any) -> None:
        if m["type"] == "http.response.start":
            out.append(m["status"])

    asyncio.run(h(scope, receive, send))
    return out[0]


def test_refuse_gateway_peers_opt_in() -> None:
    gw = frozenset({"10.0.0.1"})
    on = security.Hardening(_ok, max_body=1024, watch=security.GatewayPeerWatch(gw, refuse=True))
    off = security.Hardening(_ok, max_body=1024, watch=security.GatewayPeerWatch(gw))
    assert _status(on, "10.0.0.1") == 403
    assert _status(on, "::ffff:10.0.0.1") == 403
    assert _status(on, "10.0.0.30") == 200
    assert _status(on, "127.0.0.1") == 200  # the healthcheck
    assert _status(off, "10.0.0.1") == 200


def test_refuse_gateway_peers_setting(tmp_path: Path) -> None:
    base = {"CERTCHECK_CONFIG": str(tmp_path)}
    assert Settings.from_env(base).refuse_gateway_peers is False
    assert Settings.from_env({**base, "CERTCHECK_REFUSE_GATEWAY_PEERS": "1"}).refuse_gateway_peers is True
    with pytest.raises(ValueError, match="CERTCHECK_REFUSE_GATEWAY_PEERS"):
        Settings.from_env({**base, "CERTCHECK_REFUSE_GATEWAY_PEERS": "maybe"})
    assert security.Hardening(_ok, max_body=1, refuse_gateway_peers=True).watch.refuse is True


# --- M8: version and image labels -----------------------------------------------------------------------------


def _version() -> str:
    return str(tomllib.loads((WEB / "pyproject.toml").read_text())["project"]["version"])


def test_version_is_one_value_everywhere(tmp_path: Path) -> None:
    v = _version()
    assert re.fullmatch(r"\d+\.\d+\.\d+", v)
    lock = (WEB / "uv.lock").read_text()
    assert f'name = "certcheck-web"\nversion = "{v}"' in lock
    assert f"## {v} " in (WEB / "CHANGELOG.md").read_text()
    from app.main import create_app

    assert create_app(Settings(config_dir=tmp_path, login_required=False)).version == v


def test_dockerfile_source_label_is_a_build_arg() -> None:
    text = (WEB / "docker" / "Dockerfile").read_text()
    assert 'ARG SOURCE_URL=""' in text
    assert 'org.opencontainers.image.source="${SOURCE_URL}"' in text
    assert "github.com" not in text
