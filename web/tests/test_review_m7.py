"""Code review M7 follow-ups: healthcheck target (S3) and the gateway-peer warning (S2)."""

# ruff: noqa: S104  wildcard addresses here are test inputs, nothing binds to them

from __future__ import annotations

import http.server
import logging
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from app import __main__ as cli
from app import security

DOCKER = Path(__file__).resolve().parents[1] / "docker"


@pytest.mark.parametrize(
    ("bind", "want"),
    [(None, "127.0.0.1"), ("0.0.0.0", "127.0.0.1"), ("", "127.0.0.1"), ("::", "::1"), ("[::]", "::1"),
     ("127.0.0.1", "127.0.0.1"), ("10.0.0.20", "10.0.0.20"), (" 10.0.0.20 ", "10.0.0.20"), ("::1", "::1")],
)  # fmt: skip
def test_health_host(bind: str | None, want: str) -> None:
    env = {} if bind is None else {"CERTCHECK_BIND": bind}
    assert cli.health_host(env) == want


class _Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200 if self.path == "/api/v1/health" else 404)
        self.end_headers()

    def log_message(self, *_: object) -> None:
        pass


@pytest.fixture
def plain_server() -> Iterator[int]:
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Health)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize("bind", ["127.0.0.1", "0.0.0.0"])
def test_healthcheck_follows_bind(monkeypatch: pytest.MonkeyPatch, plain_server: int, bind: str) -> None:
    monkeypatch.setenv("CERTCHECK_TLS", "off")
    monkeypatch.setenv("CERTCHECK_PORT", str(plain_server))
    monkeypatch.setenv("CERTCHECK_BIND", bind)
    assert cli.healthcheck() == 0


def test_healthcheck_fails_on_other_bind(monkeypatch: pytest.MonkeyPatch, plain_server: int) -> None:
    # The server listens on loopback only; a bind naming another address must not be reported healthy.
    monkeypatch.setenv("CERTCHECK_TLS", "off")
    monkeypatch.setenv("CERTCHECK_PORT", str(plain_server))
    monkeypatch.setenv("CERTCHECK_BIND", "192.0.2.1")
    assert cli.healthcheck() == 1


def test_default_gateways_parses_route_table(tmp_path: Path) -> None:
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\n"
        "eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\n"
    )
    assert security.default_gateways(route) == frozenset({"10.0.0.1"})
    assert security.default_gateways(tmp_path / "missing") == frozenset()


def test_gateway_watch_warns_once_when_all_peers_are_gateway(caplog: pytest.LogCaptureFixture) -> None:
    w = security.GatewayPeerWatch(frozenset({"10.0.0.1"}), threshold=3)
    with caplog.at_level(logging.WARNING, logger="certcheck.security"):
        w.observe(("127.0.0.1", 1))  # own healthcheck: ignored
        for _ in range(5):
            w.observe(("10.0.0.1", 1))
    msgs = [r.getMessage() for r in caplog.records if r.name == "certcheck.security"]
    assert len(msgs) == 1 and "10.0.0.1" in msgs[0]


def test_gateway_watch_silent_when_real_peer_seen(caplog: pytest.LogCaptureFixture) -> None:
    w = security.GatewayPeerWatch(frozenset({"10.0.0.1"}), threshold=3)
    with caplog.at_level(logging.WARNING, logger="certcheck.security"):
        w.observe(("10.0.0.1", 1))
        w.observe(("10.0.0.5", 1))
        for _ in range(5):
            w.observe(("10.0.0.1", 1))
    assert not [r for r in caplog.records if r.name == "certcheck.security"]


def test_gateway_watch_off_without_gateway() -> None:
    w = security.GatewayPeerWatch(frozenset())
    assert w.done


def test_compose_publishes_on_host_ip_variable_only() -> None:
    svc = yaml.safe_load((DOCKER / "compose.yaml").read_text())["services"]["certcheck"]
    ports = svc["ports"]
    assert len(ports) == 1 and ports[0].startswith("${CERTCHECK_HOST_IP:?") and ports[0].endswith(":8443:8080")
    assert "0.0.0.0" not in ports[0]
