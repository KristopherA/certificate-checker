"""Probe tests against a loopback TLS server (127.0.0.1 only; no network, no Docker)."""

from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from certcheck import probe
from certcheck.model import Severity
from certcheck.shared import load_manifest, shared_dir

CA = shared_dir() / "fixtures" / "ca"
LOOPBACK_OK = probe.TargetPolicy(allow_loopback=True)
NOW = dt.datetime.fromisoformat(load_manifest()["pinned_now"].replace("Z", "+00:00"))


@contextmanager
def tls_server(case: str, *, ctx: ssl.SSLContext | None = None) -> Iterator[int]:
    """Serve one fixture case's chain.pem/key.pem on an ephemeral loopback port, for one connection."""
    if ctx is None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CA / "cases" / case / "chain.pem", CA / "cases" / case / "key.pem")
    lsock = socket.create_server(("127.0.0.1", 0))
    lsock.settimeout(5)
    port = lsock.getsockname()[1]

    def serve() -> None:
        try:
            conn, _ = lsock.accept()
        except OSError:
            return
        with conn:
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except (OSError, ssl.SSLError):
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield port
    finally:
        lsock.close()
        t.join(5)


def keys(r: probe.ProbeResult) -> set[tuple[str, str, str]]:
    return {f.key() for f in r.findings}


def test_good_chain_via_resolve_override() -> None:
    with tls_server("good") as port:
        t = probe.Target("good.example.test", port, connect_ip="127.0.0.1")
        r = probe.run(t, timeout=5, now=NOW, anchors=CA / "root.pem", policy=LOOPBACK_OK)
    assert r.error is None
    assert r.connected_ip == "127.0.0.1" and r.resolver == "override"
    assert r.tls_version in ("TLSv1.2", "TLSv1.3")
    assert len(r.chain) == 2
    assert ("trust", "pass", "trust") in keys(r)
    assert ("connected-ip", "info", "connection") in keys(r)
    assert "Connected to 127.0.0.1" in {f.title for f in r.findings}
    assert r.worst == Severity.PASS or r.worst == Severity.INFO


def test_wrong_name_is_reported() -> None:
    with tls_server("good") as port:
        r = probe.run(
            probe.Target("other.example.test", port, connect_ip="127.0.0.1"),
            timeout=5,
            now=NOW,
            anchors=CA / "root.pem",
            policy=LOOPBACK_OK,
        )
    assert ("trust", "fail", "trust") in keys(r)
    assert any(f.id == "host" and f.severity == Severity.FAIL for f in r.findings)


def test_chain_kept_in_presented_order() -> None:
    with tls_server("good") as port:
        r = probe.run(
            probe.Target("good.example.test", port, connect_ip="127.0.0.1"), timeout=5, now=NOW, policy=LOOPBACK_OK
        )
    assert [c.is_self_issued for c in r.chain] == [False, False]
    assert r.chain[0].matches("good.example.test")
    assert ("trust", "fail", "trust") in keys(r)  # fixture root is not in the system store


def test_refused_port_is_single_failure() -> None:
    s = socket.create_server(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = probe.run(probe.Target("good.example.test", port, connect_ip="127.0.0.1"), timeout=2, policy=LOOPBACK_OK)
    assert r.error
    assert [f.key() for f in r.findings][0] == ("probe", "fail", "connection")
    assert r.connected_ip == "127.0.0.1"


def test_literal_ip_is_not_resolved_or_sent_as_sni() -> None:
    assert probe.resolve(probe.Target("127.0.0.1", 443), LOOPBACK_OK) == (["127.0.0.1"], "literal")


@pytest.mark.parametrize("host", ["", "a b", "x/y", "user@host", "a" * 254])
def test_invalid_hosts_rejected(host: str) -> None:
    r = probe.run(probe.Target(host, 443))
    assert r.findings[0].id == "probe" and r.connected_ip is None


def test_default_context_is_tls12_plus() -> None:
    ctx = probe.default_context()
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1 is deprecated:DeprecationWarning")
def test_default_context_refuses_tls10_server() -> None:
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        sctx.minimum_version = ssl.TLSVersion.TLSv1
        sctx.maximum_version = ssl.TLSVersion.TLSv1
        sctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pytest.skip("this OpenSSL cannot run a TLS 1.0 server")
    sctx.load_cert_chain(CA / "cases" / "good" / "chain.pem", CA / "cases" / "good" / "key.pem")
    with tls_server("good", ctx=sctx) as port:
        r = probe.run(probe.Target("good.example.test", port, connect_ip="127.0.0.1"), timeout=5, policy=LOOPBACK_OK)
    assert r.error is not None and r.tls_version is None
    assert r.findings[0].key() == ("probe", "fail", "connection")


def test_openssl_command_is_quoted() -> None:
    cmd = probe.openssl_command(probe.Target("good.example.test", 8443, connect_ip="192.0.2.10"))
    assert cmd.startswith("openssl s_client -connect 192.0.2.10:8443 -servername good.example.test")


def test_loopback_denied_by_default() -> None:
    r = probe.run(
        probe.Target("good.example.test", 443, connect_ip="127.0.0.1"), timeout=1, policy=probe.TargetPolicy()
    )
    assert r.findings[0].id == "probe" and "loopback" in (r.error or "")
    assert r.connected_ip is None  # nothing was connected


@pytest.mark.parametrize(
    "addr",
    [
        "169.254.169.254",
        "fd00:ec2::254",
        "169.254.10.1",
        "fe80::1",
        "::ffff:169.254.169.254",
        "::ffff:127.0.0.1",
        "0.0.0.0",  # noqa: S104  denied-address test value
        "::",
        "0.1.2.3",  # 0.0.0.0/8
        str(ipaddress.IPv4Address(0x646464C8)),  # Alibaba Cloud metadata (integer: CGNAT scan)
        "64:ff9b::a9fe:a9fe",  # NAT64 of 169.254.169.254
        "64:ff9b::7f00:1",  # NAT64 of 127.0.0.1
        "2002:a9fe:a9fe::1",  # 6to4 of 169.254.169.254
        "2002:7f00:1::1",  # 6to4 of 127.0.0.1
        "::169.254.169.254",  # IPv4-compatible
        "::127.0.0.1",
        "::ffff:" + str(ipaddress.IPv4Address(0x646464C8)),
    ],
)
def test_default_policy_denies(addr: str) -> None:
    with pytest.raises(probe.TargetDenied):
        probe.TargetPolicy().check(addr, 443)


@pytest.mark.parametrize("addr", ["192.0.2.10", "10.0.0.5", "2001:db8::1", "198.51.100.7"])
def test_default_policy_allows_ordinary_hosts(addr: str) -> None:
    probe.TargetPolicy().check(addr, 443)


def test_policy_own_port_and_config() -> None:
    pol = probe.TargetPolicy.from_env(
        {"CERTCHECK_PROBE_ALLOW_LOOPBACK": "1", "CERTCHECK_PORT": "8080", "CERTCHECK_PROBE_DENY": "203.0.113.0/24"}
    )
    pol.check("127.0.0.1", 8443)
    for addr in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):  # own port is denied on loopback
        with pytest.raises(probe.TargetDenied, match="own port"):
            pol.check(addr, 8080)
    for addr in ("192.0.2.10", "2001:db8::1", "10.0.0.5"):  # ...but any other host may serve 8080 (spec)
        pol.check(addr, 8080)
    with pytest.raises(probe.TargetDenied, match="denied range"):
        pol.check("203.0.113.9", 443)
    assert probe.TargetPolicy.from_env(
        {"CERTCHECK_PROBE_ALLOW_METADATA": "1", "CERTCHECK_PROBE_ALLOW_LINK_LOCAL": "1"}
    ).allow_metadata


def test_own_port_denied_on_container_addresses() -> None:
    own = frozenset({ipaddress.ip_address("10.0.0.7"), ipaddress.ip_address("2001:db8::7")})
    pol = probe.TargetPolicy(own_ports=frozenset({8080}), own_addresses=own)
    for addr in ("10.0.0.7", "2001:db8::7", "::ffff:10.0.0.7", "64:ff9b::a00:7"):
        with pytest.raises(probe.TargetDenied, match="own port"):
            pol.check(addr, 8080)
        pol.check(addr, 443)
    pol.check("10.0.0.8", 8080)
    with pytest.raises(probe.TargetDenied):  # unspecified: denied anyway, and named as own port first
        pol.check("::", 8080)


def test_policy_from_env_reads_container_addresses_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []

    def fail(*a: object, **k: object) -> list[object]:
        calls.append(a)
        raise OSError("no name")

    def ok(*a: object, **k: object) -> list[object]:
        calls.append(a)
        return [(socket.AF_INET, 1, 6, "", ("10.0.0.7", 0))]

    probe.forget_container_addresses()
    try:
        monkeypatch.setattr(socket, "getaddrinfo", fail)
        assert probe.TargetPolicy.from_env({}).own_addresses == frozenset()  # failure: not cached
        monkeypatch.setattr(socket, "getaddrinfo", ok)
        assert probe.TargetPolicy.from_env({}).own_addresses == {ipaddress.ip_address("10.0.0.7")}
        monkeypatch.setattr(socket, "getaddrinfo", fail)
        assert probe.TargetPolicy.from_env({}).own_addresses == {ipaddress.ip_address("10.0.0.7")}  # cached
        assert len(calls) == 2
    finally:
        probe.forget_container_addresses()


def teredo(server: str, client: str, port: int = 40000) -> str:
    """Build a Teredo address (RFC 4380: client address and port stored inverted)."""
    s, c = int(ipaddress.IPv4Address(server)), int(ipaddress.IPv4Address(client))
    return str(ipaddress.IPv6Address((0x20010000 << 96) | (s << 64) | ((port ^ 0xFFFF) << 32) | (c ^ 0xFFFFFFFF)))


def test_teredo_judges_server_and_client() -> None:
    pol = probe.TargetPolicy()
    t = ipaddress.ip_address(teredo("192.0.2.1", "198.51.100.7"))
    assert probe.judged_addresses(t) == (ipaddress.ip_address("192.0.2.1"), ipaddress.ip_address("198.51.100.7"))
    pol.check(str(t), 443)
    for server, client in (("169.254.169.254", "192.0.2.1"), ("192.0.2.1", "169.254.169.254")):
        with pytest.raises(probe.TargetDenied, match="metadata"):
            pol.check(teredo(server, client), 443)
    with pytest.raises(probe.TargetDenied, match="loopback"):
        pol.check(teredo("192.0.2.1", "127.0.0.1"), 443)


def test_resolver_slot_released_when_submit_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> object:
        raise RuntimeError("cannot schedule new futures after shutdown")

    monkeypatch.setattr(probe._resolver_pool, "submit", boom)
    for _ in range(probe.RESOLVER_THREADS + 2):  # would hit "resolver busy" if slots leaked
        with pytest.raises(RuntimeError, match="shutdown"):
            probe.resolve(probe.Target("x.example.test", 443), LOOPBACK_OK)
    monkeypatch.undo()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, 1, 6, "", ("192.0.2.10", 443))])
    assert probe.resolve(probe.Target("ok.example.test", 443), LOOPBACK_OK)[0] == ["192.0.2.10"]


@pytest.mark.parametrize("port", ["", "http", "0", "65536", "-1", "80 80", "８０８０"])
def test_bad_own_port_fails_closed(port: str) -> None:
    with pytest.raises(ValueError, match="CERTCHECK_PORT"):
        probe.TargetPolicy.from_env({"CERTCHECK_PORT": port})


def test_bad_own_port_blocks_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CERTCHECK_PORT", "http")
    r = probe.run(probe.Target("192.0.2.10", 443), timeout=1)
    assert r.error and "CERTCHECK_PORT" in r.error and r.connected_ip is None


@pytest.mark.parametrize(
    ("v6", "v4"),
    [
        ("::ffff:192.0.2.1", "192.0.2.1"),
        ("64:ff9b::c000:201", "192.0.2.1"),
        ("2002:c000:201::", "192.0.2.1"),
        ("::192.0.2.1", "192.0.2.1"),
        ("::1", "::1"),
        ("::", "::"),
        ("2001:db8::1", "2001:db8::1"),
    ],
)
def test_embedded_ipv4(v6: str, v4: str) -> None:
    assert str(probe.embedded_ipv4(ipaddress.ip_address(v6))) == v4


def test_hung_lookups_cannot_exhaust_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lookups that never return hold their slot; once all are held, new lookups fail fast."""
    gate = threading.Event()

    def hang(*a: object, **k: object) -> list[object]:
        gate.wait(10)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", hang)
    try:
        for _ in range(probe.RESOLVER_THREADS):
            with pytest.raises(OSError, match="timed out"):
                probe.resolve(probe.Target("hang.example.test", 443), LOOPBACK_OK, timeout=0.05)
        t0 = time.monotonic()
        with pytest.raises(OSError, match="resolver busy"):
            probe.resolve(probe.Target("hang.example.test", 443), LOOPBACK_OK, timeout=5)
        assert time.monotonic() - t0 < 0.5
    finally:
        gate.set()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:  # slots come back once the lookups really finish
        if probe._resolver_slots.acquire(blocking=False):
            probe._resolver_slots.release()
            break
        time.sleep(0.01)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, 1, 6, "", ("192.0.2.10", 443))])
    assert probe.resolve(probe.Target("ok.example.test", 443), LOOPBACK_OK)[0] == ["192.0.2.10"]


def test_policy_applies_to_dns_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    """A public name resolving to the metadata address is refused (DNS cannot sidestep the policy)."""
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]
    )
    r = probe.run(probe.Target("meta.example.test", 443), timeout=1, policy=LOOPBACK_OK)
    assert r.error and "metadata" in r.error and r.connected_ip is None


def test_name_lookup_has_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(*a: object, **k: object) -> list[object]:
        time.sleep(2)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", slow)
    t0 = time.monotonic()
    with pytest.raises(OSError, match="timed out"):
        probe.resolve(probe.Target("slow.example.test", 443), LOOPBACK_OK, timeout=0.2)
    assert time.monotonic() - t0 < 1.5


def test_each_address_tried_once_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """First address refuses (simulated), second is the TLS server."""
    real = socket.create_connection
    tried: list[str] = []

    def connect(addr: tuple[str, int], *a: object, **k: object) -> socket.socket:
        tried.append(addr[0])
        if addr[0] == "::1":
            raise ConnectionRefusedError("refused")
        return real(addr, *a, **k)  # type: ignore[arg-type]

    with tls_server("good") as port:
        answers = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answers)
        monkeypatch.setattr(socket, "create_connection", connect)
        r = probe.run(probe.Target("good.example.test", port), timeout=5, now=NOW, policy=LOOPBACK_OK)
    assert r.error is None and r.connected_ip == "127.0.0.1"
    assert tried == ["::1", "127.0.0.1"]
    assert sum("failed" in line for line in r.transcript) == 1


def test_family_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 443)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answers)
    assert probe.resolve(probe.Target("dual.example.test", 443, family="ipv4"))[0] == ["192.0.2.10"]
    assert probe.resolve(probe.Target("dual.example.test", 443, family="ipv6"))[0] == ["2001:db8::1"]
    assert probe.resolve(probe.Target("dual.example.test", 443))[0] == ["2001:db8::1", "192.0.2.10"]


def test_connect_budget_is_split_across_fallback_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review S9: a black-holed first address gets only its share, so the working fallback still runs."""
    real = socket.create_connection
    budgets: list[tuple[str, float]] = []

    def connect(addr: tuple[str, int], timeout: float, *a: object, **k: object) -> socket.socket:
        budgets.append((addr[0], timeout))
        if addr[0] == "::1":
            time.sleep(timeout)  # a silent drop: the attempt uses exactly its share, then times out
            raise TimeoutError("timed out")
        return real(addr, timeout, *a, **k)  # type: ignore[arg-type]

    with tls_server("good") as port:
        answers = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answers)
        monkeypatch.setattr(socket, "create_connection", connect)
        r = probe.run(probe.Target("good.example.test", port), timeout=2, now=NOW, policy=LOOPBACK_OK)
    assert r.error is None and r.connected_ip == "127.0.0.1"
    (ip0, b0), (ip1, b1) = budgets
    assert ip0 == "::1" and 0.8 < b0 <= 1.0  # half of the 2 s budget
    assert ip1 == "127.0.0.1" and 0.8 < b1 <= 1.0  # the rest, for the last address
    assert r.duration_s is not None and r.duration_s < 2
