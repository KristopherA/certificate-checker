"""Address classification, resolv.conf parsing, split-DNS and firewall hints (certcheck.hints)."""

from __future__ import annotations

from pathlib import Path

import pytest

from certcheck import hints
from certcheck.hints import IPClass
from certcheck.model import Finding, Severity, Topic


@pytest.mark.parametrize(
    ("addr", "cls"),
    [
        ("10.0.0.5", IPClass.RFC1918),
        ("127.0.0.1", IPClass.LOOPBACK),
        ("192.0.2.10", IPClass.DOCUMENTATION),
        ("198.51.100.7", IPClass.DOCUMENTATION),
        ("::1", IPClass.LOOPBACK),
        ("::ffff:10.0.0.5", IPClass.RFC1918),
        ("fd00::1", IPClass.ULA),
        ("fe80::1", IPClass.LINK_LOCAL),
        ("2001:db8::1", IPClass.DOCUMENTATION),
        ("fe80::1%en0", None),
        ("host.example.test", None),
    ],
)
def test_classify(addr: str, cls: IPClass | None) -> None:
    assert hints.classify(addr) == cls


def test_nameservers(tmp_path: Path) -> None:
    p = tmp_path / "resolv.conf"
    p.write_text("# comment\nsearch example.test\nnameserver 10.0.0.53\nnameserver bogus\nnameserver 192.0.2.53 # x\n")
    assert hints.nameservers(p) == ["10.0.0.53", "192.0.2.53"]
    assert hints.nameservers(tmp_path / "missing") == []


@pytest.fixture
def documentation_is_public(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only RFC 5737 addresses may appear in this repo, so stand them in for public ones."""
    real = hints.classify

    def fake(s: str) -> IPClass | None:
        c = real(s)
        return IPClass.PUBLIC if c == IPClass.DOCUMENTATION else c

    monkeypatch.setattr(hints, "classify", fake)


@pytest.mark.usefixtures("documentation_is_public")
def test_split_dns_fires_on_public_answer_with_internal_resolver() -> None:
    f = hints.split_dns_warning("www.example.test", ["192.0.2.10"], "system", ["10.0.0.53"])
    assert f is not None and f.key() == ("split-dns", "warning", "connection")
    assert "/etc/resolv.conf" in f.detail and "dig @10.0.0.53 www.example.test" in f.detail
    assert "getent hosts www.example.test" in f.detail


@pytest.mark.usefixtures("documentation_is_public")
@pytest.mark.parametrize(
    ("host", "addrs", "source", "ns"),
    [
        ("www.example.test", ["192.0.2.10"], "override", ["10.0.0.53"]),  # connect IP given
        ("192.0.2.10", ["192.0.2.10"], "system", ["10.0.0.53"]),  # literal IP
        ("www.example.test", ["10.0.0.7"], "system", ["10.0.0.53"]),  # internal answer
        ("www.example.test", ["192.0.2.10"], "system", ["198.51.100.53"]),  # public resolver
        ("www.example.test", [], "system", ["10.0.0.53"]),
    ],
)
def test_split_dns_quiet(host: str, addrs: list[str], source: str, ns: list[str]) -> None:
    assert hints.split_dns_warning(host, addrs, source, ns) is None


def test_firewall_hint_needs_name_failure_and_split_dns() -> None:
    sd = Finding("split-dns", Severity.WARNING, Topic.CONNECTION, "x")
    host_fail = Finding("host", Severity.FAIL, Topic.HOSTNAME, "mismatch")
    host_pass = Finding("host", Severity.PASS, Topic.HOSTNAME, "ok")
    h = hints.firewall_hint([host_fail], sd)
    assert h is not None and h.key() == ("firewall-hint", "warning", "connection")
    assert hints.firewall_hint([host_pass], sd) is None
    assert hints.firewall_hint([host_fail], None) is None


@pytest.mark.usefixtures("documentation_is_public")
def test_split_dns_hint_names_the_real_nameserver_not_a_placeholder() -> None:
    f = hints.split_dns_warning("www.example.test", ["192.0.2.10"], "system", ["10.0.0.53"])
    assert f is not None
    assert "INTERNAL-IP" not in f.detail
    assert "--resolve www.example.test:$(dig +short @10.0.0.53 www.example.test | head -n 1)" in f.detail


def test_docker_desktop_net_is_the_documented_private_default() -> None:
    net = hints.DOCKER_DESKTOP_NET
    assert net.prefixlen == 24 and net.is_private
    assert hints.classify(str(net[7])) == IPClass.RFC1918
    assert hints.is_docker_resolver(str(net[7])) and hints.is_docker_resolver(str(net[254]))
    assert not hints.is_docker_resolver("10.0.0.53") and not hints.is_docker_resolver("bogus")


@pytest.mark.usefixtures("documentation_is_public")
def test_docker_desktop_resolver_is_not_split_dns() -> None:
    # The real Docker Desktop resolver (built from the constant, no literal), alone and next to a public one.
    ns = str(hints.DOCKER_DESKTOP_NET[7])
    assert hints.split_dns_warning("www.example.test", ["192.0.2.10"], "system", [ns]) is None
    assert hints.split_dns_warning("www.example.test", ["192.0.2.10"], "system", [ns, "198.51.100.53"]) is None
    # The embedded DNS of user-defined Docker networks is loopback, never "internal".
    assert hints.split_dns_warning("www.example.test", ["192.0.2.10"], "system", ["127.0.0.11"]) is None


@pytest.mark.usefixtures("documentation_is_public")
def test_docker_resolver_range_is_what_suppresses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand an allowed 10.0.0.0/24 in for the Docker range: the same resolver then stops triggering."""
    import ipaddress

    assert hints.split_dns_warning("www.example.test", ["192.0.2.10"], "system", ["10.0.0.53"]) is not None
    monkeypatch.setattr(hints, "DOCKER_RESOLVER_NETS", (ipaddress.ip_network("10.0.0.0/24"),))
    f = hints.split_dns_warning("www.example.test", ["192.0.2.10"], "system", ["10.0.0.53"])
    assert f is None
    # ... and so does the firewall hint, which needs a split-DNS finding (no false positive downstream).
    host_fail = Finding("host", Severity.FAIL, Topic.HOSTNAME, "mismatch")
    assert hints.firewall_hint([host_fail], f) is None
    # A second, non-Docker internal resolver still counts.
    g = hints.split_dns_warning("www.example.test", ["192.0.2.10"], "system", ["10.0.0.53", "fd00::53"])
    assert g is not None and "dig @fd00::53" in g.detail
