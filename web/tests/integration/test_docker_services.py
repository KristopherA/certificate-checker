"""Integration tests against real servers in throw-away containers (see shared/tools/integration.sh).

Skipped unless the runner exports CERTCHECK_IT_<SERVICE>=port. Containers listen on 127.0.0.1 only and present a
throw-away self-signed certificate for mail.example.test (MySQL presents its own auto-generated one).
"""

from __future__ import annotations

import os

import pytest

from certcheck import probe
from certcheck.services import Service

POLICY = probe.TargetPolicy(allow_loopback=True)
CASES = [
    ("SMTP", Service.SMTP_STARTTLS, "mail.example.test"),
    ("IMAP", Service.IMAP_STARTTLS, "mail.example.test"),
    ("POP3", Service.POP3_STARTTLS, "mail.example.test"),
    ("LDAP", Service.LDAP_STARTTLS, "mail.example.test"),
    ("MYSQL", Service.MYSQL, None),
]


@pytest.mark.parametrize(("env", "service", "san"), CASES, ids=[c[0] for c in CASES])
def test_real_server_upgrade(env: str, service: Service, san: str | None) -> None:
    port = os.environ.get(f"CERTCHECK_IT_{env}")
    if not port:
        pytest.skip(f"CERTCHECK_IT_{env} not set (run shared/tools/integration.sh)")
    t = probe.Target(san or "db.example.test", int(port), connect_ip="127.0.0.1", service=service)
    r = probe.run(t, timeout=20, policy=POLICY, nameservers=[])
    assert r.error is None, (r.error, r.transcript)
    assert r.chain, r.transcript
    keys = {f.key() for f in r.findings}
    if san:
        assert ("host", "pass", "hostname") in keys, keys
    # Self-signed / auto-generated: never trusted by the system store.
    assert ("trust", "pass", "trust") not in keys
