"""M4 against real OpenSSL servers in a throw-away container (see shared/tools/integration-m4.sh).

Skipped unless the runner exports CERTCHECK_IT_M4_LEGACY / _STAPLE (ports) and CERTCHECK_IT_M4_CA (the CA PEM).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from certcheck import check, probe

POLICY = probe.TargetPolicy(allow_loopback=True)


def _env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        pytest.skip(f"{name} not set (run shared/tools/integration-m4.sh)")
    return v


def test_tls10_only_server() -> None:
    t = probe.Target("www.example.test", int(_env("CERTCHECK_IT_M4_LEGACY")), connect_ip="127.0.0.1")
    plain = check.run(t, policy=POLICY, nameservers=[], timeout=20)
    assert plain.error and "legacy-hint" in {f.id for f in plain.findings}, plain.error
    r = check.run(t, check.Options(legacy=True), policy=POLICY, nameservers=[], timeout=20)
    assert r.error is None and r.legacy and r.tls_version == "TLSv1", (r.error, r.transcript)
    f = {x.id: x for x in r.findings}
    assert f["legacy-TLSv1"].severity.label == "fail"


def test_stapled_ocsp_from_real_server() -> None:
    t = probe.Target("www.example.test", int(_env("CERTCHECK_IT_M4_STAPLE")), connect_ip="127.0.0.1")
    r = check.run(t, check.Options(revocation=True, legacy=True), policy=POLICY, nameservers=[], timeout=20,
                  anchors=Path(_env("CERTCHECK_IT_M4_CA")))  # fmt: skip
    assert r.error is None, (r.error, r.transcript)
    f = {x.id: x for x in r.findings}
    assert f["rev-0"].severity.label == "pass", (f["rev-0"].title, f["rev-0"].detail)
    assert r.contacted == []  # the stapled answer is used, the OCSP URL is never fetched
    assert f["legacy-none"].severity.label == "pass"
    assert r.trust is not None and r.trust.trusted
