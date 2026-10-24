"""Result documents (the JSON the API returns and the UI renders/exports) and the Markdown export.

Everything here is data: HTML escaping is Jinja2's job (autoescape on for every template), Markdown export
escapes the characters that could form links or HTML in a viewer.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

from certcheck import guidance as gd
from certcheck.filecheck import FileReport
from certcheck.probe import ProbeResult, openssl_command
from certcheck.x509info import Cert


def cert_dict(c: Cert) -> dict[str, Any]:
    return {
        "subject": c.subject_text,
        "issuer": c.issuer_text,
        "name": c.display_name,
        "sha256": c.sha256,
        "not_before": c.not_before.isoformat(),
        "not_after": c.not_after.isoformat(),
        "dns_names": list(c.dns_names),
        "ip_addresses": list(c.ip_addresses),
        "key": c.key.description,
        "signature": c.signature_algorithm,
    }


def guidance_list(gs: list[gd.Guidance]) -> list[dict[str, Any]]:
    return [{"title": g.title, "steps": list(g.steps), "commands": list(g.commands)} for g in gs]


def probe_doc(r: ProbeResult, platform: gd.Platform) -> dict[str, Any]:
    t = r.target
    return {
        "kind": "probe",
        "target": {
            "host": t.host,
            "port": t.port,
            "profile": t.service.value,
            "sni": t.sni,
            "verify_name": t.verify_name,
            "connect_ip": t.connect_ip,
            "family": t.family,
            "platform": platform.value,
        },  # fmt: skip
        "connected_ip": r.connected_ip,
        "resolver": r.resolver,
        "tls_version": r.tls_version,
        "cipher": r.cipher,
        "legacy": r.legacy,
        "error": r.error,
        "duration_s": round(r.duration_s, 3),
        "worst": r.worst.label,
        "trust": None
        if r.trust is None
        else {"trusted": r.trust.trusted, "message": r.trust.message, "engine": r.trust.engine},  # fmt: skip
        "chain": [cert_dict(c) for c in r.chain],
        "findings": [f.as_dict() for f in r.findings],
        "contacted": list(r.contacted),
        "blocked": list(r.blocked),
        "transcript": list(r.transcript),
        "openssl_command": openssl_command(t),
        "guidance": guidance_list(gd.for_findings(r.findings, platform, t)),
    }


def file_doc(r: FileReport, names: list[str], hostname: str | None, purpose: str) -> dict[str, Any]:
    worst = max((f.severity for f in r.findings), default=None)
    return {
        "kind": "files",
        "files": names,
        "hostname": hostname,
        "purpose": purpose,
        "worst": worst.label if worst is not None else "info",
        "trust": None
        if r.trust is None
        else {"trusted": r.trust.trusted, "message": r.trust.message, "engine": r.trust.engine},  # fmt: skip
        "chain": [cert_dict(c) for c in r.chain],
        "requests": [
            {"subject": q.subject_text, "dns_names": list(q.dns_names), "key": q.key.description} for q in r.requests
        ],  # fmt: skip
        "keys": [k.description for k in r.keys],
        "findings": [f.as_dict() for f in r.findings],
        "guidance": guidance_list(gd.for_findings(r.findings, gd.Platform.GENERIC)),
    }


_MD = re.compile(r"([\\`*_{}\[\]()<>#+!|~])")


def _md(s: object) -> str:
    return _MD.sub(r"\\\1", " ".join(str(s).split()))


def markdown(doc: dict[str, Any]) -> str:
    lines: list[str] = []
    if doc["kind"] == "probe":
        t = doc["target"]
        lines += [f"# Certificate check: {_md(t['host'])}:{t['port']}", "",
                  f"- Profile: {_md(t['profile'])}",
                  f"- Connected IP: {_md(doc['connected_ip'] or 'none')} (resolver: {_md(doc['resolver'])})",
                  f"- TLS: {_md(doc['tls_version'] or 'none')} {_md(doc['cipher'] or '')}".rstrip()]  # fmt: skip
        if doc["legacy"]:
            lines.append("- LEGACY MODE: connected with TLS 1.0/1.1 (insecure)")
        if doc["error"]:
            lines.append(f"- Error: {_md(doc['error'])}")
    else:
        lines += [f"# File check: {_md(', '.join(doc['files']) or 'no files')}", "",
                  f"- Hostname: {_md(doc['hostname'] or 'none')}", f"- Purpose: {_md(doc['purpose'])}"]  # fmt: skip
    if doc["trust"]:
        lines.append(f"- Trust: {_md(doc['trust']['message'])}")
    lines += ["", "## Findings", ""]
    lines += [f"- **{f['severity'].upper()}** {_md(f['title'])}" + (f": {_md(f['detail'])}" if f["detail"] else "")
              for f in doc["findings"]]  # fmt: skip
    if doc["chain"]:
        lines += ["", "## Chain", ""]
        lines += [f"{i}. {_md(c['subject'])} (SHA-256 {c['sha256']}, expires {c['not_after']})"
                  for i, c in enumerate(doc["chain"])]  # fmt: skip
    if doc.get("contacted"):
        lines += ["", "## Contacted (AIA/OCSP/CRL)", ""] + [f"- {_md(u)}" for u in doc["contacted"]]
    if doc.get("blocked"):
        lines += ["", "## Blocked by the target policy (not contacted)", ""] + [f"- {_md(u)}" for u in doc["blocked"]]
    if doc["guidance"]:
        lines += ["", "## How to fix (copy only; review before running)", ""]
        for g in doc["guidance"]:
            lines += [f"### {_md(g['title'])}", ""] + [f"- {_md(s)}" for s in g["steps"]]
            if g["commands"]:
                lines += ["", "```sh", *[c.replace("```", "'''") for c in g["commands"]], "```"]
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def data_url(text: str, mime: str) -> str:
    """For the export links: the document travels inside the link, so nothing is stored on the server."""
    return f"data:{mime};charset=utf-8,{quote(text, safe='')}"


def exports(doc: dict[str, Any]) -> dict[str, str]:
    return {
        "json": data_url(json.dumps(doc, indent=2), "application/json"),
        "markdown": data_url(markdown(doc), "text/markdown"),
    }
