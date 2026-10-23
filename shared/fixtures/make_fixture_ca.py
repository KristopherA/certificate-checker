#!/usr/bin/env python3
"""Generate the TEST-ONLY fixture CA tree used for Mac/Linux trust-verdict parity (shared/golden).

These keys protect nothing and must never be used for a real service. Names are example.test,
addresses are RFC 5737. Dates are fixed so verdicts are stable at the pinned time in cases.json.
Every key is stored under OUT_DIR/keys/ and reused on the next run, serials are derived from the
certificate contents, and RSA PKCS#1 v1.5 signatures are deterministic, so re-running is byte-stable and
adding a case does not change existing fixtures (only the new case needs recording). Deleting keys/
regenerates everything: then re-record shared/golden (see shared/README.md).
Requires the 'cryptography' package (uv run --with cryptography ...).

Usage: make_fixture_ca.py [OUT_DIR]   (default: shared/fixtures/ca next to this script)
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import shutil
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PINNED_NOW = "2027-01-15T00:00:00Z"  # golden verdicts are recorded at this instant
UTC = dt.UTC
ORG = "Certificate Checker Fixtures"


def d(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s).replace(tzinfo=UTC)


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG)])


def serial_for(subject, issuer_name, start, end, ca, san, eku, hash_alg) -> int:
    """Deterministic positive 127-bit serial from the certificate's identity (incl. EKU and signature hash)."""
    ekus = ",".join(o.dotted_string for o in eku) if eku else "-"
    hname = hash_alg.name if hash_alg is not None else "sha256"
    ident = "|".join([subject.rfc4514_string(), issuer_name.rfc4514_string(), start, end, str(ca), repr(san), ekus, hname])
    return int.from_bytes(hashlib.sha256(ident.encode()).digest()[:16], "big") >> 1 or 1


KEYS: dict[str, object] = {}  # label -> private key, loaded from / saved to OUT_DIR/keys
KEY_DIR: Path | None = None


def key_spec(key) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return f"rsa-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"ec-{key.curve.name}"
    return type(key).__name__


def stored_key(label: str, spec: str, make):
    """Reuse OUT_DIR/keys/<label>.pem when present so fixtures stay byte-stable across runs.

    A stored key whose type or size differs from `spec` (e.g. after editing a case) is refused, not silently reused.
    """
    if label not in KEYS:
        assert KEY_DIR is not None
        f = KEY_DIR / f"{label}.pem"
        if f.exists():
            k = serialization.load_pem_private_key(f.read_bytes(), password=None)
            if key_spec(k) != spec:
                raise SystemExit(f"refusing: {f} is {key_spec(k)}, expected {spec}; delete it to regenerate")
            KEYS[label] = k
        else:
            KEYS[label] = make()
            f.write_bytes(key_pem(KEYS[label]))
    return KEYS[label]


def rsa_key(label: str, bits: int = 2048):
    return stored_key(label, f"rsa-{bits}", lambda: rsa.generate_private_key(public_exponent=65537, key_size=bits))


def ec_key(label: str):
    return stored_key(label, "ec-secp256r1", lambda: ec.generate_private_key(ec.SECP256R1()))


def build(
    subject,
    key,
    issuer_name,
    issuer_key,
    start,
    end,
    *,
    ca=False,
    pathlen=None,
    san=None,
    eku=None,
    ku=True,
    hash_alg=None,
    issuer_cert=None,
):
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial_for(subject, issuer_name, start, end, ca, san, eku, hash_alg))
        .not_valid_before(d(start))
        .not_valid_after(d(end))
    )
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen if ca else None), critical=True)
    if ku:
        b = b.add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=not ca and isinstance(key, rsa.RSAPrivateKey),
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    if issuer_cert is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    if san:
        gn = [
            x509.IPAddress(ipaddress.ip_address(v[3:]))
            if v.startswith("IP:")
            else x509.RFC822Name(v[6:])
            if v.startswith("email:")
            else x509.DNSName(v)
            for v in san
        ]
        b = b.add_extension(x509.SubjectAlternativeName(gn), critical=False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    c = b.sign(issuer_key, hashes.SHA256())
    return resign_sha1(c, issuer_key) if isinstance(hash_alg, hashes.SHA1) else c


SHA256_RSA = bytes.fromhex("06092a864886f70d01010b0500")
SHA1_RSA = bytes.fromhex("06092a864886f70d0101050500")


def resign_sha1(c, issuer_key):
    """cryptography no longer signs with SHA-1, so swap the (same-length) algorithm identifiers
    and re-sign the TBS bytes with RSA PKCS#1 v1.5 + SHA-1. Fixture use only."""
    der = c.public_bytes(serialization.Encoding.DER)
    assert der.count(SHA256_RSA) == 2, "expected the algorithm identifier in TBS and outer"
    der = der.replace(SHA256_RSA, SHA1_RSA)
    tbs = x509.load_der_x509_certificate(der).tbs_certificate_bytes
    sig = issuer_key.sign(tbs, padding.PKCS1v15(), hashes.SHA1())
    n = issuer_key.key_size // 8
    assert len(sig) == n
    return x509.load_der_x509_certificate(der[:-n] + sig)


def pem(c) -> bytes:
    return c.public_bytes(serialization.Encoding.PEM)


def key_pem(k) -> bytes:
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def main(argv: list[str]) -> int:
    global KEY_DIR
    out = Path(argv[0]) if argv else Path(__file__).resolve().parent / "ca"
    if out.exists() and any(out.iterdir()) and not (out / "cases.json").is_file():
        raise SystemExit(f"refusing to overwrite {out}: not empty and holds no cases.json")
    # Only the generated cases/ tree is replaced; keys/ is kept and reused.
    if (out / "cases").exists():
        shutil.rmtree(out / "cases")
    (out / "cases").mkdir(parents=True)
    KEY_DIR = out / "keys"
    KEY_DIR.mkdir(exist_ok=True)
    SA, CA_ = [ExtendedKeyUsageOID.SERVER_AUTH], [ExtendedKeyUsageOID.CLIENT_AUTH]

    root_k = rsa_key("root", 3072)
    root = build(name("Fixture Root CA"), root_k, name("Fixture Root CA"), root_k, "2026-01-01", "2036-01-01", ca=True)
    int_k = rsa_key("intermediate")
    inter = build(
        name("Fixture Issuing CA"),
        int_k,
        root.subject,
        root_k,
        "2026-01-01",
        "2034-01-01",
        ca=True,
        pathlen=0,
        issuer_cert=root,
    )
    (out / "root.pem").write_bytes(pem(root))
    (out / "intermediate.pem").write_bytes(pem(inter))

    def leaf(cn, start="2026-06-01", end="2027-07-02", *, key=None, san="default", eku=SA, **kw):
        k = key or rsa_key("leaf-" + cn.replace("*", "star"))
        s = [cn] if san == "default" else san
        c = build(name(cn), k, inter.subject, int_k, start, end, san=s, eku=eku, issuer_cert=inter, **kw)
        return c, k

    cases = []

    def case(cname, desc, files, host, purpose="server", mac_differs=""):
        d_ = out / "cases" / cname
        d_.mkdir()
        listed = []
        for fname, data in files:
            (d_ / fname).write_bytes(data)
            listed.append(fname)
        cases.append(
            {
                "name": cname,
                "description": desc,
                "files": listed,
                "hostname": host,
                "purpose": purpose,
                **({"known_difference": mac_differs} if mac_differs else {}),
            }
        )

    def std(cname, desc, c, k, host, purpose="server", order="leaf-first", **extra):
        chain = pem(c) + pem(inter) if order == "leaf-first" else pem(inter) + pem(c)
        files = [("chain.pem", chain if order != "leaf-only" else pem(c)), ("key.pem", key_pem(k))]
        case(cname, desc, files, host, purpose, **extra)

    c, k = leaf("good.example.test", san=["good.example.test", "www.good.example.test"])
    std("good", "Valid leaf + intermediate, serverAuth, SAN matches, 396-day lifetime", c, k, "good.example.test")
    std("misordered", "Same leaf, bundle lists the intermediate first", c, k, "good.example.test", order="int-first")
    std("leaf-only", "Leaf without its intermediate", c, k, "good.example.test", order="leaf-only")
    std("wrong-host", "Valid leaf checked against a name it does not cover", c, k, "other.example.test")
    case(
        "key-mismatch",
        "Leaf + intermediate with an unrelated private key",
        [("chain.pem", pem(c) + pem(inter)), ("key.pem", key_pem(rsa_key("unrelated")))],
        "good.example.test",
    )
    c, k = leaf("expired.example.test", "2025-01-01", "2026-01-01")
    std("expired", "Leaf expired before the pinned time", c, k, "expired.example.test")
    c, k = leaf("future.example.test", "2027-06-01", "2028-06-01")
    std("not-yet-valid", "Leaf notBefore after the pinned time", c, k, "future.example.test")
    c, k = leaf("soon.example.test", "2026-02-01", "2027-01-30")
    std(
        "expiring-soon",
        "Leaf expires 15 days after the pinned time (warn window is 30 days)",
        c,
        k,
        "soon.example.test",
    )
    c, k = leaf("weak.example.test", key=rsa_key("weak-rsa1024", 1024))
    std("weak-rsa1024", "1024-bit RSA leaf key", c, k, "weak.example.test")
    c, k = leaf("sha1.example.test", hash_alg=hashes.SHA1())
    std("sha1-signature", "Leaf signed with SHA-1", c, k, "sha1.example.test")
    c, k = leaf("nosan.example.test", san=None)
    std("no-san", "Leaf with no SAN; host only in the CN", c, k, "nosan.example.test")
    c, k = leaf("client.example.test", eku=CA_)
    std("client-eku-only", "clientAuth-only EKU checked as a TLS server", c, k, "client.example.test")
    std("client-purpose", "clientAuth-only EKU checked as a TLS client", c, k, "client.example.test", purpose="client")
    c, k = leaf("noeku.example.test", eku=None)
    std("no-eku", "Leaf with no EKU extension", c, k, "noeku.example.test")
    c, k = leaf("long.example.test", "2026-06-01", "2028-09-04")
    std("long-validity", "Private-CA leaf with an 826-day lifetime (over 398)", c, k, "long.example.test")
    c, k = leaf("ec.example.test", key=ec_key("ec-p256"))
    std("ec-p256", "ECDSA P-256 leaf", c, k, "ec.example.test")
    c, k = leaf("*.wild.example.test", san=["*.wild.example.test"])
    std("wildcard", "Wildcard leaf checked against a covered name", c, k, "a.wild.example.test")
    std("wildcard-too-deep", "Wildcard leaf checked against a two-label-deeper name", c, k, "a.b.wild.example.test")
    c, k = leaf("ip.example.test", san=["ip.example.test", "IP:192.0.2.10"])
    std("ip-san", "Leaf with an IP SAN (RFC 5737), checked by IP", c, k, "192.0.2.10")
    c, k = leaf("ipsan-cn.example.test", san=["IP:192.0.2.11"])
    std(
        "ip-only-san-cn-host",
        "SAN holds only an IP; the checked name is only in the CN (CN fallback must not apply)",
        c,
        k,
        "ipsan-cn.example.test",
    )
    c, k = leaf("mailsan-cn.example.test", san=["email:pki@example.test"])
    std(
        "email-only-san-cn-host",
        "SAN holds only an email address; the checked name is only in the CN",
        c,
        k,
        "mailsan-cn.example.test",
    )
    c, k = leaf("anyeku.example.test", eku=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE])
    std("any-eku-only", "Leaf whose only EKU is anyExtendedKeyUsage", c, k, "anyeku.example.test")
    ca_k = rsa_key("ca-as-leaf")
    ca_leaf = build(
        name("calike.example.test"),
        ca_k,
        inter.subject,
        int_k,
        "2026-06-01",
        "2027-07-02",
        ca=True,
        san=["calike.example.test"],
        eku=SA,
        issuer_cert=inter,
    )
    std("ca-as-leaf", "Leaf with Basic Constraints CA:TRUE", ca_leaf, ca_k, "calike.example.test")
    ss_k = rsa_key("self-signed")
    ss = build(
        name("self.example.test"),
        ss_k,
        name("self.example.test"),
        ss_k,
        "2026-06-01",
        "2027-07-02",
        san=["self.example.test"],
        eku=SA,
    )
    case(
        "self-signed",
        "Self-signed leaf (appliance default style)",
        [("chain.pem", pem(ss)), ("key.pem", key_pem(ss_k))],
        "self.example.test",
    )

    manifest = {
        "schema": 1,
        "pinned_now": PINNED_NOW,
        "root": "root.pem",
        "intermediate": "intermediate.pem",
        "note": "TEST-ONLY keys (keys/). Re-running reuses them; deleting keys/ means re-recording shared/golden.",
        "cases": cases,
    }
    (out / "cases.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} cases to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
