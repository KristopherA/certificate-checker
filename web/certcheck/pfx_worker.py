"""PKCS#12 decryption in a separate, time-limited process (review M3c).

Iteration counts inside encrypted SafeContents are only visible after decryption, so pfx.read_params cannot cap
them up front. filecheck.load_pkcs12 runs cryptography's load_pkcs12 here instead, and kills this process when
it exceeds PFX_TIME_BUDGET_S. Input on stdin (never argv or a file): 4-byte big-endian password length, the
UTF-8 password, then the PFX bytes. Output on stdout: one JSON object with DER certificates (base64) and the
key's SubjectPublicKeyInfo. Nothing is logged; the password exists only in this process's memory."""

from __future__ import annotations

import base64
import json
import sys


def main() -> int:
    raw = sys.stdin.buffer.read()
    n = int.from_bytes(raw[:4], "big")
    password, data = raw[4 : 4 + n], raw[4 + n :]
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, pkcs12

    try:
        p = pkcs12.load_pkcs12(data, password)
    except ValueError:
        out: dict[str, object] = {"status": "invalid"}
    else:
        certs = ([p.cert] if p.cert else []) + list(p.additional_certs)
        spki = None
        if p.key is not None and p.cert is not None:
            spki = p.key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        out = {
            "status": "ok",
            "certs": [base64.b64encode(c.certificate.public_bytes(Encoding.DER)).decode() for c in certs],
            "spki": base64.b64encode(spki).decode() if spki else None,
        }
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
