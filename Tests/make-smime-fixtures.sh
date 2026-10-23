#!/bin/bash
# TEST-ONLY S/MIME certificates (0.9.0). SYNTHETIC: keys protect nothing; addresses are @example.test. Self-signed is enough:
# the S/MIME check reads usage, address, expiry and strength, not trust.
set -euo pipefail
cd "$(dirname "$0")/Fixtures"
OPENSSL="${CC_OPENSSL:-$(command -v /opt/homebrew/opt/openssl@3/bin/openssl || command -v /usr/local/opt/openssl@3/bin/openssl || true)}"
[ -x "$OPENSSL" ] || { echo "make-smime-fixtures.sh: OpenSSL 3.4+ is required (brew install openssl@3, or set CC_OPENSSL)." >&2; exit 1; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mk() { # name bits days ext-lines [extra openssl args]
  local n="$1" bits="$2" days="$3" ext="$4"; shift 4
  printf '%b\n' "$ext" > "$T/$n.ext"
  "$OPENSSL" req -x509 -newkey "rsa:$bits" -nodes -keyout "$T/$n.key" -out "SYNTHETIC-smime-$n.pem" -sha256 -days "$days" \
    -subj "/O=SYNTHETIC/CN=SYNTHETIC SMIME $n" -extensions v3 -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n%b\n' "$ext") "$@" 2>"$T/err" \
    || { cat "$T/err" >&2; exit 1; }
}
mk good 2048 400 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=emailProtection\nsubjectAltName=email:alice@example.test'
mk signonly 2048 400 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=emailProtection\nsubjectAltName=email:alice@example.test'
mk server 2048 400 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=email:alice@example.test'
mk soon 2048 10 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=emailProtection\nsubjectAltName=email:alice@example.test'
mk weak 1024 400 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=emailProtection\nsubjectAltName=email:alice@example.test'
mk expired 2048 1 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=emailProtection\nsubjectAltName=email:alice@example.test' -not_before 20200101000000Z -not_after 20210101000000Z
mk noaddr 2048 400 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=emailProtection'
