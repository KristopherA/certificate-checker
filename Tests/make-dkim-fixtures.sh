#!/bin/bash
# TEST-ONLY DKIM keys and TXT records (0.9.0). SYNTHETIC: keys protect nothing and sign nothing.
set -euo pipefail
cd "$(dirname "$0")/Fixtures"
OPENSSL="${CC_OPENSSL:-$(command -v /opt/homebrew/opt/openssl@3/bin/openssl || command -v /usr/local/opt/openssl@3/bin/openssl || true)}"
[ -x "$OPENSSL" ] || { echo "make-dkim-fixtures.sh: OpenSSL 3 is required (brew install openssl@3, or set CC_OPENSSL)." >&2; exit 1; }
rec() { # key-file -> base64 SPKI
  "$OPENSSL" pkey -in "$1" -pubout -outform DER 2>/dev/null | base64 | tr -d '\n'
}
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out SYNTHETIC-dkim-2048.key 2>/dev/null
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out SYNTHETIC-dkim-1024.key 2>/dev/null
"$OPENSSL" genpkey -algorithm ED25519 -out SYNTHETIC-dkim-ed.key 2>/dev/null
printf 'v=DKIM1; k=rsa; p=%s\n' "$(rec SYNTHETIC-dkim-2048.key)" > SYNTHETIC-dkim-2048.txt
# Zone-file form, split into quoted strings, with sha1 allowed and testing mode on.
P="$(rec SYNTHETIC-dkim-1024.key)"
printf 'sel._domainkey IN TXT ( "v=DKIM1; h=sha1:sha256; t=y; k=rsa; "\n  "p=%s"\n  "%s" )\n' "${P:0:100}" "${P:100}" > SYNTHETIC-dkim-1024.txt
ED="$("$OPENSSL" pkey -in SYNTHETIC-dkim-ed.key -pubout -outform DER 2>/dev/null | tail -c 32 | base64)"
printf 'v=DKIM1; k=ed25519; p=%s\n' "$ED" > SYNTHETIC-dkim-ed.txt
printf 'v=DKIM1; k=rsa; p=\n' > SYNTHETIC-dkim-revoked.txt
