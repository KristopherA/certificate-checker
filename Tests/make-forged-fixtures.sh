#!/bin/bash
# TEST-ONLY forged-anchor certificates (0.10.1). SYNTHETIC: no private key is kept.
#   SYNTHETIC-forged-dsm.pem / -pve.pem: a leaf plus a fake self-issued "CA" holding the leaf issuer's key, but signed
#   by an unrelated key, so its self-signature does not verify. -leaf files hold the leaf alone.
#   SYNTHETIC-genuine-root.pem: a leaf under a real self-signed root.
set -euo pipefail
cd "$(dirname "$0")/Fixtures"
OPENSSL="$(brew --prefix openssl@3 2>/dev/null)/bin/openssl"; [ -x "$OPENSSL" ] || OPENSSL=openssl
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
O() { "$OPENSSL" "$@" 2>"$T/err" || { cat "$T/err" >&2; return 1; }; }
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=none\nauthorityKeyIdentifier=none\n' > "$T/ca.ext"
leafext() { printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$1"; }
forge() { # name ca-subject leaf-subject san
  O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/k.key"; O pkey -in "$T/k.key" -pubout -out "$T/k.pub"
  O req -new -key "$T/k.key" -subj "$2" -out "$T/ca.csr"
  # The real "CA" key K signs the leaf (issuer = $2), as an attacker's own CA would.
  O req -x509 -key "$T/k.key" -subj "$2" -days 3650 -out "$T/k.crt" -extensions v3_ca
  O req -new -newkey rsa:2048 -nodes -keyout "$T/l.key" -subj "$3" -out "$T/l.csr"
  leafext "$4" > "$T/l.ext"
  O x509 -req -in "$T/l.csr" -CA "$T/k.crt" -CAkey "$T/k.key" -set_serial 0x1001 -days 365 -sha256 -extfile "$T/l.ext" -out "$T/l.crt"
  # The fake top: subject = issuer = $2 and public key K, but signed by unrelated key Z.
  O req -x509 -newkey rsa:2048 -nodes -keyout "$T/z.key" -subj "$2" -days 3650 -out "$T/z.crt"
  O x509 -req -in "$T/ca.csr" -CA "$T/z.crt" -CAkey "$T/z.key" -force_pubkey "$T/k.pub" -set_serial 0x2002 -days 3650 -sha256 -extfile "$T/ca.ext" -out "$T/fake.crt"
  cat "$T/l.crt" "$T/fake.crt" > "SYNTHETIC-forged-$1.pem"; cp "$T/l.crt" "SYNTHETIC-forged-$1-leaf.pem"
}
forge dsm "/C=TW/L=Taipei/O=Synology Inc./CN=Synology Inc. CA" "/C=TW/L=Taipei/O=Synology Inc./CN=synology" "DNS:synology,DNS:nas.example.test"
forge pve "/CN=Proxmox Virtual Environment/OU=SYNTHETIC/O=PVE Cluster Manager CA" "/OU=PVE Cluster Node/O=Proxmox Virtual Environment/CN=pve1.example.test" "DNS:pve1.example.test"
forge radius "/O=SYNTHETIC/CN=Example Test RADIUS CA" "/O=SYNTHETIC/CN=radius.example.test" "DNS:radius.example.test"
# A genuine self-signed root and its leaf.
O req -x509 -newkey rsa:2048 -nodes -keyout "$T/r.key" -subj "/O=SYNTHETIC/CN=Example Test Genuine Root" -days 3650 -sha256 -out "$T/r.crt" -extensions v3_ca
O req -new -newkey rsa:2048 -nodes -keyout "$T/g.key" -subj "/O=SYNTHETIC/CN=radius.example.test" -out "$T/g.csr"
leafext "DNS:radius.example.test" > "$T/g.ext"
O x509 -req -in "$T/g.csr" -CA "$T/r.crt" -CAkey "$T/r.key" -set_serial 0x3003 -days 365 -sha256 -extfile "$T/g.ext" -out "$T/g.crt"
cat "$T/g.crt" "$T/r.crt" > SYNTHETIC-genuine-root.pem
echo "Forged-anchor fixtures written."
