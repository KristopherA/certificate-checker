#!/bin/bash
# Generates throwaway IKEv2 test certificates. Test data only; keys are never used anywhere else.
set -euo pipefail
cd "$(dirname "$0")/Fixtures"
OPENSSL="$(brew --prefix openssl@3 2>/dev/null)/bin/openssl"; [ -x "$OPENSSL" ] || OPENSSL=openssl
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
O() { "$OPENSSL" "$@" 2>/dev/null; }
# CA
O req -x509 -newkey rsa:2048 -nodes -keyout "$T/ca.key" -out ipsec-ca.crt -days 3650 -sha256 -subj "/CN=Test IKEv2 CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
sign() { # name days ext-file [keyspec] [digest]
  O req -new -newkey "${4:-rsa:2048}" -nodes -keyout "ipsec-$1.key" -out "$T/$1.csr" -subj "/CN=$1.example.test"
  if [[ "$2" == *-* ]]; then dates=(-not_before "${2%-*}" -not_after "${2#*-}"); else dates=(-days "$2"); fi
  O x509 -req -in "$T/$1.csr" -CA "${CA:-ipsec-ca.crt}" -CAkey "${CAKEY:-$T/ca.key}" -CAcreateserial -out "ipsec-$1.crt" "${dates[@]}" -"${5:-sha256}" -extfile "$3"
}
cat > "$T/good.ext" <<X
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,1.3.6.1.5.5.8.2.2
subjectAltName=DNS:vpn.example.test,IP:203.0.113.10
X
cat > "$T/bad.ext" <<X
basicConstraints=CA:FALSE
keyUsage=critical,keyEncipherment
extendedKeyUsage=clientAuth
X
cat > "$T/plain.ext" <<X
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:*.example.test
X
cat > "$T/notca.ext" <<X
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyCertSign
X
sign server 397 "$T/good.ext"
O ecparam -name prime256v1 -out "$T/p256.pem"
sign ec 397 "$T/good.ext" "ec:$T/p256.pem"
sign bad 900 "$T/bad.ext" rsa:1024 sha1
sign wild 825 "$T/plain.ext"
# A "CA" without CA:TRUE that signs a server certificate.
sign fakeca 3650 "$T/notca.ext"
CA=ipsec-fakeca.crt CAKEY=ipsec-fakeca.key sign orphan 397 "$T/good.ext"
# Issued before 1 July 2019 (Apple's 825-day rule does not apply); long lifetime, now expired.
sign old 20190601000000Z-20220101000000Z "$T/good.ext"
# Expired intermediate CA issuing a current server certificate.
cat > "$T/ca.ext" <<X
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
X
sign intexp 20200101000000Z-20210101000000Z "$T/ca.ext"
CA=ipsec-intexp.crt CAKEY=ipsec-intexp.key sign underexp 397 "$T/good.ext"
# pathLen violation: root pathlen:0 -> intermediate CA -> server.
O req -x509 -newkey rsa:2048 -nodes -keyout "$T/pl0.key" -out ipsec-pl0-root.crt -days 3650 -sha256 -subj "/CN=Test PathLen0 Root" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign"
CA=ipsec-pl0-root.crt CAKEY="$T/pl0.key" sign plint 3650 "$T/ca.ext"
CA=ipsec-plint.crt CAKEY=ipsec-plint.key sign plleaf 397 "$T/good.ext"
# CA rollover: self-issued intermediate (same name, new key) under a pathlen:0 root; must NOT count toward pathLen.
O req -x509 -newkey rsa:2048 -nodes -keyout "$T/roll1.key" -out ipsec-rollroot.crt -days 3650 -sha256 -subj "/CN=Test Rollover CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash"
O req -new -newkey rsa:2048 -nodes -keyout "$T/roll2.key" -out "$T/roll2.csr" -subj "/CN=Test Rollover CA"
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$T/roll.ext"
O x509 -req -in "$T/roll2.csr" -CA ipsec-rollroot.crt -CAkey "$T/roll1.key" -CAcreateserial -out ipsec-roll.crt -days 3650 -sha256 -extfile "$T/roll.ext"
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:roll.example.test\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$T/rollleaf.ext"
CA=ipsec-roll.crt CAKEY="$T/roll2.key" sign rollleaf 397 "$T/rollleaf.ext"
# Root with AKI but no SKI (legacy CA), plus a rollover cert under it: the root must still count as self-signed.
O req -x509 -newkey rsa:2048 -nodes -keyout "$T/ak1.key" -out ipsec-akiroot.crt -days 3650 -sha256 -subj "/CN=Test AKI Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=none" -addext "authorityKeyIdentifier=keyid:always"
O req -new -newkey rsa:2048 -nodes -keyout "$T/ak2.key" -out "$T/ak2.csr" -subj "/CN=Test AKI Root"
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n' > "$T/akroll.ext"
# OpenSSL will not derive a key ID from an issuer without SKI, so sign the rollover with a same-key twin that has one.
O req -x509 -new -key "$T/ak1.key" -out "$T/aktwin.crt" -days 3650 -sha256 -subj "/CN=Test AKI Root" -addext "basicConstraints=critical,CA:TRUE" -addext "subjectKeyIdentifier=hash"
O x509 -req -in "$T/ak2.csr" -CA "$T/aktwin.crt" -CAkey "$T/ak1.key" -CAcreateserial -out ipsec-akiroll.crt -days 3650 -sha256 -extfile "$T/akroll.ext"
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:akileaf.example.test\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$T/akleaf.ext"
CA=ipsec-akiroll.crt CAKEY="$T/ak2.key" sign akileaf 397 "$T/akleaf.ext"
O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ipsec-other.key
rm -f ipsec-*.srl ipsec-old.key ipsec-intexp.key ipsec-underexp.key ipsec-plint.key ipsec-plleaf.key ipsec-rollleaf.key ipsec-bad.key ipsec-wild.key ipsec-fakeca.key ipsec-orphan.key ipsec-akileaf.key
echo "IPsec fixtures written."
