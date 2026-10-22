#!/bin/bash
# Regenerates TEST-ONLY fixtures. These keys protect nothing and must never be used for a real service.
set -euo pipefail
OPENSSL="${OPENSSL:-/opt/homebrew/bin/openssl}"
D="$(cd "$(dirname "$0")" && pwd)/Fixtures"
mkdir -p "$D"; cd "$D"; rm -f ./*.pem ./*.key ./*.csr ./*.der ./*.p7b ./*.p12 ./*.cnf ./*.srl
cat > ext.cnf <<'CNF'
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
[leaf]
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:test.example.internal,DNS:*.wild.example.internal,IP:198.51.100.5,IP:127.0.0.1,DNS:localhost
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
[client]
basicConstraints=CA:FALSE
extendedKeyUsage=clientAuth
subjectAltName=DNS:client.example.internal
[nosan]
basicConstraints=CA:FALSE
extendedKeyUsage=serverAuth
CNF
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 3650 -subj "/CN=Test Root CA/O=Certificate Checker Fixtures" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
"$OPENSSL" req -new -newkey rsa:2048 -nodes -keyout int.key -out int.csr -subj "/CN=Test Issuing CA/O=Certificate Checker Fixtures" 2>/dev/null
"$OPENSSL" x509 -req -in int.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out int.pem -days 3000 -extfile ext.cnf -extensions ca 2>/dev/null
"$OPENSSL" genrsa -traditional -out leaf.rsa.key 2048 2>/dev/null
"$OPENSSL" pkcs8 -topk8 -nocrypt -in leaf.rsa.key -out leaf.key
"$OPENSSL" req -new -key leaf.key -out leaf.csr -subj "/CN=test.example.internal" -addext "subjectAltName=DNS:test.example.internal,DNS:*.wild.example.internal" 2>/dev/null
"$OPENSSL" x509 -req -in leaf.csr -CA int.pem -CAkey int.key -CAcreateserial -out leaf.pem -days 2900 -sha256 -extfile ext.cnf -extensions leaf 2>/dev/null
"$OPENSSL" x509 -in leaf.pem -outform DER -out leaf.der
cat leaf.pem int.pem > fullchain.pem
cat int.pem leaf.pem > misordered.pem
"$OPENSSL" crl2pkcs7 -nocrl -certfile leaf.pem -certfile int.pem -certfile ca.pem -out bundle.p7b -outform DER
"$OPENSSL" genrsa -out other.key 2048 2>/dev/null
# EC P-256 (SEC1 and PKCS#8) self-signed
"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out ec.sec1.key
"$OPENSSL" pkcs8 -topk8 -nocrypt -in ec.sec1.key -out ec.key
"$OPENSSL" req -x509 -key ec.key -out ec.pem -days 3000 -subj "/CN=ec.example.internal" -addext "subjectAltName=DNS:ec.example.internal" -addext "extendedKeyUsage=serverAuth" 2>/dev/null
"$OPENSSL" genpkey -algorithm ed25519 -out ed25519.key
"$OPENSSL" pkcs8 -topk8 -in leaf.key -out encrypted.key -passout pass:test -v2 aes-256-cbc
# Expired leaf
"$OPENSSL" x509 -req -in leaf.csr -CA int.pem -CAkey int.key -CAcreateserial -out expired.pem -not_before 20200101000000Z -not_after 20210101000000Z -extfile ext.cnf -extensions leaf 2>/dev/null
# Weak: 1024-bit RSA, SHA-1 signature
"$OPENSSL" req -new -newkey rsa:1024 -nodes -keyout weak.key -out weak.csr -subj "/CN=weak.example.internal" 2>/dev/null
"$OPENSSL" x509 -req -in weak.csr -CA int.pem -CAkey int.key -CAcreateserial -out weak.pem -days 2000 -sha1 -extfile ext.cnf -extensions leaf 2>/dev/null
"$OPENSSL" x509 -req -in leaf.csr -CA int.pem -CAkey int.key -CAcreateserial -out client.pem -days 2000 -extfile ext.cnf -extensions client 2>/dev/null
"$OPENSSL" x509 -req -in leaf.csr -CA int.pem -CAkey int.key -CAcreateserial -out nosan.pem -days 2000 -extfile ext.cnf -extensions nosan 2>/dev/null
"$OPENSSL" pkcs12 -export -in leaf.pem -inkey leaf.key -certfile int.pem -out leaf.p12 -passout pass:fixture-only -name "fixture" 2>/dev/null
rm -f ./*.srl weak.csr int.csr
echo "Fixtures regenerated in $D"
