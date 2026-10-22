#!/bin/bash
# TEST-ONLY Docker registry / Logstash Beats input / Elasticsearch / Beats client certificates. SYNTHETIC: keys protect nothing.
set -euo pipefail
cd "$(dirname "$0")/Fixtures"
OPENSSL="$(brew --prefix openssl@3 2>/dev/null)/bin/openssl"; [ -x "$OPENSSL" ] || OPENSSL=openssl
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
O() { "$OPENSSL" "$@" 2>/dev/null; }
ca() { # name subject  -> SYNTHETIC-<name>.pem (CA certificate only; its key stays in the temp folder)
  O req -x509 -newkey rsa:2048 -nodes -keyout "$T/$1.key" -out "SYNTHETIC-$1.pem" -days 3650 -sha256 -subj "$2" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
}
leaf() { # name ca subject eku san  -> SYNTHETIC-<name>.pem (leaf + CA) and SYNTHETIC-<name>.key
  O req -new -newkey rsa:2048 -nodes -keyout "SYNTHETIC-$1.key" -out "$T/$1.csr" -subj "$3"
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=%s\n%s' "$4" "${5:+subjectAltName=$5
}" > "$T/$1.ext"
  O x509 -req -in "$T/$1.csr" -CA "SYNTHETIC-$2.pem" -CAkey "$T/$2.key" -CAcreateserial -out "$T/$1.crt" -days 365 -sha256 -extfile "$T/$1.ext"
  cat "$T/$1.crt" "SYNTHETIC-$2.pem" > "SYNTHETIC-$1.pem"
}
ca stack-ca "/O=SYNTHETIC/CN=SYNTHETIC Stack CA"
ca other-ca "/O=SYNTHETIC/CN=SYNTHETIC Other CA"
leaf registry-server stack-ca "/CN=registry.example.test" serverAuth "DNS:registry.example.test,DNS:localhost,IP:127.0.0.1"
leaf logstash-server stack-ca "/CN=logstash.example.test" serverAuth "DNS:logstash.example.test,DNS:localhost,IP:127.0.0.1"
leaf es-server stack-ca "/CN=es.example.test" serverAuth "DNS:es.example.test,DNS:localhost,IP:127.0.0.1"
leaf beats-client stack-ca "/CN=beats01.example.test" clientAuth "DNS:beats01.example.test"
leaf beats-serveronly stack-ca "/CN=beats02.example.test" serverAuth "DNS:beats02.example.test"
leaf beats-otherca other-ca "/CN=beats03.example.test" clientAuth "DNS:beats03.example.test"
# Like an Elasticsearch 8 auto-configured HTTP certificate (security auto-configuration CA).
ca es-autoca "/CN=Elasticsearch security auto-configuration HTTP CA"
leaf es-auto es-autoca "/CN=es.example.test" serverAuth "DNS:es.example.test,DNS:localhost,IP:127.0.0.1"
# Client certificate whose only EKU is anyExtendedKeyUsage (self-signed end entity; used only for the EKU check).
O req -x509 -newkey rsa:2048 -nodes -keyout SYNTHETIC-beats-anyeku.key -out SYNTHETIC-beats-anyeku.pem -days 365 -sha256 -subj "/CN=beats04.example.test" \
  -addext "basicConstraints=CA:FALSE" -addext "extendedKeyUsage=2.5.29.37.0" -addext "subjectAltName=DNS:beats04.example.test"
rm -f ./*.srl
echo "Stack (registry / Beats / Elasticsearch) fixtures written."
