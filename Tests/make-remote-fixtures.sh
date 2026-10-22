#!/bin/bash
# TEST-ONLY RDP / WinRM certificates under the test issuing CA (int.pem). Keys protect nothing.
set -euo pipefail
cd "$(dirname "$0")/Fixtures"
OPENSSL="$(brew --prefix openssl@3 2>/dev/null)/bin/openssl"; [ -x "$OPENSSL" ] || OPENSSL=openssl
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
O() { "$OPENSSL" "$@" 2>/dev/null; }
issue() { # name ext-lines
  O req -new -newkey rsa:2048 -nodes -keyout "rdp-$1.key" -out "$T/$1.csr" -subj "/CN=rdp.example.test"
  printf "$2" > "$T/$1.ext"
  O x509 -req -in "$T/$1.csr" -CA int.pem -CAkey int.key -CAcreateserial -out "$T/$1.crt" -days 365 -sha256 -extfile "$T/$1.ext"
  cat "$T/$1.crt" int.pem > "rdp-$1.pem"
}
# Remote Desktop Authentication EKU only (accepted by RDP, not by a generic TLS server policy).
issue rda 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=1.3.6.1.4.1.311.54.1.2\nsubjectAltName=DNS:rdp.example.test,IP:127.0.0.1\n'
# Client Authentication only: must fail for RDP.
issue clientonly 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:rdp.example.test,IP:127.0.0.1\n'
# Like the Windows default RDP certificate: self-signed, CN only, Server Authentication, 180 days, no basicConstraints.
O req -x509 -newkey rsa:2048 -nodes -keyout rdp-selfsigned.key -out rdp-selfsigned.pem -days 180 -sha256 -subj "/CN=host1.example.test" \
  -addext "extendedKeyUsage=serverAuth" -addext "keyUsage=keyEncipherment,dataEncipherment" -addext "basicConstraints=CA:FALSE"
# Same shape, but expired: the trust failure must NOT be downgraded.
O req -x509 -newkey rsa:2048 -nodes -keyout rdp-selfexpired.key -out rdp-selfexpired.pem -not_before 20240101000000Z -not_after 20240630000000Z -sha256 -subj "/CN=host1.example.test" \
  -addext "extendedKeyUsage=serverAuth" -addext "keyUsage=keyEncipherment,dataEncipherment" -addext "basicConstraints=CA:FALSE"
rm -f ./*.srl
echo "Remote-access fixtures written."
