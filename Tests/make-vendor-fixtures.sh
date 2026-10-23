#!/bin/bash
# TEST-ONLY Munki / FileMaker Server / Retrospect / HP printer EWS / Barracuda WAF look-alike certificates, plus wildcard,
# IP-SAN and expired-intermediate chains for the supplied-CA tests. SYNTHETIC: keys protect nothing; names are example.test.
set -euo pipefail
cd "$(dirname "$0")/Fixtures"
# -not_before/-not_after (expired intermediate) need OpenSSL 3.4+; macOS /usr/bin/openssl is LibreSSL. Fail loudly, never silently.
OPENSSL=""
for c in "${CC_OPENSSL:-}" /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do [ -n "$c" ] && [ -x "$c" ] && { OPENSSL="$c"; break; }; done
[ -n "$OPENSSL" ] || { echo "make-vendor-fixtures.sh: OpenSSL 3.4+ is required (brew install openssl@3, or set CC_OPENSSL). LibreSSL is not supported." >&2; exit 1; }
ver="$("$OPENSSL" version)"
case "$ver" in LibreSSL*) echo "make-vendor-fixtures.sh: $OPENSSL is LibreSSL ($ver); OpenSSL 3.4+ is required." >&2; exit 1;; esac
mm="$(printf '%s' "$ver" | awk '{print $2}')"; maj="${mm%%.*}"; rest="${mm#*.}"; min="${rest%%.*}"
if [ "$maj" -lt 3 ] || { [ "$maj" -eq 3 ] && [ "$min" -lt 4 ]; }; then echo "make-vendor-fixtures.sh: $ver is too old; OpenSSL 3.4+ is required for -not_before/-not_after." >&2; exit 1; fi
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
O() { "$OPENSSL" "$@" 2>"$T/err" || { echo "make-vendor-fixtures.sh: openssl $1 failed:" >&2; cat "$T/err" >&2; exit 1; }; }
ca() { # name subject -> SYNTHETIC-<name>.pem (CA certificate only; its key stays in the temp folder)
  O req -x509 -newkey rsa:2048 -nodes -keyout "$T/$1.key" -out "SYNTHETIC-$1.pem" -days 3650 -sha256 -subj "$2" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
}
sign() { # name issuer csr-subject ext-file [validity args...] -> $T/<name>.crt
  local n="$1" i="$2" s="$3" e="$4"; shift 4
  O req -new -newkey rsa:2048 -nodes -keyout "$T/$n.key" -out "$T/$n.csr" -subj "$s"
  O x509 -req -in "$T/$n.csr" -CA "$T/$i.crt" -CAkey "$T/$i.key" -CAcreateserial -out "$T/$n.crt" -sha256 -extfile "$e" "$@"
}
leafext() { printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=%s\n%s' "$1" "${2:+subjectAltName=$2
}" > "$T/ext.$3"; echo "$T/ext.$3"; }
ca vendor-ca "/O=SYNTHETIC/CN=SYNTHETIC Vendor CA"; cp SYNTHETIC-vendor-ca.pem "$T/vendor-ca.crt"
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$T/ext.ca"
# Intermediate that expired in 2021; the leaf under it is inside its own dates.
sign vendor-int-expired vendor-ca "/O=SYNTHETIC/CN=SYNTHETIC Expired Intermediate" "$T/ext.ca" -not_before 20200101000000Z -not_after 20210101000000Z
sign expint-server vendor-int-expired "/CN=expint.example.test" "$(leafext serverAuth 'DNS:expint.example.test,DNS:localhost,IP:127.0.0.1' a)" -days 365
cat "$T/expint-server.crt" "$T/vendor-int-expired.crt" > SYNTHETIC-expint-server.pem; cp "$T/expint-server.key" SYNTHETIC-expint-server.key
sign wild-server vendor-ca "/CN=*.wild.example.test" "$(leafext serverAuth 'DNS:*.wild.example.test' b)" -days 365
cat "$T/wild-server.crt" > SYNTHETIC-wild-server.pem
# Munki repo server, client certificate (clientAuth) and an unrelated key.
sign munki-repo vendor-ca "/CN=munki.example.test" "$(leafext serverAuth 'DNS:munki.example.test,DNS:localhost,IP:127.0.0.1' c)" -days 365
cat "$T/munki-repo.crt" SYNTHETIC-vendor-ca.pem > SYNTHETIC-munki-repo.pem; cp "$T/munki-repo.key" SYNTHETIC-munki-repo.key
sign munki-client vendor-ca "/CN=client01.example.test" "$(leafext clientAuth 'DNS:client01.example.test' d)" -days 365
cp "$T/munki-client.crt" SYNTHETIC-munki-client.pem; cp "$T/munki-client.key" SYNTHETIC-munki-client.key
O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out SYNTHETIC-munki-other.key
# Custom (CA-issued) FileMaker Server certificate.
sign fms-custom vendor-ca "/CN=fms.example.test" "$(leafext serverAuth 'DNS:fms.example.test,DNS:localhost,IP:127.0.0.1' e)" -days 365
cat "$T/fms-custom.crt" SYNTHETIC-vendor-ca.pem > SYNTHETIC-fms-custom.pem; cp "$T/fms-custom.key" SYNTHETIC-fms-custom.key
selfsigned() { # name subject bits [san]
  O req -x509 -newkey "rsa:$3" -nodes -keyout "SYNTHETIC-$1.key" -out "SYNTHETIC-$1.pem" -days 3650 -sha256 -subj "$2" \
    -addext "basicConstraints=CA:FALSE" ${4:+-addext "subjectAltName=$4"}
}
# Look-alikes of factory certificates (subjects modelled on the vendor defaults, OU=SYNTHETIC).
selfsigned fms-default "/O=FileMaker/OU=SYNTHETIC/CN=FileMaker" 2048
selfsigned hp-default "/O=HP/OU=SYNTHETIC/CN=NPI0A1B2C" 1024
selfsigned hp-ljname "/OU=SYNTHETIC/CN=HP LaserJet 1A2B3C" 2048
selfsigned hp-hpinc "/O=HP Inc./OU=SYNTHETIC/CN=printer01" 2048
selfsigned hpc-lookalike "/O=Example/OU=SYNTHETIC/CN=hpc01.example.test" 2048
selfsigned barracuda-default "/O=Barracuda Networks/OU=SYNTHETIC/CN=barracuda" 2048 "DNS:localhost,IP:127.0.0.1"
selfsigned retrospect-default "/O=Retrospect/OU=SYNTHETIC/CN=Retrospect" 2048
selfsigned openssl-default "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=localhost" 2048
cat > SYNTHETIC-ManagedInstalls.plist <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>SoftwareRepoURL</key><string>https://munki.example.test/repo</string>
	<key>UseClientCertificate</key><true/>
	<key>ClientCertificatePath</key><string>/Library/Managed Installs/certs/client.pem</string>
	<key>ClientKeyPath</key><string>/Library/Managed Installs/certs/client.key</string>
	<key>SoftwareRepoCACertificate</key><string>/Library/Managed Installs/certs/ca.pem</string>
</dict>
</plist>
PL
rm -f ./*.srl "$T"/*.srl
echo "Vendor (Munki / FileMaker / Retrospect / HP / Barracuda) fixtures written."
