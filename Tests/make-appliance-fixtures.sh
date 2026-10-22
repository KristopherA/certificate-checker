#!/bin/bash
# TEST-ONLY Synology DSM / Proxmox VE / Proxmox Backup Server look-alike certificates. SYNTHETIC: keys protect nothing.
set -euo pipefail
cd "$(dirname "$0")/Fixtures"
OPENSSL="$(brew --prefix openssl@3 2>/dev/null)/bin/openssl"; [ -x "$OPENSSL" ] || OPENSSL=openssl
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
O() { "$OPENSSL" "$@" 2>/dev/null; }
ca() { # file subject
  O req -x509 -newkey rsa:2048 -nodes -keyout "$T/$1.key" -out "$T/$1.crt" -days 3650 -sha256 -subj "$2" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
}
leaf() { # name ca subject san
  O req -new -newkey rsa:2048 -nodes -keyout "SYNTHETIC-$1.key" -out "$T/$1.csr" -subj "$3"
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$4" > "$T/$1.ext"
  O x509 -req -in "$T/$1.csr" -CA "$T/$2.crt" -CAkey "$T/$2.key" -CAcreateserial -out "$T/$1.crt" -days 365 -sha256 -extfile "$T/$1.ext"
  cat "$T/$1.crt" "$T/$2.crt" > "SYNTHETIC-$1.pem"
}
# Like the DSM factory certificate: CN=synology under a NAS-generated "Synology Inc. CA".
ca dsmca "/C=TW/L=Taipei/O=Synology Inc./CN=Synology Inc. CA"
leaf dsm-default dsmca "/C=TW/L=Taipei/O=Synology Inc./CN=synology" "DNS:synology,IP:127.0.0.1"
# Like a PVE node certificate issued by the cluster CA.
ca pveca "/CN=Proxmox Virtual Environment/OU=SYNTHETIC/O=PVE Cluster Manager CA"
leaf pve-default pveca "/OU=PVE Cluster Node/O=Proxmox Virtual Environment/CN=pve1.example.test" "DNS:pve1.example.test,DNS:localhost,IP:127.0.0.1"
# Like the PBS install-time self-signed certificate.
O req -x509 -newkey rsa:2048 -nodes -keyout SYNTHETIC-pbs-selfsigned.key -out SYNTHETIC-pbs-selfsigned.pem -days 365 -sha256 \
  -subj "/C=CA/ST=SYNTHETIC/O=Proxmox Backup Server/OU=SYNTHETIC/CN=pbs.example.test" \
  -addext "basicConstraints=CA:FALSE" -addext "extendedKeyUsage=serverAuth" -addext "subjectAltName=DNS:pbs.example.test,DNS:localhost,IP:127.0.0.1"
rm -f ./*.srl
echo "Appliance fixtures written."
