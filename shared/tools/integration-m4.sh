#!/bin/bash
# M4 integration: a real OpenSSL server that only speaks TLS 1.0 (legacy mode) and one that staples OCSP.
#   DOCKER_CONTEXT must be set explicitly (e.g. desktop-linux); this script refuses to guess.
# Everything is labelled certcheck-test and removed on exit (containers, images, networks, volumes).
# Only public images are pulled; nothing is built, tagged or pushed. Ports bind to 127.0.0.1.
set -euo pipefail
: "${DOCKER_CONTEXT:?set DOCKER_CONTEXT explicitly}"
export DOCKER_CONTEXT
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LABEL=certcheck-test
ALPINE=alpine:3.20
PLATFORM=linux/arm64
NAME=certcheck-test-m4
D() { docker --context "$DOCKER_CONTEXT" "$@"; }
WORK="$(mktemp -d)"

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then echo "--- $NAME (last 30 log lines)"; D logs "$NAME" 2>&1 | tail -30 || true; fi
  D ps -aq --filter "label=$LABEL" | xargs -r docker --context "$DOCKER_CONTEXT" rm -fv >/dev/null || true
  D network ls -q --filter "label=$LABEL" | xargs -r docker --context "$DOCKER_CONTEXT" network rm >/dev/null || true
  D volume ls -q --filter "label=$LABEL" | xargs -r docker --context "$DOCKER_CONTEXT" volume rm >/dev/null || true
  for img in "${PULLED[@]+"${PULLED[@]}"}"; do D image rm "$img" >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
PULLED=()
D image inspect "$ALPINE" >/dev/null 2>&1 || PULLED+=("$ALPINE")
trap cleanup EXIT

read -r -d '' SRV <<'SH' || true
set -e
apk add -q --no-progress openssl >/dev/null
mkdir -p /c && cd /c
cat > ca.cnf <<C
[leaf]
basicConstraints=critical,CA:FALSE
subjectAltName=DNS:www.example.test
extendedKeyUsage=serverAuth
authorityInfoAccess=OCSP;URI:http://127.0.0.1:9/
C
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/O=SYNTHETIC/CN=Test M4 CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/O=SYNTHETIC/CN=www.example.test" \
  -keyout leaf.key -out leaf.csr 2>/dev/null
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ca.cnf -extensions leaf \
  -out leaf.pem 2>/dev/null
serial=$(openssl x509 -in leaf.pem -noout -serial | cut -d= -f2)
exp=$(date -u -d @$(( $(date +%s) + 86400 )) +%y%m%d%H%M%SZ)
printf 'V\t%s\t\t%s\tunknown\t/O=SYNTHETIC/CN=www.example.test\n' "$exp" "$serial" > index.txt
openssl ocsp -index index.txt -rsigner ca.pem -rkey ca.key -CA ca.pem -issuer ca.pem -cert leaf.pem \
  -ndays 1 -respout ocsp.der >/dev/null 2>&1
chmod 644 ca.pem
openssl s_server -quiet -accept 4430 -tls1 -cipher 'DEFAULT:@SECLEVEL=0' -cert leaf.pem -key leaf.key \
  -cert_chain ca.pem -www >/dev/null 2>&1 &
openssl s_server -quiet -accept 4431 -status_file ocsp.der -cert leaf.pem -key leaf.key -cert_chain ca.pem \
  -www >/dev/null 2>&1 &
touch /c/ready
wait
SH

D run -d --platform "$PLATFORM" --label "$LABEL" --name "$NAME" -p 127.0.0.1::4430 -p 127.0.0.1::4431 \
  "$ALPINE" sh -c "$SRV" >/dev/null
port() { D port "$NAME" "$1" | head -1 | sed 's/.*://'; }
for _ in $(seq 120); do D exec "$NAME" test -f /c/ready 2>/dev/null && break; sleep 1; done
sleep 1
D cp "$NAME:/c/ca.pem" "$WORK/ca.pem"

export CERTCHECK_IT_M4_LEGACY CERTCHECK_IT_M4_STAPLE CERTCHECK_IT_M4_CA="$WORK/ca.pem"
CERTCHECK_IT_M4_LEGACY=$(port 4430/tcp)
CERTCHECK_IT_M4_STAPLE=$(port 4431/tcp)
cd "$REPO/web"
uv sync -q
if [ "$(uname)" = Darwin ]; then chflags nohidden .venv/lib/python*/site-packages/*.pth 2>/dev/null || true; fi
CI=1 uv run -q --no-sync pytest -q -p no:cacheprovider -rs tests/integration/test_m4_live.py
