#!/bin/bash
# M5/M6 integration: the web app (python -m app on loopback, TLS 1.2+ with a self-signed certificate and a login,
# as M6 serves it) checks a real OpenSSL TLS server in a throw-away container through its REST API and UI routes,
# and verifies the server key and certificate as a PFX upload.
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
NAME=certcheck-test-m5
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
C
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/O=SYNTHETIC/CN=Test M5 CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/O=SYNTHETIC/CN=www.example.test" \
  -keyout leaf.key -out leaf.csr 2>/dev/null
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ca.cnf -extensions leaf \
  -out leaf.pem 2>/dev/null
chmod 644 ca.pem leaf.pem leaf.key
openssl s_server -quiet -accept 4432 -cert leaf.pem -key leaf.key -cert_chain ca.pem -www >/dev/null 2>&1 &
touch /c/ready
wait
SH

D run -d --platform "$PLATFORM" --label "$LABEL" --name "$NAME" -p 127.0.0.1::4432 "$ALPINE" sh -c "$SRV" >/dev/null
for _ in $(seq 120); do D exec "$NAME" test -f /c/ready 2>/dev/null && break; sleep 1; done
sleep 1
for f in ca.pem leaf.pem leaf.key; do D cp "$NAME:/c/$f" "$WORK/$f"; done

export CERTCHECK_IT_M5_PORT CERTCHECK_IT_M5_DIR="$WORK"
CERTCHECK_IT_M5_PORT=$(D port "$NAME" 4432/tcp | head -1 | sed 's/.*://')
cd "$REPO/web"
uv sync -q
if [ "$(uname)" = Darwin ]; then chflags nohidden .venv/lib/python*/site-packages/*.pth 2>/dev/null || true; fi
CI=1 uv run -q --no-sync pytest -q -p no:cacheprovider -rs tests/integration/test_m5_live.py
