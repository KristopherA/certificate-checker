#!/bin/bash
# M7 integration: builds the web image locally (web/docker/Dockerfile, native platform only), runs it with the
# deployment hardening (non-root, read-only rootfs, tmpfs /tmp, all capabilities dropped, no-new-privileges, pids and
# memory limits, password hash as a mounted file, /config read-only, /data a named volume) and checks it from the
# host: health, login over TLS, AEAD-only TLS 1.2, a live probe trusted through a /config/ca anchor against a real
# OpenSSL server on a private network, and the container's own security state.
#   DOCKER_CONTEXT must be set explicitly (e.g. desktop-linux); this script refuses to guess.
# Everything is labelled certcheck-test and removed on exit (containers, the built image, networks, volumes and the
# pulled helper image). Nothing is tagged for a registry or pushed. Ports bind to 127.0.0.1.
set -euo pipefail
: "${DOCKER_CONTEXT:?set DOCKER_CONTEXT explicitly}"
export DOCKER_CONTEXT
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LABEL=certcheck-test
ALPINE=alpine:3.20
IMAGE=certcheck-test-web:m7
NAME=certcheck-test-m7
SRV_NAME=certcheck-test-m7-srv
NET=certcheck-test-m7-net
VOL=certcheck-test-m7-data
D() { docker --context "$DOCKER_CONTEXT" "$@"; }
WORK="$(mktemp -d)"

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then echo "--- $NAME (last 40 log lines)"; D logs "$NAME" 2>&1 | tail -40 || true; fi
  D ps -aq --filter "label=$LABEL" | xargs -r docker --context "$DOCKER_CONTEXT" rm -fv >/dev/null || true
  D network ls -q --filter "label=$LABEL" | xargs -r docker --context "$DOCKER_CONTEXT" network rm >/dev/null || true
  D volume ls -q --filter "label=$LABEL" | xargs -r docker --context "$DOCKER_CONTEXT" volume rm >/dev/null || true
  D image rm "$IMAGE" >/dev/null 2>&1 || true
  for img in "${PULLED[@]+"${PULLED[@]}"}"; do D image rm "$img" >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
PULLED=()
D image inspect "$ALPINE" >/dev/null 2>&1 || PULLED+=("$ALPINE")
trap cleanup EXIT

echo "Building $IMAGE (local only)…"
D build -q --label "$LABEL" -t "$IMAGE" -f "$REPO/web/docker/Dockerfile" "$REPO" >/dev/null

D network create --label "$LABEL" "$NET" >/dev/null
D volume create --label "$LABEL" "$VOL" >/dev/null

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
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/O=SYNTHETIC/CN=Test M7 CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/O=SYNTHETIC/CN=www.example.test" \
  -keyout leaf.key -out leaf.csr 2>/dev/null
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ca.cnf -extensions leaf \
  -out leaf.pem 2>/dev/null
chmod 644 ca.pem
openssl s_server -quiet -accept 4432 -cert leaf.pem -key leaf.key -cert_chain ca.pem -www >/dev/null 2>&1 &
touch /c/ready
wait
SH
D run -d --label "$LABEL" --name "$SRV_NAME" --network "$NET" --network-alias www.example.test "$ALPINE" sh -c "$SRV" >/dev/null
for _ in $(seq 120); do D exec "$SRV_NAME" test -f /c/ready 2>/dev/null && break; sleep 1; done

mkdir -p "$WORK/config/ca" "$WORK/secrets"
D cp "$SRV_NAME:/c/ca.pem" "$WORK/config/ca/test-m7-ca.pem"
chmod 755 "$WORK/config" "$WORK/config/ca"; chmod 644 "$WORK/config/ca/test-m7-ca.pem"
# The login password exists only in this file (deleted on exit) and the test process; the container sees its hash.
PW="$(openssl rand -base64 18)"; printf '%s' "$PW" > "$WORK/password"; chmod 600 "$WORK/password"; unset PW
D run --rm -i --label "$LABEL" --network none --entrypoint python "$IMAGE" \
  -c 'import sys; from app.auth import hash_password; print(hash_password(sys.stdin.read()))' \
  < "$WORK/password" > "$WORK/secrets/password_hash"
# Deliberately group/other-readable, as a compose bind-mounted secret often is: the app must warn, not refuse.
chmod 644 "$WORK/secrets/password_hash"

D run -d --label "$LABEL" --name "$NAME" --network "$NET" \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 256 --memory 512m \
  -v "$WORK/config:/config:ro" -v "$VOL:/data" -v "$WORK/secrets/password_hash:/run/secrets/password_hash:ro" \
  -e CERTCHECK_PASSWORD_HASH_FILE=/run/secrets/password_hash -e CERTCHECK_TLS_NAMES=certcheck.example.test \
  -p 127.0.0.1::8080 "$IMAGE" >/dev/null
for _ in $(seq 90); do
  s="$(D inspect -f '{{.State.Health.Status}}' "$NAME")"; [ "$s" = healthy ] && break
  [ "$s" = unhealthy ] && { echo "container unhealthy"; exit 1; }; sleep 1
done
[ "$(D inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] || { echo "container never became healthy"; exit 1; }

export CERTCHECK_IT_M7_PORT CERTCHECK_IT_M7_DIR="$WORK" CERTCHECK_IT_M7_CONTAINER="$NAME"
CERTCHECK_IT_M7_PORT=$(D port "$NAME" 8080/tcp | head -1 | sed 's/.*://')
cd "$REPO/web"
uv sync -q
if [ "$(uname)" = Darwin ]; then chflags nohidden .venv/lib/python*/site-packages/*.pth 2>/dev/null || true; fi
CI=1 uv run -q --no-sync pytest -q -p no:cacheprovider -rs tests/integration/test_m7_image.py
