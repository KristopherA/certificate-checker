#!/bin/bash
# eapol_test / RADIUS integration run in throw-away containers.
#   DOCKER_CONTEXT must be set explicitly (e.g. desktop-linux); this script refuses to guess.
# FreeRADIUS (alpine, arm64) presents a throw-away leaf + intermediate for radius.example.test (root NOT sent);
# the tests run inside a python:3.12 (Debian, arm64) container with Debian's eapoltest, repo mounted read-only.
# The shared secret is generated per run and passed by environment only; it is never echoed.
# Everything is labelled certcheck-test and removed on exit (containers, images, networks, volumes).
# Only public images are pulled; nothing is built, tagged or pushed. No ports are published.
set -euo pipefail
: "${DOCKER_CONTEXT:?set DOCKER_CONTEXT explicitly}"
export DOCKER_CONTEXT
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LABEL=certcheck-test
ALPINE=alpine:3.20
PY=python:3.12-slim-bookworm
PLATFORM=linux/arm64
NET=certcheck-test-radius
VOL=certcheck-test-radius-certs
D() { docker --context "$DOCKER_CONTEXT" "$@"; }

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then echo "--- radius (last 40 log lines)"; D logs certcheck-test-radius 2>&1 | tail -40 || true; fi
  D ps -aq --filter "label=$LABEL" | xargs -r docker --context "$DOCKER_CONTEXT" rm -fv >/dev/null || true
  D network ls -q --filter "label=$LABEL" | xargs -r docker --context "$DOCKER_CONTEXT" network rm >/dev/null || true
  D volume ls -q --filter "label=$LABEL" | xargs -r docker --context "$DOCKER_CONTEXT" volume rm >/dev/null || true
  for img in "${PULLED[@]+"${PULLED[@]}"}"; do D image rm "$img" >/dev/null 2>&1 || true; done
}
PULLED=()
for img in "$ALPINE" "$PY"; do D image inspect "$img" >/dev/null 2>&1 || PULLED+=("$img"); done
trap cleanup EXIT

SECRET="$(openssl rand -hex 12)"  # not tr|head: SIGPIPE under pipefail
D network create --label "$LABEL" "$NET" >/dev/null
D volume create --label "$LABEL" "$VOL" >/dev/null

read -r -d '' SRV <<'SH' || true
set -e
apk add -q --no-progress openssl freeradius freeradius-eap >/dev/null
cd /c
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3 -subj "/O=SYNTHETIC/CN=SYNTHETIC RADIUS Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout root.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/O=SYNTHETIC/CN=SYNTHETIC RADIUS Intermediate" -keyout int.key -out int.csr 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > int.ext
openssl x509 -req -in int.csr -CA ca.pem -CAkey root.key -CAcreateserial -days 2 -extfile int.ext -out int.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/O=SYNTHETIC/CN=radius.example.test" -keyout srv.key -out srv.csr 2>/dev/null
printf 'subjectAltName=DNS:radius.example.test\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n' > srv.ext
openssl x509 -req -in srv.csr -CA int.pem -CAkey int.key -CAcreateserial -days 1 -extfile srv.ext -out srv.pem 2>/dev/null
cat srv.pem int.pem > chain.pem
chmod 644 /c/*
R=/etc/raddb
cat > $R/clients.conf <<C
client probe {
  ipaddr = 0.0.0.0/0
  secret = $RADIUS_SECRET
}
C
sed -i -e "s#^\([[:space:]]*private_key_file =\).*#\1 /c/srv.key#" \
       -e "s#^\([[:space:]]*certificate_file =\).*#\1 /c/chain.pem#" \
       -e "s#^\([[:space:]]*ca_file =\).*#\1 /c/ca.pem#" $R/mods-available/eap
sed -i -e 's/^\([[:space:]]*\)\(dh_file =.*\)/\1#\2/' -e 's/^\([[:space:]]*\)\(random_file =.*\)/\1#\2/' $R/mods-available/eap
[ -e $R/mods-enabled/eap ] || ln -s ../mods-available/eap $R/mods-enabled/eap
touch /c/ready
exec radiusd -f -l stdout
SH

D run -d --platform "$PLATFORM" --label "$LABEL" --name certcheck-test-radius --network "$NET" --network-alias radius \
  -e RADIUS_SECRET="$SECRET" --mount "type=volume,source=$VOL,destination=/c" "$ALPINE" sh -c "$SRV" >/dev/null
for _ in $(seq 120); do D logs certcheck-test-radius 2>&1 | grep -q "Ready to process requests" && break; sleep 1; done
D logs certcheck-test-radius 2>&1 | grep -q "Ready to process requests"

read -r -d '' CLI <<'SH' || true
set -e
apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends eapoltest >/dev/null
pip install -q --disable-pip-version-check --root-user-action=ignore "cryptography>=43" "pyyaml>=6" "pytest>=8" >/dev/null
cd /src/web
PYTHONPATH=/src/web python -m pytest -q -p no:cacheprovider -rA tests/integration/test_radius_live.py
SH
D run --rm --platform "$PLATFORM" --label "$LABEL" --name certcheck-test-eapol --network "$NET" \
  -e PYTHONDONTWRITEBYTECODE=1 -e CERTCHECK_SHARED=/src/shared \
  -e CERTCHECK_IT_RADIUS_HOST=radius -e CERTCHECK_IT_RADIUS_SECRET="$SECRET" -e CERTCHECK_IT_RADIUS_CA=/c/ca.pem \
  --mount "type=volume,source=$VOL,destination=/c,readonly" \
  --mount "type=bind,source=$REPO/web,destination=/src/web,readonly" \
  --mount "type=bind,source=$REPO/shared,destination=/src/shared,readonly" \
  "$PY" sh -c "$CLI"
