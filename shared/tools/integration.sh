#!/bin/bash
# Real-server STARTTLS / SSLRequest integration run in throw-away containers.
#   DOCKER_CONTEXT must be set explicitly (e.g. desktop-linux); this script refuses to guess.
# MySQL data lives on tmpfs (no anonymous volume); containers are removed with -v.
# Everything is labelled certcheck-test and removed on exit (containers, images, networks, volumes).
# Only public images are pulled; nothing is built, tagged or pushed. Ports bind to 127.0.0.1.
set -euo pipefail
: "${DOCKER_CONTEXT:?set DOCKER_CONTEXT explicitly}"
export DOCKER_CONTEXT
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LABEL=certcheck-test
ALPINE=alpine:3.20
MYSQL=mysql:8.4
PLATFORM=linux/arm64
D() { docker --context "$DOCKER_CONTEXT" "$@"; }

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    for c in certcheck-test-mail certcheck-test-mysql; do
      echo "--- $c (last 30 log lines)"; D logs "$c" 2>&1 | tail -30 || true
    done
  fi
  D ps -aq --filter "label=$LABEL" | xargs -r docker --context "$DOCKER_CONTEXT" rm -fv >/dev/null || true
  D network ls -q --filter "label=$LABEL" | xargs -r docker --context "$DOCKER_CONTEXT" network rm >/dev/null || true
  D volume ls -q --filter "label=$LABEL" | xargs -r docker --context "$DOCKER_CONTEXT" volume rm >/dev/null || true
  for img in "${PULLED[@]+"${PULLED[@]}"}"; do D image rm "$img" >/dev/null 2>&1 || true; done
}
PULLED=()
for img in "$ALPINE" "$MYSQL"; do  # only remove images this run pulled
  D image inspect "$img" >/dev/null 2>&1 || PULLED+=("$img")
done
trap cleanup EXIT

read -r -d '' MAIL <<'SH' || true
set -e
apk add -q --no-progress openssl postfix dovecot dovecot-pop3d openldap >/dev/null
mkdir -p /c && cd /c
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/O=SYNTHETIC/CN=mail.example.test" \
  -addext "subjectAltName=DNS:mail.example.test" -addext "extendedKeyUsage=serverAuth" -keyout key.pem -out cert.pem 2>/dev/null
chmod 644 key.pem
cat > /etc/dovecot/dovecot.conf <<C
protocols = imap pop3
listen = *
ssl = yes
ssl_cert = </c/cert.pem
ssl_key = </c/key.pem
log_path = /dev/stderr
passdb {
  driver = static
  args = password=unused
}
userdb {
  driver = static
  args = uid=1000 gid=1000 home=/var/empty
}
C
dovecot
cat > /c/slapd.conf <<C
TLSCertificateFile /c/cert.pem
TLSCertificateKeyFile /c/key.pem
pidfile /c/slapd.pid
C
slapd -h ldap:/// -f /c/slapd.conf
postconf -e smtpd_tls_cert_file=/c/cert.pem smtpd_tls_key_file=/c/key.pem smtpd_tls_security_level=may \
  maillog_file=/dev/stdout myhostname=mail.example.test inet_interfaces=all
newaliases 2>/dev/null || true
touch /c/ready
exec postfix start-fg
SH

D run -d --platform "$PLATFORM" --label "$LABEL" --name certcheck-test-mail \
  -p 127.0.0.1::25 -p 127.0.0.1::143 -p 127.0.0.1::110 -p 127.0.0.1::389 "$ALPINE" sh -c "$MAIL" >/dev/null
D run -d --platform "$PLATFORM" --label "$LABEL" --name certcheck-test-mysql -e MYSQL_RANDOM_ROOT_PASSWORD=1 \
  --mount type=tmpfs,destination=/var/lib/mysql \
  -p 127.0.0.1::3306 "$MYSQL" >/dev/null

port() { D port "$1" "$2" | head -1 | sed 's/.*://'; }
for _ in $(seq 120); do D exec certcheck-test-mail test -f /c/ready 2>/dev/null && break; sleep 1; done
for _ in $(seq 180); do D logs certcheck-test-mysql 2>&1 | grep -q "port: 3306" && break; sleep 1; done
sleep 2

export CERTCHECK_IT_SMTP CERTCHECK_IT_IMAP CERTCHECK_IT_POP3 CERTCHECK_IT_LDAP CERTCHECK_IT_MYSQL
CERTCHECK_IT_SMTP=$(port certcheck-test-mail 25/tcp)
CERTCHECK_IT_IMAP=$(port certcheck-test-mail 143/tcp)
CERTCHECK_IT_POP3=$(port certcheck-test-mail 110/tcp)
CERTCHECK_IT_LDAP=$(port certcheck-test-mail 389/tcp)
CERTCHECK_IT_MYSQL=$(port certcheck-test-mysql 3306/tcp)
cd "$REPO/web"
uv sync -q
# macOS can flag venv .pth files UF_HIDDEN (e.g. under an iCloud-synced ~/Documents); Python then skips them.
if [ "$(uname)" = Darwin ]; then chflags nohidden .venv/lib/python*/site-packages/*.pth 2>/dev/null || true; fi
CI=1 uv run -q --no-sync pytest -q -p no:cacheprovider -rs tests/integration
