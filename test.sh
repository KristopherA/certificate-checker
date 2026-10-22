#!/bin/bash
# Runs the XCTest suite (unit + loopback probe tests). Fixtures are test-only keys.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
# DerivedData lives outside the synced Documents folder: file-provider metadata breaks codesign there.
DERIVED="${DERIVED:-$HOME/Library/Caches/CertificateChecker/DerivedData}"
[ -f "$ROOT/Tests/Fixtures/leaf.pem" ] || "$ROOT/Tests/make-fixtures.sh"
[ -f "$ROOT/Tests/Fixtures/wg-client.conf" ] || "$ROOT/Tests/make-wg-fixtures.sh"
[ -f "$ROOT/Tests/Fixtures/ipsec-rollleaf.crt" ] || "$ROOT/Tests/make-ipsec-fixtures.sh"
[ -f "$ROOT/Tests/Fixtures/SYNTHETIC-pfsense-2.7-config.xml" ] || "$ROOT/Tests/make-synthetic-fixtures.sh"
[ -f "$ROOT/Tests/Fixtures/rdp-selfexpired.pem" ] || "$ROOT/Tests/make-remote-fixtures.sh"
[ -f "$ROOT/Tests/Fixtures/SYNTHETIC-pbs-selfsigned.pem" ] || "$ROOT/Tests/make-appliance-fixtures.sh"
[ -f "$ROOT/Tests/Fixtures/SYNTHETIC-beats-client.pem" ] || "$ROOT/Tests/make-stack-fixtures.sh"
(cd "$ROOT" && xcodegen generate --quiet)
FIXTURES="$(dirname "$DERIVED")/fixtures"
rm -rf "$FIXTURES"; mkdir -p "$FIXTURES"; cp "$ROOT"/Tests/Fixtures/* "$ROOT/Tests/tls_server.py" "$FIXTURES/"
# Tests never read the user's config: built-in generic defaults only, for every step below.
export CERTCHECK_CONFIG=none
# Full log, scanned at the end for organisation-specific strings and any local-config output.
LOG="$(dirname "$DERIVED")/test-last.log"; : > "$LOG"
exec > >(tee "$LOG") 2>&1
echo "Identifier check (no organisation-specific values in the project tree)…"
"$ROOT/check-identifiers.sh"
TMPP="$(mktemp -d)"; printf '# only a comment\n\n' > "$TMPP/comments.txt"
if CC_IDENTIFIER_PATTERNS="$TMPP/missing.txt" "$ROOT/check-identifiers.sh" >/dev/null 2>&1; then echo "  missing patterns file did not fail"; exit 1; fi
if CC_IDENTIFIER_PATTERNS="$TMPP/comments.txt" "$ROOT/check-identifiers.sh" >/dev/null 2>&1; then echo "  comments-only patterns file did not fail"; exit 1; fi
mkdir -p "$TMPP/tree"; printf 'zz\0 /Us''ers/someone/x\n' > "$TMPP/tree/blob.bin"; printf 'zzorgword\n' > "$TMPP/p.txt"; printf 'a zzorgword b\0' > "$TMPP/tree/b2.bin"
if CC_IDENTIFIER_PATTERNS="$TMPP/p.txt" "$ROOT/check-identifiers.sh" "$TMPP/tree" >/dev/null 2>&1; then echo "  binary file hits not detected"; exit 1; fi
rm -rf "$TMPP"; echo "  ok  missing/comment-only patterns fail; binary files are scanned"
TEST_RUNNER_CC_FIXTURES="$FIXTURES" TEST_RUNNER_CERTCHECK_CONFIG=none xcodebuild -project "$ROOT/CertificateChecker.xcodeproj" -scheme CertificateChecker -derivedDataPath "$DERIVED" \
  -destination 'platform=macOS,arch=arm64' CODE_SIGN_IDENTITY=- test "$@"

echo "CLI private-key leak check (WireGuard)…"
CLI="$DERIVED/Build/Products/Debug/certificate-checker"
for f in wg-server.conf wg-client.conf wg-bad.conf pfsense-config.xml SYNTHETIC-pfsense-wireguard-export.xml; do
  out="$("$CLI" wireguard "$FIXTURES/$f" 2>&1 || true)"
  key="$(grep -m1 -oE '(PrivateKey = |<privatekey>)[A-Za-z0-9+/=]{44}' "$FIXTURES/$f" | grep -oE '[A-Za-z0-9+/=]{44}$')"
  [ -n "$key" ] || { echo "  no key found in $f"; exit 1; }
  if printf '%s' "$out" | grep -qF "$key"; then echo "  LEAK in $f"; exit 1; else echo "  ok  $f"; fi
done
echo "CLI wireguard exit codes and --expect-public…"
"$CLI" wireguard "$FIXTURES/wg-server.conf" "$FIXTURES/wg-client.conf" >/dev/null 2>&1 && echo "  ok  good pair exits 0" || { echo "  good pair did not exit 0"; exit 1; }
if "$CLI" wireguard "$FIXTURES/wg-bad.conf" >/dev/null 2>&1; then echo "  bad config exited 0"; exit 1; else echo "  ok  bad config exits non-zero"; fi
priv="$(grep -m1 -oE 'PrivateKey = [A-Za-z0-9+/=]{44}' "$FIXTURES/wg-client.conf" | grep -oE '[A-Za-z0-9+/=]{44}$')"
out="$("$CLI" wireguard "$FIXTURES/wg-client.conf" --expect-public "$priv" 2>&1 || true)"
printf '%s' "$out" | grep -q "looks like a private key" || { echo "  --expect-public private key not detected"; exit 1; }
if printf '%s' "$out" | grep -qF "$priv"; then echo "  LEAK via --expect-public"; exit 1; fi
echo "  ok  --expect-public rejects a private key without echoing it"
echo "CLI wireguard blank template…"
set +e; out="$("$CLI" wireguard "$FIXTURES/wg-blank-template.conf" 2>&1)"; rc=$?; set -e
[ "$rc" = 1 ] || { echo "  blank template exit code $rc (want 1; >1 means crash or usage)"; exit 1; }
for fld in PrivateKey Address DNS PublicKey AllowedIPs Endpoint; do printf '%s' "$out" | grep -q "$fld is empty" || { echo "  missing '$fld is empty'"; exit 1; }; done
echo "  ok  blank template exits 1 and names all six empty fields"
echo "CLI ipsec exit codes and key secrecy…"
"$CLI" ipsec "$FIXTURES/ipsec-server.crt" "$FIXTURES/ipsec-ca.crt" "$FIXTURES/ipsec-server.key" --expect-id vpn.example.test >/dev/null 2>&1 && echo "  ok  good server exits 0" || { echo "  good IPsec server did not exit 0"; exit 1; }
if "$CLI" ipsec "$FIXTURES/ipsec-bad.crt" "$FIXTURES/ipsec-ca.crt" >/dev/null 2>&1; then echo "  bad IPsec cert exited 0"; exit 1; else echo "  ok  bad server exits non-zero"; fi
out="$("$CLI" ipsec "$FIXTURES/ipsec-server.crt" "$FIXTURES/ipsec-ca.crt" "$FIXTURES/ipsec-server.key" "$FIXTURES/ipsec-other.key" 2>&1 || true)"
for k in ipsec-server.key ipsec-other.key; do
  line="$(sed -n 2p "$FIXTURES/$k")"
  if printf '%s' "$out" | grep -qF "$line"; then echo "  LEAK of $k"; exit 1; fi
done
echo "  ok  private keys never printed"
echo "CLI radius (offline) and radius-probe without eapol_test…"
"$CLI" radius "$FIXTURES/ipsec-server.crt" "$FIXTURES/ipsec-ca.crt" --expect vpn.example.test >/dev/null 2>&1 && echo "  ok  good RADIUS cert exits 0" || { echo "  good RADIUS cert did not exit 0"; exit 1; }
if "$CLI" radius "$FIXTURES/ipsec-bad.crt" "$FIXTURES/ipsec-ca.crt" >/dev/null 2>&1; then echo "  bad RADIUS cert exited 0"; exit 1; else echo "  ok  bad RADIUS cert exits non-zero"; fi
if [ -z "$(command -v eapol_test)" ] && ! ls /opt/homebrew/bin/eapol_test /opt/homebrew/sbin/eapol_test /usr/local/bin/eapol_test /usr/local/sbin/eapol_test >/dev/null 2>&1; then
  set +e; out="$(printf 'SYNTH-secret-123\n' | "$CLI" radius-probe 192.0.2.1 --secret-stdin 2>&1)"; rc=$?; set -e
  [ "$rc" = 3 ] && printf '%s' "$out" | grep -q "eapol_test is not installed" && ! printf '%s' "$out" | grep -q "SYNTH-secret" && echo "  ok  radius-probe skips (exit 3) with install guidance, no network" || { echo "  radius-probe skip check failed (rc=$rc)"; exit 1; }
else echo "  skip radius-probe skip check: eapol_test is installed (test.sh never sends live RADIUS traffic)"; fi
echo "CLI config: defaults are generic (user config never read)…"
out="$("$CLI" config)"; printf '%s' "$out" | grep -q "KB links: none" && printf '%s' "$out" | grep -q "default domain: example.com" && echo "  ok  built-in defaults are generic" || { echo "  defaults not generic"; exit 1; }
# The user's own config is never read here (CERTCHECK_CONFIG=none for every step). Check it by hand with:
#   certificate-checker --config PATH config --check
out="$("$CLI" --config none config --check)" && printf '%s' "$out" | grep -q "^Config: built-in defaults" && echo "  ok  --config none: built-in defaults, config --check passes" || { echo "  --config none did not use built-in defaults"; exit 1; }
echo "CLI rdp / rdg / winrm usage (no network)…"
for bad in "rdp" "rdg" "winrm" "winrm h.example.test --http-port 5985" "rdp a b"; do
  set +e; "$CLI" $bad >/dev/null 2>&1; rc=$?; set -e
  [ "$rc" = 2 ] || { echo "  '$bad' exit $rc (want 2)"; exit 1; }
done
echo "  ok  usage errors exit 2 (including --http-port without --check-http)"
echo "CLI dsm / pve / pbs usage and fingerprint validation (no network)…"
for bad in "dsm" "pve" "pbs" "pve a b" "dsm h.example.test --fingerprint 00" "dsm h.example.test --fingerprint AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB" "pve h.example.test --fingerprint AA:BB" "pbs h.example.test --fingerprint not-a-fingerprint" "pbs h.example.test --fingerprint AA:BB"; do
  set +e; "$CLI" $bad >/dev/null 2>&1; rc=$?; set -e
  [ "$rc" = 2 ] || { echo "  '$bad' exit $rc (want 2)"; exit 1; }
done
echo "  ok  usage errors exit 2 (including --fingerprint on dsm and malformed pbs/pve pins)"
echo "CLI registry / beats / es usage and mtls-pair (no network)…"
for bad in "registry" "beats" "es" "registry a b" "beats h.example.test --check-v2" "es h.example.test --check-v2" "mtls-pair" "mtls-pair $FIXTURES/SYNTHETIC-beats-client.pem"; do
  set +e; "$CLI" $bad >/dev/null 2>&1; rc=$?; set -e
  [ "$rc" = 2 ] || { echo "  '$bad' exit $rc (want 2)"; exit 1; }
done
"$CLI" mtls-pair "$FIXTURES/SYNTHETIC-beats-client.pem" "$FIXTURES/SYNTHETIC-beats-client.key" --ca "$FIXTURES/SYNTHETIC-stack-ca.pem" >/dev/null 2>&1 && echo "  ok  good client pair exits 0" || { echo "  good client pair did not exit 0"; exit 1; }
if "$CLI" mtls-pair "$FIXTURES/SYNTHETIC-beats-serveronly.pem" "$FIXTURES/SYNTHETIC-beats-client.key" --ca "$FIXTURES/SYNTHETIC-stack-ca.pem" >/dev/null 2>&1; then echo "  bad client pair exited 0"; exit 1; fi
out="$("$CLI" mtls-pair "$FIXTURES/SYNTHETIC-beats-client.pem" "$FIXTURES/SYNTHETIC-beats-client.key" --ca "$FIXTURES/SYNTHETIC-stack-ca.pem" 2>&1 || true)"
if printf '%s' "$out" | grep -qF "$(sed -n 2p "$FIXTURES/SYNTHETIC-beats-client.key")"; then echo "  LEAK of client key"; exit 1; fi
echo "  ok  usage errors exit 2; bad pair exits non-zero; client key never printed"
echo "Log scan: no organisation-specific strings, no local-config output…"
# Word-bounded so "unable"/"unauthenticated" do not match. The organisation word is assembled at run time so this
# script itself never contains it (check-identifiers scans the tree); the local patterns file, if present, is applied too.
O="$(printf 'u%s' na)"
# Scan a snapshot: grepping the live log while tee appends to it can feed matches back into it.
# The build machine's own checkout and home paths (xcodebuild echoes them, sometimes backslash-escaped) are replaced
# first: they describe where this copy is built, not what it contains.
SNAP="$LOG.snap"
trap 'rm -f "$SNAP"' EXIT   # also removed when a check below exits early
awk -v r="$ROOT" -v h="$HOME" 'function rep(s, a, b,   i, o) { o = ""; while ((i = index(s, a)) > 0) { o = o substr(s, 1, i - 1) b; s = substr(s, i + length(a)) } return o s }
  { gsub(/\\ /, " "); $0 = rep($0, r, "<checkout>"); $0 = rep($0, h, "<home>"); print }' "$LOG" > "$SNAP"
if grep -inE "${O}\\.ca|${O}-|(^|[^a-z])${O}([^a-z]|\$)" "$SNAP" | grep -v 'Log scan' ; then rm -f "$SNAP"; echo "  organisation-specific string in the test log"; exit 1; fi
# Same patterns and matching as check-identifiers.sh (-iwE); only line numbers are printed, never the matched text.
PF="${CC_IDENTIFIER_PATTERNS:-$HOME/Library/Application Support/CertificateChecker/identifier-patterns.txt}"
pargs=()
if [ "$PF" != none ] && [ -f "$PF" ]; then
  while IFS= read -r l || [ -n "$l" ]; do case "$l" in '#'*) continue;; esac; [ -n "${l//[[:space:]]/}" ] && pargs+=(-e "$l"); done < "$PF"
fi
if [ ${#pargs[@]} -gt 0 ]; then
  n="$(grep -ciwE "${pargs[@]}" "$SNAP" || true)"
  if [ "${n:-0}" -gt 0 ]; then echo "  local identifier pattern matched $n log line(s): $(grep -niwE "${pargs[@]}" "$SNAP" | cut -d: -f1 | head -20 | tr '\n' ' ')"; rm -f "$SNAP"; exit 1; fi
  echo "  log also scanned with $(( ${#pargs[@]} / 2 )) local identifier patterns"
fi
if grep -nE '^Config: ' "$SNAP" | grep -v 'Config: built-in defaults'; then echo "  a non-default config was loaded"; exit 1; fi
if grep -nE 'Application Support/CertificateChecker/config\.json|^  (ok     |MISSING |url     )|organization: [^(]' "$SNAP"; then echo "  local-config output in the test log"; exit 1; fi
echo "  ok  $(wc -l < "$SNAP" | tr -d ' ') log lines scanned ($LOG)"; rm -f "$SNAP"
