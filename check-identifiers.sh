#!/bin/bash
# Fails if organisation-specific identifiers appear in the project tree (text AND binary files) or in built binaries.
# Organisation patterns are read from a local file OUTSIDE the tree, so the repo never contains them:
#   ~/Library/Application Support/CertificateChecker/identifier-patterns.txt  (override: CC_IDENTIFIER_PATTERNS=PATH)
# One extended regex per line, matched case-insensitively as whole words. Lines starting with '#' are comments.
# The file must exist and contain at least one pattern; set CC_IDENTIFIER_PATTERNS=none to check home paths only.
# Built-in generic check: personal home paths (/Users/<name>, /home/<name>).
# Usage: check-identifiers.sh [TREE] [BINARY...]   (default TREE: this folder; binaries default to TREE/dist app + CLI if present)
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")" && pwd)}"; shift $(( $# > 0 ? 1 : 0 ))
PATTERNS="${CC_IDENTIFIER_PATTERNS:-$HOME/Library/Application Support/CertificateChecker/identifier-patterns.txt}"
EXCL=(--exclude-dir=.build --exclude-dir=dist --exclude-dir=DerivedData --exclude-dir=xcuserdata --exclude-dir='*.app' --exclude-dir=.git --exclude-dir=.venv --exclude-dir=venv --exclude=.DS_Store)
args=()
if [ "$PATTERNS" != none ]; then
  [ -f "$PATTERNS" ] || { echo "Identifier check FAILED: patterns file missing: $PATTERNS (set CC_IDENTIFIER_PATTERNS=none to skip organisation patterns)"; exit 1; }
  while IFS= read -r l || [ -n "$l" ]; do
    case "$l" in '#'*) continue;; esac
    [ -n "${l//[[:space:]]/}" ] && args+=(-e "$l")
  done < "$PATTERNS"
  [ ${#args[@]} -gt 0 ] || { echo "Identifier check FAILED: patterns file has no patterns (only comments or blank): $PATTERNS"; exit 1; }
fi
fail=0
# g: grep that records an error (exit 2: unreadable file, bad pattern) instead of treating it as "no match".
GERR="$(mktemp)"; trap 'rm -f "$GERR"' EXIT
g() { grep "$@"; local r=$?; [ $r -le 1 ] || echo "grep exit $r: ${*: -1}" >> "$GERR"; return 0; }
# -a: scan binary files too (fixtures, icons, project files).
hits="$(g -rnaiE "${EXCL[@]}" -e '/Users/[A-Za-z0-9._-]+' -e '/home/[a-z0-9._-]+' "$ROOT" | { grep -v '/Users/Shared' || true; } | cut -c1-300)"
[ -z "$hits" ] || { echo "  personal home paths found:"; printf '%s\n' "$hits" | sed 's/^/    /'; fail=1; }
if [ ${#args[@]} -gt 0 ]; then
  hits="$(g -rnaiwE "${EXCL[@]}" "${args[@]}" "$ROOT" | cut -c1-300)"
  [ -z "$hits" ] || { echo "  organisation identifiers found:"; printf '%s\n' "$hits" | sed 's/^/    /'; fail=1; }
fi
# Built-in: no RFC 1918 (10/8, 172.16/12, 192.168/16) or CGNAT (100.64/10) address unless allowlisted.
# Allowed: 10.0.0.x test values, the classify() boundary values in Tests/Release0100Tests.swift, and RFC 5737 (never private).
ALLOW_EXACT=" 10.1.2.3 172.16.0.1 172.31.255.255 192.168.1.1 100.64.0.1 100.127.255.1 "
ALLOW_PREFIX="10.0.0. 192.0.2. 198.51.100. 203.0.113."
IPV4='([0-9]{1,3}[.]){3}[0-9]{1,3}'
# stdin: "LABEL:ADDRESS" lines; prints the ones that are private/CGNAT and not allowlisted.
private_hits() {
  awk -F: -v ex="$ALLOW_EXACT" -v pre="$ALLOW_PREFIX" 'BEGIN{np=split(pre,P," ")}
    { ip=$NF; n=split(ip,o,"."); if (n!=4) next
      for(i=1;i<=4;i++) if (o[i]+0>255) next
      priv = (o[1]==10) || (o[1]==172 && o[2]>=16 && o[2]<=31) || (o[1]==192 && o[2]==168) || (o[1]==100 && o[2]>=64 && o[2]<=127)
      if (!priv || index(ex," " ip " ")) next
      for(i=1;i<=np;i++) if (index(ip,P[i])==1) next
      print }'
}
# Every 4-octet window of every digits-and-dots run, so an address straight after a version or another number is caught.
quads() { awk -F: '{ run=$NF; pre=substr($0, 1, length($0)-length(run)); n=split(run, o, ".")
    for (i=1; i+3<=n; i++) if (o[i]!="" && o[i+1]!="" && o[i+2]!="" && o[i+3]!="") print pre o[i] "." o[i+1] "." o[i+2] "." o[i+3] }'; }
hits="$(g -rnoaE "${EXCL[@]}" -e '[0-9]+([.][0-9]+){3,}' "$ROOT" | quads | private_hits | sort -u | head -40)"
[ -z "$hits" ] || { echo "  private or CGNAT addresses not on the allowlist:"; printf '%s\n' "$hits" | sed 's/^/    /'; fail=1; }
# Optional site-specific patterns (extended regex per line, case-insensitive, '#' comments) from a local file
# outside the tree, never zipped. Override: CC_IDENTIFIER_LOCAL=PATH, or CC_IDENTIFIER_LOCAL=none to skip.
LOCAL="${CC_IDENTIFIER_LOCAL:-$HOME/Library/Application Support/CertificateChecker/identifiers.local}"
largs=()
if [ "$LOCAL" != none ] && [ -f "$LOCAL" ]; then
  while IFS= read -r l || [ -n "$l" ]; do case "$l" in '#'*) continue;; esac; [ -n "${l//[[:space:]]/}" ] && largs+=(-e "$l"); done < "$LOCAL"
elif [ "$LOCAL" != none ] && [ -n "${CC_IDENTIFIER_LOCAL:-}" ]; then
  echo "  local site-patterns file missing: $LOCAL (set CC_IDENTIFIER_LOCAL=none to skip)"; fail=1
elif [ "$LOCAL" != none ]; then
  echo "  warning: no local site-patterns file at $LOCAL; site patterns not checked (set CC_IDENTIFIER_LOCAL=none to skip on purpose)"
fi
if [ ${#largs[@]} -gt 0 ]; then
  hits="$(g -rnaiE "${EXCL[@]}" "${largs[@]}" "$ROOT" | cut -c1-300)"
  [ -z "$hits" ] || { echo "  local site patterns found:"; printf '%s\n' "$hits" | sed 's/^/    /'; fail=1; }
fi
# Built binaries: strings -a over the app executable and the CLI.
BINS=("$@")
if [ ${#BINS[@]} -eq 0 ]; then for b in "$ROOT/dist/Certificate Checker.app/Contents/MacOS/Certificate Checker" "$ROOT/dist/certificate-checker"; do [ -f "$b" ] && BINS+=("$b"); done; fi
for b in "${BINS[@]+"${BINS[@]}"}"; do
  s="$(strings -a "$b")"
  h="$( { if [ ${#args[@]} -gt 0 ]; then printf '%s\n' "$s" | g -iwE "${args[@]}"; fi; printf '%s\n' "$s" | g -E '/Users/[A-Za-z0-9._-]+|/home/[a-z0-9._-]+' | { grep -v '/Users/Shared' || true; }; printf '%s\n' "$s" | g -oE '[0-9]+([.][0-9]+){3,}' | sed 's/^/addr:/' | quads | private_hits; if [ ${#largs[@]} -gt 0 ]; then printf '%s\n' "$s" | g -iE "${largs[@]}"; fi; } | sort -u | head -20)"
  if [ -n "$h" ]; then echo "  identifiers in binary $(basename "$b"):"; printf '%s\n' "$h" | sed 's/^/    /'; fail=1; else echo "  ok  binary $(basename "$b") (strings -a)"; fi
done
echo "  checked $(( ${#args[@]} / 2 )) org patterns, $(( ${#largs[@]} / 2 )) site patterns ($([ ${#largs[@]} -gt 0 ] && echo "$LOCAL" || echo "no local file")), private ranges + home paths in $ROOT$([ ${#BINS[@]} -gt 0 ] && echo " and ${#BINS[@]} binaries")"
if [ -s "$GERR" ]; then echo "  grep failed (not the same as no match):"; sed 's/^/    /' "$GERR"; fail=1; fi
[ "$fail" = 0 ] && echo "  ok  no identifiers found" || { echo "Identifier check FAILED"; exit 1; }
