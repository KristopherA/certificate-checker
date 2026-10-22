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
EXCL=(--exclude-dir=.build --exclude-dir=dist --exclude-dir=DerivedData --exclude-dir=xcuserdata --exclude-dir='*.app' --exclude-dir=.git --exclude=.DS_Store)
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
# -a: scan binary files too (fixtures, icons, project files).
hits="$(grep -rnaiE "${EXCL[@]}" -e '/Users/[A-Za-z0-9._-]+' -e '/home/[a-z0-9._-]+' "$ROOT" | grep -v '/Users/Shared' | cut -c1-300 || true)"
[ -z "$hits" ] || { echo "  personal home paths found:"; printf '%s\n' "$hits" | sed 's/^/    /'; fail=1; }
if [ ${#args[@]} -gt 0 ]; then
  hits="$(grep -rnaiwE "${EXCL[@]}" "${args[@]}" "$ROOT" | cut -c1-300 || true)"
  [ -z "$hits" ] || { echo "  organisation identifiers found:"; printf '%s\n' "$hits" | sed 's/^/    /'; fail=1; }
fi
# Built binaries: strings -a over the app executable and the CLI.
BINS=("$@")
if [ ${#BINS[@]} -eq 0 ]; then for b in "$ROOT/dist/Certificate Checker.app/Contents/MacOS/Certificate Checker" "$ROOT/dist/certificate-checker"; do [ -f "$b" ] && BINS+=("$b"); done; fi
for b in "${BINS[@]+"${BINS[@]}"}"; do
  s="$(strings -a "$b")"
  h="$( { [ ${#args[@]} -gt 0 ] && printf '%s\n' "$s" | grep -iwE "${args[@]}"; printf '%s\n' "$s" | grep -E '/Users/[A-Za-z0-9._-]+|/home/[a-z0-9._-]+' | grep -v '/Users/Shared'; } | sort -u | head -20 || true)"
  if [ -n "$h" ]; then echo "  identifiers in binary $(basename "$b"):"; printf '%s\n' "$h" | sed 's/^/    /'; fail=1; else echo "  ok  binary $(basename "$b") (strings -a)"; fi
done
echo "  checked $(( ${#args[@]} / 2 )) local patterns + home paths in $ROOT$([ ${#BINS[@]} -gt 0 ] && echo " and ${#BINS[@]} binaries")"
[ "$fail" = 0 ] && echo "  ok  no identifiers found" || { echo "Identifier check FAILED"; exit 1; }
