#!/bin/bash
# Verifies a built app and CLI in place without rebuilding. Default: this checkout's dist/ (what build.sh just produced).
# Pass a folder to check another copy, e.g. the deployed one; the binary path is printed next to the Identifier.
# iCloud Drive adds FinderInfo/file-provider xattrs there, so --strict is run on an xattr-stripped copy outside Documents,
# and its CDHash must equal the in-place one. Usage: verify-signatures.sh [DIST_DIR]
set -euo pipefail
DIST="${1:-$(cd "$(dirname "$0")" && pwd)/dist}"
[ -d "$DIST" ] || { echo "No such folder: $DIST (run build.sh first, or pass DIST_DIR)"; exit 2; }
echo "Verifying $DIST"
APP="$DIST/Certificate Checker.app"; CLI="$DIST/certificate-checker"
cdhash() { /usr/bin/codesign -dvvv "$1" 2>&1 | /usr/bin/sed -n 's/^CDHash=//p'; }
/usr/bin/codesign --verify --deep "$APP" && echo "ok  app: codesign --verify --deep (in place)"
/usr/bin/codesign --verify --deep "$CLI" && echo "ok  CLI: codesign --verify --deep (in place)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
ditto --norsrc --noextattr "$APP" "$T/Certificate Checker.app"
ditto --norsrc --noextattr "$CLI" "$T/certificate-checker"
/usr/bin/codesign --verify --deep --strict "$T/Certificate Checker.app" && echo "ok  app: --deep --strict on stripped copy"
/usr/bin/codesign --verify --deep --strict "$T/certificate-checker" && echo "ok  CLI: --deep --strict on stripped copy"
for pair in "app|$APP|$T/Certificate Checker.app" "CLI|$CLI|$T/certificate-checker"; do
  IFS='|' read -r name a b <<<"$pair"
  ha="$(cdhash "$a")"; hb="$(cdhash "$b")"
  [ -n "$ha" ] && [ "$ha" = "$hb" ] || { echo "CDHash mismatch for $name: in place $ha, stripped copy $hb"; exit 1; }
  echo "ok  $name CDHash $ha (in place = stripped copy)"
done
echo "Identifier scan (strings -a) of the built binaries…"
"$(cd "$(dirname "$0")" && pwd)/check-identifiers.sh" "$(cd "$(dirname "$0")" && pwd)" "$APP/Contents/MacOS/Certificate Checker" "$CLI"
echo "$(/usr/bin/codesign -dvvv "$CLI" 2>&1 | /usr/bin/grep -E '^Identifier=')  ($CLI)"
