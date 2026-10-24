#!/bin/bash
# Records shared/golden/*.json from the Mac app's checks (FileCheck + SecTrust) for shared/fixtures/ca.
# macOS only (Xcode + xcodegen). Runs one XCTest (GoldenExportTests) that is skipped in normal test.sh runs.
# Dates in titles come from Analysis.fmt, so the run is pinned to TZ=UTC and en_US (the test checks this).
# Logs go to a mktemp file that is deleted before exit. Usage: shared/tools/record-golden.sh
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
# The app folder is <repo> (public layout) or <repo>/Source (working copy); see swift_root.py.
SRC="$(python3 "$REPO/shared/tools/swift_root.py" "$REPO")"; FX="$REPO/shared/fixtures/ca"; OUT="$REPO/shared/golden"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
DERIVED="${DERIVED:-$HOME/Library/Caches/CertificateChecker/DerivedData}"
STAGE="$(mktemp -d)"; LOG="$(mktemp)"; trap 'rm -rf "$STAGE" "$LOG"' EXIT
(cd "$SRC" && xcodegen generate --quiet)
if ! TEST_RUNNER_CC_GOLDEN_OUT="$STAGE" TEST_RUNNER_CC_GOLDEN_FIXTURES="$FX" TEST_RUNNER_CC_GOLDEN_ADJUST_FIXTURES="$REPO/shared/fixtures/adjust" \
  TEST_RUNNER_CERTCHECK_CONFIG=none \
  TEST_RUNNER_TZ=UTC TEST_RUNNER_LANG=en_US.UTF-8 TEST_RUNNER_LC_ALL=en_US.UTF-8 \
  xcodebuild -project "$SRC/CertificateChecker.xcodeproj" -scheme CertificateChecker -derivedDataPath "$DERIVED" \
  -destination 'platform=macOS,arch=arm64' CODE_SIGN_IDENTITY=- \
  -testLanguage en -testRegion US \
  -only-testing:CertificateCheckerTests/GoldenExportTests test >"$LOG" 2>&1; then
  grep -E 'error:|failed' "$LOG" | head -20; echo "golden recording FAILED"; exit 1
fi
n="$(find "$STAGE" -maxdepth 1 -name '*.json' | wc -l | tr -d ' ')"
[ "$n" -gt 0 ] || { echo "no golden files written (was the test skipped?)"; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT"
# Normalise: 2-space indent, sorted keys, trailing newline (stable diffs across Foundation versions).
for f in "$STAGE"/*.json; do
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); open(sys.argv[2],"w").write(json.dumps(d,indent=2,sort_keys=True,ensure_ascii=False)+"\n")' "$f" "$OUT/$(basename "$f")"
done
# Service adjustments (shared/fixtures/adjust) land in golden/adjust/.
n2="$(find "$STAGE/adjust" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
[ "$n2" -gt 0 ] || { echo "no adjust golden files written"; exit 1; }
mkdir -p "$OUT/adjust"
for f in "$STAGE"/adjust/*.json; do
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); open(sys.argv[2],"w").write(json.dumps(d,indent=2,sort_keys=True,ensure_ascii=False)+"\n")' "$f" "$OUT/adjust/$(basename "$f")"
done
echo "recorded $n golden verdicts and $n2 adjustments in $OUT"
