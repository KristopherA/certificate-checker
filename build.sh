#!/bin/bash
# Builds Certificate Checker (universal, macOS 14+) with xcodebuild and signs it ad hoc.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/.build"
DIST="${1:-$ROOT/dist}"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
# DerivedData lives outside the synced Documents folder: file-provider metadata breaks codesign there.
DERIVED="${DERIVED:-$HOME/Library/Caches/CertificateChecker/DerivedData}"
mkdir -p "$BUILD/cache" "$DIST"
echo "Drawing icon…"
xcrun swiftc -module-cache-path "$BUILD/cache" "$ROOT/Tools/Icon.swift" -o "$BUILD/icon"
"$BUILD/icon" "$BUILD/CertificateChecker.iconset" "$ROOT/Resources/Assets.xcassets/AppIcon.appiconset" "$BUILD/icon-1024.png"
command -v xcodegen >/dev/null || { echo "xcodegen is required to regenerate the project (brew install xcodegen)"; exit 2; }
(cd "$ROOT" && xcodegen generate --quiet)
echo "Building (arm64 + x86_64)…"
xcodebuild -project "$ROOT/CertificateChecker.xcodeproj" -scheme CertificateChecker -configuration Release \
  -derivedDataPath "$DERIVED" ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO CODE_SIGN_IDENTITY=- build -quiet
PRODUCTS="$DERIVED/Build/Products/Release"
# Sign in a staging folder outside the synced Documents folder, where file-provider metadata cannot interfere.
# mktemp -d, never a path derived from the overridable DERIVED, so nothing outside a fresh private folder is removed.
STAGE="$(mktemp -d "${TMPDIR:-/private/var/tmp}/cc-stage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
ditto --norsrc --noextattr "$PRODUCTS/Certificate Checker.app" "$STAGE/Certificate Checker.app"
ditto --norsrc --noextattr "$PRODUCTS/certificate-checker" "$STAGE/certificate-checker"
/usr/bin/xattr -cr "$STAGE" 2>/dev/null || true
/usr/bin/codesign --force --sign - "$STAGE/Certificate Checker.app"
/usr/bin/codesign --force --sign - "$STAGE/certificate-checker"
# Strict verify here, outside the synced folder: the file provider re-adds FinderInfo/provenance attributes in dist/.
/usr/bin/codesign --verify --strict --verbose=1 "$STAGE/Certificate Checker.app"
/usr/bin/codesign --verify --strict --verbose=1 "$STAGE/certificate-checker"
rm -rf "$DIST/Certificate Checker.app"
ditto --norsrc --noextattr "$STAGE/Certificate Checker.app" "$DIST/Certificate Checker.app"
ditto --norsrc --noextattr "$STAGE/certificate-checker" "$DIST/certificate-checker"
"$(dirname "$0")/verify-signatures.sh" "$DIST"
xcrun lipo -info "$DIST/Certificate Checker.app/Contents/MacOS/Certificate Checker" "$DIST/certificate-checker"
echo "Built: $DIST/Certificate Checker.app"
