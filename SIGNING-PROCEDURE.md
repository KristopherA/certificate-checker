# Procedure: sign and distribute Certificate Checker

**Owner:** your macOS packaging / Apple Developer account administrators
**Updated:** 21 October 2026
**Application:** Certificate Checker 0.9.1, macOS 14+, Apple Silicon and Intel. Bundle ID `tools.certificatechecker.desktop`, executable `Certificate Checker`, CLI `certificate-checker`.
**Deliverable:** A signed, notarized installer that installs the app in `/Applications`.

Replace the placeholders with your organisation's values. This document contains no identities, Team ID or notary credentials, and no signing or Apple submission has been done for this build.

## 1. Confirm the signing identities

```sh
security find-identity -v
security find-identity -v -p codesigning
```

You need a **Developer ID Application** identity for the app and CLI, and a **Developer ID Installer** identity for the .pkg. An installer signature does not replace the app signature. Keep private keys in the approved keychain. Never send keys, `.p12` passwords or notary secrets through tickets.

## 2. Prepare a release copy outside synced folders

```sh
CC_VERSION='0.9.1'
CC_APP_IDENTITY='Developer ID Application: REPLACE WITH EXACT ORGANISATION NAME (TEAMID)'
CC_INSTALLER_IDENTITY='Developer ID Installer: REPLACE WITH EXACT ORGANISATION NAME (TEAMID)'
CC_NOTARY_PROFILE='CertificateChecker-Notary'
CC_RELEASE="$(mktemp -d /private/tmp/CertificateChecker.XXXXXX)"
ditto --norsrc --noextattr "Certificate Checker.app" "$CC_RELEASE/Certificate Checker.app"
ditto --norsrc --noextattr certificate-checker "$CC_RELEASE/certificate-checker"
```

## 3. Sign with hardened runtime

The app needs no entitlements: it is not sandboxed, makes only outbound TCP connections, and only reads files.

```sh
codesign --force --timestamp --options runtime --sign "$CC_APP_IDENTITY" "$CC_RELEASE/certificate-checker"
codesign --force --timestamp --options runtime --sign "$CC_APP_IDENTITY" "$CC_RELEASE/Certificate Checker.app"
codesign --verify --strict --deep --verbose=2 "$CC_RELEASE/Certificate Checker.app"
```

## 4. Package, notarize, staple

```sh
mkdir -p "$CC_RELEASE/root/Applications" && ditto --norsrc --noextattr "$CC_RELEASE/Certificate Checker.app" "$CC_RELEASE/root/Applications/Certificate Checker.app"
pkgbuild --root "$CC_RELEASE/root" --identifier tools.certificatechecker.pkg --version "$CC_VERSION" --install-location / "$CC_RELEASE/unsigned.pkg"
productsign --sign "$CC_INSTALLER_IDENTITY" "$CC_RELEASE/unsigned.pkg" "$CC_RELEASE/CertificateChecker-$CC_VERSION.pkg"
xcrun notarytool submit "$CC_RELEASE/CertificateChecker-$CC_VERSION.pkg" --keychain-profile "$CC_NOTARY_PROFILE" --wait
xcrun stapler staple "$CC_RELEASE/CertificateChecker-$CC_VERSION.pkg"
spctl --assess --type install -vv "$CC_RELEASE/CertificateChecker-$CC_VERSION.pkg"
```

Create the notary profile once, with `xcrun notarytool store-credentials "$CC_NOTARY_PROFILE"`, using your organisation's approved credentials.

## 5. Acceptance on a test Mac

Install the package and open the app. Confirm Gatekeeper accepts it, run a file check and one probe of each type against your own services, then allow the app in the managed firewall if needed. Record the results in VALIDATION.md before broad distribution.


## Location and signature verification (updated 2026-10-21)

The build and its verification work wherever the project folder lives, including a folder synced by iCloud Drive (for example under ~/Documents). Moving it to ~/Applications is not required.

iCloud Drive adds `com.apple.FinderInfo` and file-provider extended attributes to bundles in Documents, so `codesign --verify --strict` reports "resource fork, Finder information, or similar detritus not allowed" there even though the signature is intact. The build therefore verifies like this (`verify-signatures.sh` in Source/, the repository root; run automatically at the end of `build.sh`, and runnable on its own without rebuilding):

1. `codesign --verify --deep` on the app and CLI in place.
2. `ditto --norsrc --noextattr` copies of both into a temporary folder outside Documents, then `codesign --verify --deep --strict` on those copies.
3. The CDHash of each stripped copy must equal the in-place CDHash; the script fails otherwise and prints the CLI identifier.

```sh
./verify-signatures.sh            # checks Source/dist (what build.sh just built)
./verify-signatures.sh /path/dir  # checks another copy; the CLI path is printed next to its Identifier
```

Rebuilding changes the CLI cdhash (see VALIDATION.md); an outbound firewall such as Little Snitch must re-approve it.
