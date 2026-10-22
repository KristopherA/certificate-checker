# Deployment: Certificate Checker 0.7.0

## Requirements

- macOS 14 or later. PFX checks need macOS 15 or later, because the app imports in memory only.
- Apple Silicon or Intel (universal binary).
- No administrator rights, agents, kernel or system extensions, or LaunchAgents/LaunchDaemons. The app runs only when a user opens it.

## Current build

- `Certificate Checker.app` (bundle ID `tools.certificatechecker.desktop`) and `certificate-checker` (CLI).
- **Ad-hoc signed only.** On another Mac, Gatekeeper will block it until it is Developer ID signed and notarized. Follow `SIGNING-PROCEDURE.md`. Don't strip quarantine or disable Gatekeeper.

## Permissions users may see

- **Files & Folders (Documents/Desktop/Downloads):** the first time a user checks a file from a protected folder. Files are read only.
- **Network firewalls (for example Little Snitch):** probes make outbound TCP connections to the targets the user adds. Allow outbound connections for Certificate Checker to the internal services it checks. Implicit TLS and STARTTLS then work.
- **Connection Workbench hand-off:** this only opens the app and writes the target URL to the clipboard.

## Data

| Data | Location | Retention |
|---|---|---|
| Saved targets (name, host, port, service, SNI, expected name, platform, notes) | `~/Library/Application Support/CertificateChecker/targets.json`, 0600 | Until the user deletes the targets |
| Check results, transcripts, certificates | Memory | Discarded when the app quits |
| Private keys, PFX passwords | Memory, for the duration of one check | Never stored, logged or uploaded |

To remove the app, delete it and `~/Library/Application Support/CertificateChecker`.

## Managed deployment

1. Sign, notarize and package it following `SIGNING-PROCEDURE.md`.
2. Distribute through your organisation's normal software deployment (for example Munki). No configuration profile is needed.
3. If the managed firewall policy needs one, add an allow rule for Certificate Checker's outbound TCP connections to internal service ports: 443, 636, 389, 465, 587, 993, 143, 995, 110 and 3306.


## Location and signature verification (updated 2026-10-21)

The build and its verification work wherever the project folder lives, including a folder synced by iCloud Drive (for example under ~/Documents). Moving it to ~/Applications is not required.

iCloud Drive adds `com.apple.FinderInfo` and file-provider extended attributes to bundles in Documents, so `codesign --verify --strict` reports "resource fork, Finder information, or similar detritus not allowed" there even though the signature is intact. The build therefore verifies like this (`verify-signatures.sh` in Source/, the repository root; run automatically at the end of `build.sh`, and runnable on its own without rebuilding):

1. `codesign --verify --deep` on the app and CLI in place.
2. `ditto --norsrc --noextattr` copies of both into a temporary folder outside Documents, then `codesign --verify --deep --strict` on those copies.
3. The CDHash of each stripped copy must equal the in-place CDHash; the script fails otherwise and prints the CLI identifier.

```sh
./verify-signatures.sh   # run from Source/ (the repository root)
```

Rebuilding changes the CLI cdhash (see VALIDATION.md); Little Snitch must re-approve it.

Organisation-specific settings (KB links, organisation name, placeholders) are per-user: deploy `~/Library/Application Support/CertificateChecker/config.json` separately if wanted (see README, Configuration).
