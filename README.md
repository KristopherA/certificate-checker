# Certificate Checker

A native macOS app for checking certificate files and TLS services. It reports chain order, missing intermediates, SAN coverage, EKU, expiry, weak algorithms and key pairing, with fix steps for each platform. v0.5.2 (TLS, WireGuard, IKEv2 IPsec, RADIUS, RDP/RD Gateway/WinRM checks), macOS 14+, universal (Apple Silicon and Intel).

## Run

Open **Certificate Checker.app**. You don't need Homebrew, Python, OpenSSL or administrator rights. The companion `certificate-checker` command is optional.

This build has an ad-hoc signature. It is **not Developer ID signed or notarized**. To deploy it across your organisation, follow `SIGNING-PROCEDURE.md` and `DEPLOYMENT.md`. Don't disable Gatekeeper or remove quarantine to deploy it.

The app runs **on demand only**. It has no LaunchAgent, background agent, scheduler, telemetry, or update check.

## Files: offline checks

> **PFX/P12 requires macOS 15 or later.** It is opened with `kSecImportToMemoryOnly`, which does not exist on macOS 14; there the app disables the password field and refuses PFX files rather than importing them into a keychain.

1. **Files › Choose files…**, or drop files on the panel. Supported inputs:
   - PEM bundles and DER `.cer`/`.crt` files
   - PKCS#7 `.p7b`/`.p7c` bundles
   - CSRs
   - unencrypted PKCS#1, PKCS#8 and SEC1 private keys (RSA, ECDSA P-256/384/521, Ed25519)
   - PFX/P12 files
2. Optionally enter the expected hostname, the purpose (TLS server, TLS client or any) and the platform. The platform only selects which fix guidance you see.
3. For a PFX file, enter its password. The password is used for one check and then cleared.
4. Click **Check files**.

Checks:

| Check | Result |
|---|---|
| Chain order | Pass when the bundle goes leaf → issuer. Warning when it is out of order, with the correct order shown |
| Intermediates | Notes a bundle that stops at an issued certificate. Warns about unrelated certificates and AKI/SKI mismatches |
| Trust | macOS trust evaluation with network fetching **disabled**, so an offline check contacts nothing |
| Expiry | Fail when expired or not yet valid. Warning within 30 days |
| SAN / hostname | RFC 6125 matching: single-label wildcards, IP SANs, and a warning when a name matches only the Common Name |
| EKU | Fail when the selected purpose is missing. Info when there is no EKU extension |
| Weak algorithms | SHA-1/MD5 signatures on non-root certificates, RSA keys under 2048 bits |
| Key pairing | Compares the public half derived from the private key with each certificate, and with the CSR |
| Other | CA:TRUE on a leaf, lifetime over 398 days (info only, since private CAs may issue longer), SHA-256/SHA-1 fingerprints, SPKI pin |

### Private key handling

- Key files are read into memory. The app keeps only the derived public key and drops the private bytes when the check ends.
- Keys are never logged, cached, copied, uploaded or written to disk. Findings contain no key material, and a unit test enforces this.
- PFX files are opened with `kSecImportToMemoryOnly`, so nothing is imported into any keychain. On macOS 14 the app declines PFX checks rather than importing.
- Generated CSR commands write the key with umask 077 / `chmod 600`; delete the key file from the working folder after installing it.
- Encrypted PKCS#8 keys are not decrypted in v0.1. Use the matching PFX instead.

## Targets: live probes

Add a target (**+**): name, host or IP, service, port, optional SNI override, optional expected certificate name, and platform. Click **Check now** for one target or **Check all** for every saved target (up to four at a time).

| Service | Default port | Before TLS |
|---|---|---|
| HTTPS / TLS (implicit) | 443 | — |
| LDAPS | 636 | — |
| LDAP StartTLS | 389 | RFC 4511 ExtendedRequest 1.3.6.1.4.1.1466.20037 |
| SMTP STARTTLS / SMTPS | 587 / 465 | EHLO, then STARTTLS (must be advertised) |
| IMAP STARTTLS / IMAPS | 143 / 993 | `a1 STARTTLS` |
| POP3 STLS / POP3S | 110 / 995 | `STLS` |
| MySQL TLS | 3306 | Reads the server greeting, checks CLIENT_SSL, then sends an SSLRequest |

A probe never authenticates, sends no credentials, sends no application request (no HTTP request, no LDAP bind, no MySQL login), and follows no redirects.

The app collects the certificates the server presents in the order it sends them. It then runs the same analysis as the file check against the expected name, and a macOS trust evaluation. That trust evaluation may contact the CA's AIA/OCSP endpoints, the same way macOS does. The negotiated TLS version is shown, and TLS 1.0/1.1 gets a warning. The **Protocol transcript** shows the plaintext exchange: server lines are trimmed to printable ASCII and 200 characters.

Targets are saved to `~/Library/Application Support/CertificateChecker/targets.json` with mode 0600. Results are kept in memory only.

Each target also shows the equivalent `openssl s_client` command, for you to copy and run yourself. Commands you run on this Mac use Homebrew OpenSSL 3 via `"$(brew --prefix openssl@3)/bin/openssl"` (install with `brew install openssl@3`); commands meant for a server use that server's plain `openssl`: macOS's `/usr/bin/openssl` is LibreSSL, which lacks `-starttls ldap`/`mysql` and some options. Host names in commands are shell-quoted.

## Fix guidance

A warning or failure has a **How to fix** button. It opens steps for the selected platform:

- pfSense Cert Manager, including IPsec IKEv2
- Windows AD (LDAPS)
- IIS / RD Gateway
- nginx and Apache
- Zimbra
- MySQL
- Synology DSM
- Proxmox VE
- Proxmox Backup Server: the default self-signed certificate, with its fingerprint pinned in PVE
- macOS

Commands are **copy-only**. The app never runs them. Each guidance card can show links to your own knowledge-base documents. No links are built in: a KB button appears only when its topic has a link in your configuration (see **Configuration** below). Topics: `pki`, `runbook`, `checklist`, `ldapsReplace`, `ldapRef`, `mysqlRotation`, `mysqlAdmin`, `zimbra`, `reverseProxy`, `proxmox`, `synology`, `pfSense`, `radiusGuide`, `radiusWifi`, `radius8021x`, `wgRunbook`, `wgCheatSheet`, `wgHandbook`, `ikev2Profile`.

The key-match commands and the `s_client` pattern follow common OpenSSL practice. The app reimplements its checks natively, without a shell.

## Configuration

Organisation-specific values live in a user configuration file, never in the app:

- Default location: `~/Library/Application Support/CertificateChecker/config.json`
- Override (CLI only): `certificate-checker --config PATH …`, or the `CERTCHECK_CONFIG` environment variable (`none` = built-in defaults). The app always reads the default location (apps opened from Finder do not see shell variables) and shows the config source in its sidebar.
- KB links: remote links must be `https://`; local links must be documents. Folders, bundles and executables (`.app`, `.command`, `.terminal`, `.workflow`, files with the executable bit, …) are refused.
- Show or check it: `certificate-checker config` / `certificate-checker config --check` (exit 1 if a configured local KB file is missing).

All keys are optional; built-in defaults are generic (example.com, no KB links, KB buttons hidden). See `config.example.json`:

| Key | Meaning | Default |
|---|---|---|
| `organizationName` | Shown in the app footer | empty |
| `kbRoot` | Folder that relative `kbLinks` paths start from | none |
| `kbLinks` | Topic (incl. `rdp`, `rdGateway`, `winrm`) → relative path, absolute/`~` path, or http(s)/file URL | `{}` |
| `defaultDomain` | Example domain used in hints | `example.com` |
| `hostPlaceholder`, `vpnHostPlaceholder`, `radiusHostPlaceholder` | Placeholders in fields and copy-only commands | `host.example.com`, `vpn.example.com`, `radius.example.com` |
| `signingProcedureDoc` | Name of your signing/distribution procedure | `SIGNING-PROCEDURE.md` |
| `connectionWorkbenchApp` | Path to Connection Workbench, if not found by bundle ID | none |

Keep a local copy of your values in `config.local.json` (gitignored) if you want one next to the source.

## WireGuard: offline checks (milestone 2)

**WireGuard** in the sidebar, or `certificate-checker wireguard FILE... [--expect-public KEY]`. Accepts wg-quick `.conf` files and a pfSense `config.xml` export (installedpackages › wireguard: tunnels and peers, grouped by `<tun>`). Nothing is sent over the network; there are no UDP probes.

| Check | Result |
|---|---|
| Key format | Interface, peer and preshared keys must be canonical base64 of exactly 32 bytes |
| Key pair | Public key derived from the private key with CryptoKit Curve25519; compared with pfSense's stored `<publickey>` and with `--expect-public` / the app's expected-key field |
| Peers | Duplicate peer keys and a peer key equal to the interface's own key fail; a missing PublicKey fails |
| PresharedKey | Must be valid 32-byte base64 |
| AllowedIPs | Invalid prefixes fail; the same prefix on two peers fails (cryptokey routing gives it to one peer only); a contained prefix warns |
| Endpoint | `host:port` or `[IPv6]:port`, port 1–65535; unbracketed IPv6 or a missing port fails |
| Both ends | Given two or more configs, each side must list the other's public key; a one-sided match fails (usually a re-key) |

Fix guidance covers pfSense (VPN › WireGuard), Linux wg-quick and the macOS WireGuard app, with optional KB links (`wgRunbook`, `wgCheatSheet`, `wgHandbook`). Guidance never suggests `wg showconf` or printing key files.

**Private keys:** decoded in memory only to derive the public key. The parsed model stores no private key or preshared key value (only their validity), so keys cannot appear in findings, the UI, CLI output or logs. A unit test and a test.sh check of real CLI output enforce this.

## Connection Workbench hand-off

An HTTPS target shows **Copy URL & open Workbench**. It puts the target URL on the clipboard and opens Connection Workbench (by bundle ID, or from the path set in `connectionWorkbenchApp` in config.json). Use it when the problem is reaching the service (DNS, proxy, VPN) rather than the certificate.

## Command line

```sh
certificate-checker file fullchain.pem server.key --host intranet.example
certificate-checker probe ldaps dc1.ad.example
certificate-checker wireguard server.conf client.conf
certificate-checker wireguard config.xml --expect-public 'BASE64PUBLICKEY='
certificate-checker probe smtp-starttls mail.example --port 587
certificate-checker probe https 198.51.100.5 --sni portal.example --expect portal.example
certificate-checker file bundle.pfx                 # prompts for the password without echo
certificate-checker file identity.bin --pfx          # treat a file without .pfx/.p12 extension as PFX and prompt
printf '%s\n' "$PW" | certificate-checker file bundle.pfx --password-stdin   # piped; on a terminal it prompts hidden
```

Exit status is 0 when there are no failures, 1 when there are failures, and 2 for a usage error.

## Not in v0.1 (planned milestones)

- pfSense IPsec IKEv2 Cert Manager export checks
- RADIUS EAP via `eapol_test`
- RDP / RD Gateway / WinRM
- Synology, PVE/PBS API checks, including the PBS fingerprint compared with PVE `storage.cfg`
- Docker registry
- Beats mTLS
- Munki
- FileMaker
- Retrospect
- HP printers
- Barracuda
- S/MIME
- DKIM
- code signing
- SSH host keys
- encrypted PKCS#8 keys

## Build from source

Requirements: macOS 14+, Xcode 16+ and [XcodeGen](https://github.com/yonaskolb/XcodeGen). The Xcode project is generated from `project.yml` and is not checked in.

```sh
brew install xcodegen
git clone https://github.com/<owner>/certificate-checker.git && cd certificate-checker
xcodegen generate            # optional: build.sh also runs it
./build.sh                   # icon, project, universal Release build, ad-hoc sign -> ./dist
CC_IDENTIFIER_PATTERNS=none ./test.sh   # KB link check + XCTest (unit and loopback probe tests)
```

`build.sh` takes an optional output folder (default `./dist`) and uses `DEVELOPER_DIR` if your Xcode is not in `/Applications`.

**Tests and the identifier check:** `test.sh` and `verify-signatures.sh` run `check-identifiers.sh`, which fails unless a patterns file exists at `~/Library/Application Support/CertificateChecker/identifier-patterns.txt` (or the path in `CC_IDENTIFIER_PATTERNS`). Set `CC_IDENTIFIER_PATTERNS=none` to check only for personal home paths, or create the file with one extended regex per line for the names your organisation must never publish.

**Test fixtures:** the keys, certificates, PKCS#12 file and WireGuard configs in `Tests/Fixtures/` are throwaway test material for example domains (`example.test`, `example.internal`) and documentation IP ranges only. They are not used anywhere real; regenerate them with the `Tests/make-*.sh` scripts. `.gitleaks.toml` allowlists them for secret scanners.

**Running tests modifies the tree:** `test.sh` runs `xcodegen` (regenerating `CertificateChecker.xcodeproj`) and generates any missing synthetic, test-only fixtures into `Tests/Fixtures`, reusing existing ones. Run it on a working copy, not a frozen snapshot.

### Configuration setup

Copy the example config and edit it with your organisation's values:

```sh
mkdir -p ~/Library/Application\ Support/CertificateChecker
cp config.example.json ~/Library/Application\ Support/CertificateChecker/config.json
```

Or point the CLI at another file with `certificate-checker --config PATH …`. See **Configuration** above for every key.

### WireGuard memory note
Private keys are parsed in memory only and never logged, cached, copied or uploaded. The raw file text (Swift `String`/`Data`) is not zeroed after use; it is released when the check ends. pfSense XML with `<!DOCTYPE`/`<!ENTITY` is refused and external entities are never loaded. Disabled tunnels/peers and peers with `<tun>unassigned</tun>` are skipped and reported as info.

## IKEv2 IPsec (0.3.0)

`certificate-checker ipsec FILE... [--expect-id FQDN|IP]`, or the **IKEv2 IPsec** pane. Offline only — no IKE/UDP 500/4500 traffic.

Inputs: server and CA certificates exported from pfSense System › Cert. Manager (PEM/DER/PKCS#7), an optional unencrypted private key, or a pfSense `config.xml` backup (`<cert>`/`<ca>` entries; when IPsec Phase 1 entries name a `certref`, only those certificates are checked as servers). XML with `<!DOCTYPE`/`<!ENTITY>` is refused and external entities are never loaded.

Checks: serverAuth EKU (fail if missing); IKE intermediate EKU 1.3.6.1.5.5.8.2.2 (info — Microsoft's OID, recommended for Windows; macOS/iOS don't need it); DNS/IP SAN and the expected client identifier (wildcard-only match is info); keyUsage digitalSignature; RSA 2048+ or ECDSA P-256/384/521; SHA-256+ signature; validity and 30-day expiry warning; lifetime over 825 days is a warning (Apple's documented 825-day limit is for TLS server certificates issued after 1 July 2019 — HT210176 — and macOS/iOS IKEv2 clients are widely reported to apply it too); CA chain links (subject/issuer, AKI/SKI, signatures verified by macOS with the supplied CA as the only anchor, network off); issuers must have basicConstraints CA:TRUE (and keyCertSign when keyUsage is present); private key match.

Private keys (PEM or config.xml `<prv>`) are parsed in memory only to derive the public half; they are never shown, logged, cached or saved. File text stays in memory unzeroed until the check ends. A config.xml holds every private key on the firewall (including the CA's) — keep it out of synced folders.

Guidance is copy-only: pfSense Cert. Manager steps (and `swanctl`/`openssl` commands for Diagnostics › Command Prompt or SSH), the Windows IKEv2 client (PowerShell: CA into LocalMachine\Root, `Add-VpnConnection`), and macOS/iOS profiles (RemoteAddress/RemoteIdentifier in the SAN, `security verify-cert -p IPSec`). Optional KB links: `pfSense`, `pki`, `runbook`. A reference .mobileconfig profile is never opened by the app, because opening one starts a profile install.

### WireGuard follow-ups (0.2.0 approval)
- Linux key command: `mkdir -p /etc/wireguard` and `set -C`, writing `wg0.key.new` so an existing key is never overwritten.
- `--expect-public` falls back to the stated public key when the file has no private key, otherwise emits an info finding.
- `wg genpsk` guidance says to clear the terminal and scrollback afterwards.

## RADIUS / 802.1X (0.4.0)

- `certificate-checker radius FILE... [--expect NAME]` — offline: serverAuth EKU, the name clients expect (SAN, or CN as info), RSA 2048+/ECDSA, SHA-256+, validity, 825-day warning for certificates issued on/after 1 July 2019, chain to the CA (signatures verified locally, network off), private key match in memory.
- `certificate-checker radius-probe HOST [--port 1812] [--method peap|ttls] [--expect NAME] [--secret-stdin]` — one eapol_test attempt (`-r 0`, 15 s), anonymous outer identity, dummy inner password, no ca_cert; captures the chain with `-o` and analyses it. Authentication is expected to fail. This Mac must be a RADIUS client on the server. eapol_test is looked for only in /opt/homebrew/{bin,sbin} and /usr/local/{bin,sbin}; if missing the probe is skipped (exit 3) with copy-only install guidance.
- Shared secret: hidden prompt or `--secret-stdin`, in memory only, never logged or written to disk or targets.json. eapol_test only accepts it as `-s SECRET`, so it is briefly visible in the process list to local users while the probe runs. Output is reduced to EAP/RADIUS status lines and any line containing the secret or the word "secret" is removed.
- Copy-only guidance: Windows NPS, FreeRADIUS on Linux, pfSense FreeRADIUS package; KB: wireless-radius-8021x-guide.md, Change Radius for WIfi.txt, 802.1x and Active Directory (PDF), PKI lifecycle guide.

## 0.4.1: generic release

- No organisation-specific values in source, defaults, tests, fixtures or docs. Organisation name, KB links, placeholders and the signing-procedure name come from the user configuration (see **Configuration**). `check-identifiers.sh` (run by test.sh) fails if organisation identifiers listed in a local, untracked patterns file appear in the project tree.
- Chain building is shared (`ChainCheck`): a self-issued certificate counts as self-signed when its AKI or SKI is missing or they are equal, so rollover certificates (AKI ≠ SKI) are followed to the real root.
- RADIUS probe: outer identity `anonymous`, inner identity `certchecker-probe@invalid.example`; eapol_test is killed (SIGKILL) if it ignores SIGTERM after the timeout; MPPE and hexdump lines are never shown; name resolution is IPv4-only. Use a probe-only RADIUS client entry with its own shared secret.

## 0.4.2: release hardening

- `check-identifiers.sh` fails when the local patterns file is missing, empty or comments-only (set `CC_IDENTIFIER_PATTERNS=none` to check home paths only); only lines starting with `#` are comments; binary files are scanned (`grep -a`); only `xcuserdata` is excluded from the project; built binaries are scanned with `strings -a` (also by `verify-signatures.sh`).
- KB links: remote links must be https; folders, bundles and executables are refused. The app sidebar shows where its config came from. `CERTCHECK_CONFIG` is CLI-only.
- Test fixtures use documentation address ranges (198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).

## Remote access: RDP, RD Gateway, WinRM (0.5.0)

Sidebar **Remote access**, the Targets list (service types *RDP (TLS)*, *RD Gateway (HTTPS)*, *WinRM HTTPS*), or the CLI:

```sh
certificate-checker rdp host.example.com [--expect NAME]
certificate-checker rdg gateway.example.com
certificate-checker winrm host.example.com [--check-http]
certificate-checker probe rdp|rdg|winrm HOST          # same, as probe presets
```

- **RDP (3389):** one TCP connection. Sends a TPKT/X.224 Connection Request with an RDP Negotiation Request for PROTOCOL_SSL|PROTOCOL_HYBRID (no cookie, no user name), reports the selected protocol (CredSSP/NLA = pass; HYBRID_EX, RDSTLS or RDS AAD = fail as not requested; TLS without NLA = warning, Standard RDP Security = fail) or the failure code (SSL_NOT_ALLOWED_BY_SERVER, SSL_CERT_NOT_ON_SERVER, HYBRID_REQUIRED_BY_SERVER, …), then completes the TLS handshake and captures the chain. It stops there: no CredSSP messages, no credentials. `nmap --script rdp-enum-encryption,ssl-cert` is shown as the copy-only manual equivalent (openssl s_client cannot do the X.224 step).
- **RD Gateway (443):** checked by TLS handshake only (the gateway service itself, its RDG HTTP/RPC endpoints and UDP 3391 are not exercised): the HTTPS probe with RD Gateway rules (self-signed = fail, Connection Workbench hand-off available). No HTTP request is sent.
- **WinRM HTTPS (5986):** TLS only. Warns when the certificate CN differs from the host name. The plaintext HTTP listener (5985) is checked only with `--check-http` / the app toggle: one unauthenticated `POST /wsman`, reporting the offered authentication schemes (Basic over HTTP = fail, otherwise warning; a 401 without WWW-Authenticate or a `Server: Microsoft-HTTPAPI` header is reported as "likely WinRM").
- **Certificate checks:** EKU (RDP accepts Server Authentication or Remote Desktop Authentication 1.3.6.1.4.1.311.54.1.2; an RDA-only chain is trust-evaluated with the X.509 policy and hostname is checked separately), name/SAN match, self-signed Windows default RDP certificate (warning; its trust failure is downgraded to a warning only when it is the sole certificate, inside its validity dates and correctly self-signed), key and digest strength, expiry, presented SHA-1 thumbprint for comparison.
- **Guidance (copy-only PowerShell, `THUMBPRINT` placeholder, hosts PowerShell-quoted):** `Win32_TSGeneralSetting` `SSLCertificateSHA1Hash` via `Set-CimInstance` (or legacy `wmic`), NLA/security layer, RD Gateway Manager or `Set-Item RDS:\GatewayServer\SSLCertificate\Thumbprint`, `Set-RDCertificate`, `New-Item WSMan:\localhost\Listener … -CertificateThumbPrint`, WinRM Basic/AllowUnencrypted hardening, and firewall scoping notes. KB links via config keys `rdp`, `rdGateway`, `winrm`.

## License

MIT. See [LICENSE](LICENSE).
