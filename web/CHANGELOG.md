# Changelog: Certificate Checker Web

Versions match `web/pyproject.toml`.

## 1.0.0 (unreleased)

First release. Built in milestones M0 to M8 of the Linux-native plan (rev 2.2).

- Shared findings catalogue and golden results with the Mac app; fixture CA.
- TLS probe with an explicit trust and policy engine; STARTTLS, MySQL, RDP, WinRM, LDAPS, appliance and vendor checks.
- Offline file checks (certificate, key, chain, CSR, PFX) and RADIUS/EAP-TLS via `eapol_test`.
- Opt-in revocation (stapled OCSP, live OCSP, CRL, must-staple), AIA and CT; isolated legacy TLS 1.0/1.1 mode.
- Web UI and REST API with JSON and Markdown export.
- Single-user login (argon2), sessions, CSRF protection, lockout, LAN-only clients, rate and concurrency limits.
- Hardened multi-arch image (amd64, arm64), compose file bound to one host address, Proxmox notes, CI with
  gitleaks, Trivy, SBOM and provenance.
- Warning when every client arrives from the Docker gateway (IPv4 and IPv6, IPv4-mapped peers unwrapped), and
  opt-in `CERTCHECK_REFUSE_GATEWAY_PEERS` to refuse them.
- No published images: build locally with `docker build` or `docker compose` (`web/docker/BUILD.md`); CI builds
  and Trivy-scans the image without pushing it.
