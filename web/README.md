# Certificate Checker Web

A Linux-native web version of Certificate Checker: on-demand certificate checks from a browser on the LAN. It is a
single-user FastAPI app (server-rendered Jinja2 and htmx, no JavaScript build) packaged as a hardened Docker image.
It shares its findings catalogue and golden results with the Mac app (`../shared/`), so both report the same
problems the same way.

## What it checks

- **Live endpoints:** TLS on any port, STARTTLS (SMTP, IMAP, POP3, LDAP), MySQL, RDP, WinRM,
  LDAPS, appliance and vendor checks, RADIUS/EAP-TLS (`eapol_test`). Each check resolves the host once, connects to
  exactly that address and shows it, with an optional resolve override (like `curl --resolve`).
- **Files:** certificates, keys, chains, CSRs and PFX/PKCS#12 (the PFX password stays in memory only).
- **Trust and policy:** chain building, expiry, names, key usage, weak keys and signatures, with fix steps per
  platform.
- **Opt-in extras:** revocation (stapled OCSP, live OCSP, CRL fallback, must-staple), AIA and CT, and a legacy mode
  for TLS 1.0/1.1 devices, isolated from normal checks and always flagged INSECURE.

Results can be exported as JSON or Markdown. Nothing is stored unless you export it.

## Use it

There are no published images: build it locally with `docker compose build` (or `docker build`); see
[docker/BUILD.md](docker/BUILD.md) and [docker/DEPLOYMENT.md](docker/DEPLOYMENT.md). In short: set a
password hash (`hash-password`), set `CERTCHECK_HOST_IP` to the host's LAN address, `docker compose up -d`, then
browse to `https://<host>:8443/` and log in.

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/check` | Live check (JSON): host, port, profile, SNI, resolve override, legacy flag |
| `POST /api/v1/files/verify` | Multipart upload of a certificate, key, chain, CSR or PFX (+ password) |
| `GET /api/v1/profiles` | Check profiles and their default ports |
| `GET /api/v1/targets` | Saved targets from `/config/targets.yaml` (read-only) |
| `GET /api/v1/health` | Liveness, no login |
| `GET /api/v1/openapi.json` | OpenAPI document (needs a session) |

API calls need a session cookie from `/login` and either a JSON body or the `X-CertCheck-Request: 1` header.

## Security model

- One local user: argon2 password hash from a Docker secret (or the environment), sessions, CSRF protection and a
  login lockout. Login is the main control: any host the user enters can be checked (no target allowlist).
- LAN-only clients by default, a TLS 1.2+ UI with a mounted or self-signed certificate, a strict
  Content-Security-Policy, a 1 MB request cap, rate limits and a concurrency cap.
- Uploaded keys and passwords are never written to disk or logged.
- The container runs as UID 10001 with a read-only root filesystem, all capabilities dropped and
  `no-new-privileges`. There are no published images: build it locally
  ([docker/BUILD.md](docker/BUILD.md)).

Settings (`/config/settings.yaml` and `CERTCHECK_*` variables) are listed in [app/settings.py](app/settings.py) and
[docker/DEPLOYMENT.md](docker/DEPLOYMENT.md).

## Develop

```sh
cd web
uv sync --frozen
uv run ruff check . && uv run ruff format --check . && uv run mypy
uv run pytest -q
```

Integration tests run against throwaway servers in Docker: `../shared/tools/integration*.sh`. CI is
`.github/workflows/web.yml` (tests, gitleaks, an image build that is not pushed, and a Trivy scan). Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## Licence

MIT, like the Mac app.
