FastAPI app (Jinja2 + htmx): routes in main.py, request hardening in security.py, login, sessions, lockout and rate limits in auth.py, the UI certificate in tlsboot.py, /config/ca in cabundle.py, in-memory form parsing in forms.py. Run with python -m app (TLS 1.2+ on 0.0.0.0:8080 and a login; python -m app hash-password makes the password hash). One worker, one event loop: all of this state is per process.

Notes (review M5 S2/S3):
- /api/v1/openapi.json needs a session since M6 (it was public in M5). Swagger/ReDoc are off (CSP).
- CSRF: an unsafe request is refused when Sec-Fetch-Site is cross-site or same-site, or when Origin is present and not this origin. There is no Referer fallback when Origin is missing; such requests still need the form CSRF token (UI) or a JSON body / X-CertCheck-Request header (API).
- At most CERTCHECK_MAX_CONCURRENT checks run at once; one more gets 429 straight away, never a queue. Each address also gets checks_per_minute checks (429 with Retry-After beyond it).

Notes (review M6):
- /config/ca anchors widen trust for live probes (TLS, STARTTLS, RADIUS, appliance checks) as well as for uploaded files: anything chaining to them is reported as trusted. Symlinks there are refused and each file is capped at 1 MiB.
- Login lockout: per address (default 5 failures in 15 min) plus a global limit of 4x that across all addresses. The global limit means anyone on the LAN can lock out every login for the lockout period by sending wrong passwords (sessions keep working). That trades availability for resistance to guessing spread over many addresses; tune it under login: in settings.yaml. See web/docker/DEPLOYMENT.md.
- The UI listener (certcheck.listener) offers TLS 1.2+ with AEAD ciphers only: on TLS 1.2, ECDHE with AES-GCM or ChaCha20-Poly1305.
- Empty and overlong passwords are refused but still pay one argon2 verify, so their timing matches a wrong password.
- A password-hash file readable by group or other is accepted with a warning (a compose secret keeps the host file's mode).
- Deployment (Docker, compose, Proxmox, DNS): web/docker/DEPLOYMENT.md.

## Notes (review M7)

- Behind Docker's userland proxy every client can appear as the bridge gateway, which defeats the LAN-only check and
  the per-address lockout; security.GatewayPeerWatch logs one warning when the first 20 non-loopback requests all
  come from the default gateway. Compose binds to `CERTCHECK_HOST_IP`, never 0.0.0.0 (see
  ../docker/DEPLOYMENT.md, "Client addresses").
- `python -m app healthcheck` connects to `CERTCHECK_BIND` (loopback for 0.0.0.0 or ::).

## Notes (review M7b, M8)

- `security.peer_ip` unwraps `::ffff:a.b.c.d` before any comparison with the gateways; `default_gateways` reads
  both `/proc/net/route` and `/proc/net/ipv6_route`.
- `CERTCHECK_REFUSE_GATEWAY_PEERS=1` (off by default) refuses every request whose peer is a default gateway (403),
  before the LAN check.
- The OpenAPI version is the package version from `web/pyproject.toml` (1.0.0), the same value as
  `web/CHANGELOG.md`.

- M8f: there is no release workflow and no container registry. CI builds the image without pushing it, and
  `tests/test_review_m8f.py` keeps any workflow from gaining registry access; see `docker/BUILD.md`.
