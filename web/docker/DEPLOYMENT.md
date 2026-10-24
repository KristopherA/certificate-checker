# Deploying Certificate Checker Web

The image is generic: it holds no targets, CAs, certificates or passwords. Everything site-specific is mounted.
Supported hosts: an Ubuntu machine with Docker, or Proxmox (a VM or an LXC container running Docker). Synology
would probably work but is not a target.

## Quick start (Docker Compose)

```sh
cd web/docker
docker compose build
mkdir -p config secrets
docker run --rm -it certcheck-web:local hash-password | tail -1 > secrets/password_hash
sudo chown 10001:10001 secrets/password_hash && sudo chmod 400 secrets/password_hash
echo CERTCHECK_HOST_IP=10.0.0.20 > .env          # this host's LAN address; compose refuses to start without it
CERTCHECK_TLS_NAMES=certcheck.example.test,10.0.0.20 docker compose up -d
docker compose logs certcheck | grep 'UI certificate'   # compare this SHA-256 with the browser's warning
```

Browse to `https://certcheck.example.test:8443/` from a machine on the LAN and log in.

Use at least 12 characters for the password. Login is the main control against misuse (there is no target
allowlist), so a strong password, the lockout and LAN-only exposure all matter.

The container runs as UID/GID 10001. A Compose secret is a bind mount that keeps the host file's owner and mode, so
the hash file must be readable by UID 10001: `chown 10001:10001` plus `chmod 400` is best. If the file is readable
by group or other, the app still starts but logs a warning, because anyone who can read the hash can try to guess
the password offline.

The same hash can come from `CERTCHECK_PASSWORD_HASH` instead of a file, but environment variables show up in
`docker inspect`, so prefer the secret.

## Plain `docker run`

```sh
docker volume create certcheck-data
docker run -d --name certcheck --restart unless-stopped \
  -p 10.0.0.20:8443:8080 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 256 --memory 512m \
  -v "$PWD/config:/config:ro" -v certcheck-data:/data \
  -v "$PWD/secrets/password_hash:/run/secrets/certcheck_password_hash:ro" \
  -e CERTCHECK_TLS_NAMES=certcheck.example.test,10.0.0.20 \
  certcheck-web:local
```

## Client addresses, published ports and firewalls

The app's LAN-only check and its per-address login lockout both use the TCP peer address it sees. Two Docker
behaviours change that address or the exposure:

- **Every client can look like the gateway.** Through Docker's userland proxy (always on Docker Desktop, and on
  Linux for some IPv6 and hairpin setups) connections reach the container from the bridge gateway (usually
  the first address of the Docker bridge subnet), instead of the real client. Then the LAN-only check passes for everyone who can reach the port,
  including clients off the LAN if the host is exposed, and the lockout counts all clients as one address, so one
  person's failed logins lock everyone out. The app logs a warning ("clients all came from the gateway") once the
  first 20 non-loopback requests all arrive from the container's default gateway.
- **Published ports bypass the host firewall.** Docker writes its own iptables/nftables rules, so a port published
  on 0.0.0.0 is reachable even when ufw or firewalld says otherwise.

So compose publishes on one host address only, `CERTCHECK_HOST_IP` (for example `10.0.0.20`, set in `.env`); there
is no 0.0.0.0 default. To keep real client addresses, use rootful Docker on Linux with the default iptables NAT
(no userland proxy for IPv4), or `network_mode: host` with `CERTCHECK_BIND` set to the host's LAN address. Filter
the port on the Proxmox or network firewall as well, not only with ufw/firewalld on the Docker host.

## The /config volume (read-only)

| Path | What it holds |
| --- | --- |
| `/config/targets.yaml` | Saved targets, profiles, per-target legacy flag |
| `/config/ca/*.pem`, `*.crt`, `*.cer` | Internal CA certificates, trusted in addition to the system store |
| `/config/tls/cert.pem`, `key.pem` | The UI certificate and key; without them a self-signed one is made in `/data` |
| `/config/settings.yaml` | Rate and concurrency limits, timeouts, login lockout, optional denylist |

**Anchors in `/config/ca` widen trust everywhere.** A certificate that chains to one of them is reported as trusted
in live probes (TLS, STARTTLS, RADIUS and appliance checks) as well as in uploaded-file checks. Put only CAs you
control there. Symlinks are refused (copy the file in) and each file is capped at 1 MiB; the app does not start if
a file there cannot be read as certificates.

## Hardening

Compose and the `docker run` line above apply the spec's hardening: non-root (10001), read-only root filesystem,
a small `noexec` tmpfs at `/tmp`, every capability dropped, `no-new-privileges`, plus PID and memory limits. The
app needs no capability: it listens on 8080 inside the container, and its probes are ordinary outbound
connections. `/data` is the only writable path; it holds the generated UI key (0600).

The UI listener accepts TLS 1.2 and 1.3 only, with AEAD ciphers only (ECDHE with AES-GCM or ChaCha20-Poly1305 on
TLS 1.2). There is no HSTS header on purpose: with a self-signed certificate it would stop anyone clicking past the
browser's warning, even after checking the fingerprint.

### Login lockout and its denial-of-service trade-off

Five failed logins from one address within 15 minutes lock that address out for 15 minutes. All addresses together
get four times that allowance (20 failures in the window) before **every** login is locked for the lockout period.
That global limit stops someone spreading guesses across many LAN addresses, but it also means anyone on the LAN
can lock the real user out of logging in by sending 20 wrong passwords. Existing sessions keep working, and the
lock ends on its own (or on a container restart, which also logs everyone out). Tune it in
`/config/settings.yaml` under `login:` (`max_failures`, `window_min`, `lockout_min`). This trade-off favours
resisting guessing over availability, which suits a single-user LAN tool.

## DNS

The app resolves each target once, connects to exactly that address, and shows it in the result.

- On the default bridge network, Docker's embedded resolver forwards to the daemon's DNS servers. Set `dns:` in
  `compose.yaml` (or `--dns` on `docker run`, or `"dns"` in `/etc/docker/daemon.json`) to use your internal
  resolver.
- **Split-horizon pitfall:** if the container sees public DNS while the LAN uses internal answers, it can probe the
  wrong address or virtual host. Compare the resolved IP in the result with what you expect, or use the per-probe
  resolve override (like `curl --resolve host:port:ip`).
- `network_mode: host` uses the host's own resolver and reaches LAN hosts directly. Remove `ports:` then; the app
  listens on `CERTCHECK_PORT` (8080) on the host, so set `CERTCHECK_PORT` if that port is taken.

## Proxmox

- **VM (recommended):** an Ubuntu 24.04 VM with Docker Engine is the simplest and closest to the supported
  Ubuntu host. Give it 1 vCPU and 1 GB of RAM. Bridge it onto the LAN (`vmbr0`) so clients reach it directly.
- **LXC:** Docker inside an *unprivileged* Ubuntu 24.04 container works with `features: nesting=1,keyctl=1` in
  `/etc/pve/lxc/<id>.conf` (or Options > Features in the UI). Do not use a privileged container. If Docker
  cannot apply `read_only` or `no-new-privileges` inside the LXC, fix the LXC features rather than dropping
  the hardening; if that fails, use a VM.
- Either way, give the guest a static LAN address (or a DHCP reservation), and put that name and address in
  `CERTCHECK_TLS_NAMES` so the self-signed certificate matches.
- The Proxmox host's own firewall can limit port 8443 to the LAN subnets as a second layer.
- Probing the Proxmox host itself (port 8006) from a guest is an ordinary LAN check; the app only blocks its own
  UI port, loopback, link-local and cloud metadata addresses by default.

## Upgrading

`docker compose build --pull && docker compose up -d`. Sessions and lockouts live in memory and are cleared by a
restart; the UI certificate in the `certcheck-data` volume is kept.

## Health

`GET /api/v1/health` needs no login. The image's `HEALTHCHECK` runs `python -m app healthcheck`, which asks the
container's own listener at `CERTCHECK_BIND` (loopback when the bind is 0.0.0.0 or ::).
