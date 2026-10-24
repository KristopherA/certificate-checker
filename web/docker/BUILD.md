# Building Certificate Checker Web locally

There are no published images and no container registry. Build the image on the Docker host from a checkout of the
repository, then run it with Compose or `docker run` as in [DEPLOYMENT.md](DEPLOYMENT.md).

## Docker Compose (recommended)

```sh
cd web/docker
docker compose build                              # tags certcheck-web:local
mkdir -p config secrets
docker run --rm -it certcheck-web:local hash-password | tail -1 > secrets/password_hash
sudo chown 10001:10001 secrets/password_hash && sudo chmod 400 secrets/password_hash
echo CERTCHECK_HOST_IP=10.0.0.20 > .env          # this host's LAN address; compose refuses to start without it
CERTCHECK_TLS_NAMES=certcheck.example.test,10.0.0.20 docker compose up -d
docker compose logs certcheck | grep 'UI certificate'   # compare this SHA-256 with the browser's warning
```

`CERTCHECK_HOST_IP` is required: compose publishes on that one address only, never 0.0.0.0. The other
`CERTCHECK_*` settings and the /config volume are described in DEPLOYMENT.md.

## Plain `docker build`

The build context is the repository root:

```sh
docker build -f web/docker/Dockerfile -t certcheck-web:local .
```

Optional OCI labels can be filled in with build arguments, for example
`--build-arg VERSION=1.0.0 --build-arg REVISION="$(git rev-parse HEAD)"`. `SOURCE_URL` is empty unless you pass it.
For another architecture, use buildx: `docker buildx build --platform linux/arm64 -f web/docker/Dockerfile .`

## Updating

Pull the new source, run `docker compose build`, then `docker compose up -d`. The /data volume and the mounted
/config are kept. Check `web/CHANGELOG.md` for changes.

## CI

`.github/workflows/web.yml` runs the tests and gitleaks, builds amd64 and arm64 with `push: false`, and scans the
image with Trivy. It has only `contents: read`, logs in to no registry and pushes nothing.
