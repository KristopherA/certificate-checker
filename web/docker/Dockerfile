# syntax=docker/dockerfile:1
# Certificate Checker Web image (spec section 9). Build from the repository root:
#   docker buildx build -f web/docker/Dockerfile -t certcheck-web:dev .
# Generic on purpose: no site data, no targets, no CA, no password. Everything site-specific is mounted at /config
# (read-only) and the password hash comes from a Docker secret or the environment. Base images are pinned by digest
# so OpenSSL behaviour stays stable (spec section 3, legacy TLS); bump the tag and digest together.
ARG PYTHON_IMAGE=python:3.12.15-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.8@sha256:3b7b60a81d3c57ef471703e5c83fd4aaa33abcd403596fb22ab07db85ae91347

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PYTHON=/usr/local/bin/python3 \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src/web
COPY web/pyproject.toml web/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY web/app ./app
COPY web/certcheck ./certcheck
RUN uv sync --frozen --no-dev --no-editable

FROM ${PYTHON_IMAGE}
# Optional OCI labels: pass with docker build --build-arg (see BUILD.md); empty or "dev" by default.
ARG SOURCE_URL=""
ARG VERSION="dev"
ARG REVISION=""
LABEL org.opencontainers.image.title="certcheck-web" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.description="Certificate Checker Web: on-demand certificate checks from a browser on the LAN" \
      org.opencontainers.image.licenses="MIT"
# openssl: chain verification (openssl verify) and copy-ready guidance. eapoltest: the RADIUS/EAP-TLS probe.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssl eapoltest \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 certcheck \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin certcheck \
 && install -d -o 10001 -g 10001 -m 0700 /data \
 && install -d -m 0755 /config
COPY --from=build /opt/venv /opt/venv
COPY shared/findings.yaml shared/web-findings.yaml /opt/certcheck/shared/
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CERTCHECK_SHARED=/opt/certcheck/shared CERTCHECK_CONFIG=/config CERTCHECK_STATE=/data \
    CERTCHECK_BIND=0.0.0.0 CERTCHECK_PORT=8080
USER 10001:10001
WORKDIR /
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["python", "-m", "app", "healthcheck"]
ENTRYPOINT ["python", "-m", "app"]
