# The aegis verifier image.
#
# Runs as an init container beside every model-serving pod. Its whole job is to
# refuse to let an unverified model reach the serving container, so it is built
# to be small and boring: no torch, no modelscan, no build tooling, no shell
# beyond what the base provides.
#
# The `build` extra (torch + modelscan) is deliberately NOT installed — those are
# needed to *produce* a secured model, never to check one. Measured on the site
# packages alone that is 82 MB installed instead of 689 MB, and it keeps a large
# native ML stack out of a security-critical component that runs on every pod
# start. (The image itself lands ~500 MB; most of the remainder is the Python
# base and the cosign binary.)

FROM debian:12-slim AS tools

ARG ORAS_VERSION=1.3.3
# Matches the cosign major version the pipeline signs with. A v2 binary cannot
# be assumed to read every v3-produced bundle, so keep these in step.
ARG COSIGN_VERSION=3.1.1
ARG TARGETARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_${TARGETARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin oras \
    && curl -fsSL -o /usr/local/bin/cosign \
        "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${TARGETARCH}" \
    && chmod +x /usr/local/bin/oras /usr/local/bin/cosign \
    && rm -rf /var/lib/apt/lists/*


FROM python:3.12-slim

COPY --from=tools /usr/local/bin/oras /usr/local/bin/oras
COPY --from=tools /usr/local/bin/cosign /usr/local/bin/cosign

WORKDIR /app
COPY pyproject.toml README.md ./
COPY supplychain ./supplychain

# No --extra build: verification does not need torch or modelscan.
RUN pip install --no-cache-dir . \
    && find /usr/local/lib/python3.12 -name '__pycache__' -prune -exec rm -rf {} +

# Unprivileged by default. The verifier only ever needs to read the registry and
# write to the shared model volume.
RUN useradd --uid 65532 --create-home --shell /usr/sbin/nologin aegis
USER 65532

ENTRYPOINT ["aegis"]
CMD ["--help"]
