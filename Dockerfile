FROM ghcr.io/xtls/xray-core:latest AS xray-runtime

FROM python:slim

ARG VCS_REF=""
LABEL org.opencontainers.image.title="tracegate" \
      org.opencontainers.image.source="https://github.com/MyHeartRaces/Tracegate" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY --from=xray-runtime /usr/local/bin/xray /usr/local/bin/xray
COPY --from=xray-runtime /usr/local/share/xray/geoip.dat /usr/local/bin/geoip.dat
COPY --from=xray-runtime /usr/local/share/xray/geosite.dat /usr/local/bin/geosite.dat

COPY pyproject.toml /app/
COPY alembic.ini /app/
COPY alembic /app/alembic
COPY src /app/src
COPY bundles /app/bundles

# Runtime deps for the node-agent:
# - procps: pgrep/pkill
# - iproute2: ss
# - nftables: nft (host firewall apply)
# - wireguard-tools: live WireGuard peer sync via wg set
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        procps \
        iproute2 \
        nftables \
        wireguard-tools \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

CMD ["tracegate-api"]
