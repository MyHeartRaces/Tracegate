FROM debian:bookworm-slim AS xray-builder

ARG XRAY_VERSION=latest

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN set -eux; \
    version="${XRAY_VERSION}"; \
    if [ "$version" = "latest" ]; then \
        zip_url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"; \
    else \
        zip_url="https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip"; \
    fi; \
    curl -fsSL -o /tmp/xray-linux-64.zip "$zip_url"; \
    unzip -j /tmp/xray-linux-64.zip xray geoip.dat geosite.dat -d /out; \
    chmod +x /out/xray; \
    rm -f /tmp/xray-linux-64.zip

FROM python:3.12-slim

ARG VCS_REF=""
LABEL org.opencontainers.image.title="tracegate" \
      org.opencontainers.image.source="https://github.com/MyHeartRaces/Tracegate" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY --from=xray-builder /out/xray /usr/local/bin/xray
COPY --from=xray-builder /out/geoip.dat /usr/local/bin/geoip.dat
COPY --from=xray-builder /out/geosite.dat /usr/local/bin/geosite.dat

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
