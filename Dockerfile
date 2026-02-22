FROM python:3.12-slim

ARG VCS_REF=""
LABEL org.opencontainers.image.title="tracegate" \
      org.opencontainers.image.source="https://github.com/MyHeartRaces/Tracegate" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY pyproject.toml /app/
COPY alembic.ini /app/
COPY alembic /app/alembic
COPY src /app/src
COPY bundles /app/bundles

# Runtime deps for the node-agent:
# - procps: pgrep/pkill
# - iproute2: ss
# - wireguard-tools: wg
# - nftables: nft (host firewall apply)
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        procps \
        iproute2 \
        wireguard-tools \
        nftables \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

CMD ["tracegate-api"]
