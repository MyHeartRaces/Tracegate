ARG CADDY_VERSION=2.9
ARG CADDY_BUILDER_IMAGE=caddy:${CADDY_VERSION}-builder-alpine
ARG CADDY_RUNTIME_IMAGE=caddy:${CADDY_VERSION}-alpine

FROM ${CADDY_BUILDER_IMAGE} AS builder

ARG FORWARDPROXY_REF=naive

RUN xcaddy build \
      --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@${FORWARDPROXY_REF} \
    && ./caddy list-modules | grep -Fx http.handlers.forward_proxy

FROM ${CADDY_RUNTIME_IMAGE}

ARG VCS_REF=""
ARG FORWARDPROXY_REF=naive
LABEL org.opencontainers.image.title="tracegate-naiveproxy-caddy" \
      org.opencontainers.image.description="Caddy runtime with the NaiveProxy forward_proxy module" \
      org.opencontainers.image.source="https://github.com/MyHeartRaces/Tracegate" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.base.name="${CADDY_RUNTIME_IMAGE}" \
      org.opencontainers.image.vendor="Tracegate" \
      tracegate.forwardproxy.ref="${FORWARDPROXY_REF}"

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

RUN caddy list-modules | grep -Fx http.handlers.forward_proxy
