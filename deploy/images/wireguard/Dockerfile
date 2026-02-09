FROM alpine:3.20

ARG VCS_REF=""
LABEL org.opencontainers.image.title="tracegate-wireguard" \
      org.opencontainers.image.source="https://github.com/MyHeartRaces/Tracegate" \
      org.opencontainers.image.revision="${VCS_REF}"

RUN apk add --no-cache bash iproute2 iptables wireguard-tools

COPY deploy/images/wireguard/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
