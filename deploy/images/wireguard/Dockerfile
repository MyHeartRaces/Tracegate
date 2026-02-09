FROM alpine:3.20

RUN apk add --no-cache bash iproute2 iptables wireguard-tools

COPY deploy/images/wireguard/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
