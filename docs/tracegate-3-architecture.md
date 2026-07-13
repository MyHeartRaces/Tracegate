# Tracegate 3 host architecture

Tracegate 3 uses two Linux host roles: Entry and Endpoint. Services are
supervised by systemd; containerized transports use host networking and bind
their public or loopback addresses explicitly.

## Endpoint

Endpoint owns client ingress and internet egress. HAProxy owns public TCP/443
and dispatches by SNI to loopback-only Reality, TLS backup, ShadowTLS and
Telegram Proxy backends. Nginx terminates the public WebSocket surface,
including `/wgws`, and forwards WGWS using HTTP/1.1 upgrade semantics.

WireGuard peers are derived from the agent's private `desired-state.json` and
applied live by `tracegate-wireguard-sync-runner`. Revoked peers are removed
without restarting WireGuard or WSTunnel.

## Entry

Entry provides the Chain ingress. Its public listener forwards client traffic
to Endpoint through the private interconnect while Endpoint remains the only
internet egress role.

## Client profiles

- Direct: Reality and Hysteria2 (Salamander or Gecko);
- Chain: the managed Entry path;
- Backup: VLESS gRPC and VLESS WebSocket;
- Experimental: Shadowsocks-2022 with ShadowTLS v3 and WireGuard over
  WebSocket.

Telegram Proxy uses a per-account Telemt secret. The control plane records the
grant, and block/revoke operations remove the runtime secret.

## Public-safe runtime inputs

- `bundles/base-entry` and `bundles/base-transit`;
- `deploy/systemd`;
- `scripts/check_host_runtime.py`;
- `tracegate-host-private-preflight` and `tracegate-host-private-reload`.

Private credentials, rendered production state and live deployment coordinates
remain outside the public repository.
