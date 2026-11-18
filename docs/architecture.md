# Tracegate 4 host architecture

Tracegate 4 uses two Linux host roles: Entry and Endpoint. Services are
supervised by systemd; containerized transports use host networking and bind
their public or loopback addresses explicitly.

## Endpoint

Endpoint runs the control plane (API, dispatcher, bot, database and
monitoring) and is the only role that sends client traffic to the internet.
Its public TLS listeners are demultiplexed by SNI to loopback-only backends:
Reality inbounds, the own-domain web layer (cover site and monitoring) and
the Telegram Proxy runtime. Direct Hysteria2 listeners (Salamander or Gecko
obfuscation, optional port hopping) also run here.

## Entry

Entry is a replaceable ingress for Chain profiles. It accepts the client
connection and forwards the traffic to Endpoint over a dedicated,
source-restricted backhaul; it never sends client traffic to the internet
itself. Entry applies a host-wide traffic cap to its outbound interface.

## Ports

Listener ports are deployment settings. The templates ship defaults; a
production deployment should choose its own values and keep them in private
state. These rules hold whatever the values are:

- backends listen on loopback; public listeners only route to them;
- a port setting applies to new issuance and to re-issues only. Stored
  revisions keep their address, port and SNI, and every listener that issued
  revisions use stays served until those revisions are revoked;
- `REALITY_DIRECT_PORT` selects the TCP port written into new Direct Reality
  revisions;
- Hysteria2 port-hopping ranges are generated per host on the first deploy
  when none are configured, and are private.

None of these transports is described as resistant to every inspection
technique; the port settings only change which ports carry them.

## Client profiles

- Direct: Reality and Hysteria2 (Salamander or Gecko);
- Chain: the managed Entry path, issued only as VLESS Reality;
- Retired in 4.0.0: the client Shadowsocks-2022 + ShadowTLS v3 profile and
  WireGuard over WebSocket. Existing rows of both are revoked by migration and
  can no longer be issued.
- Retired in 4.1.1: the VLESS gRPC-TLS and VLESS WebSocket-TLS profiles (the
  former Direct "Backup" profiles and the legacy WebSocket/gRPC Chain
  variants). Existing rows are revoked by migration and cannot be issued,
  re-issued, activated or exported; Reality and Hysteria2 cover the same
  networks.
- Retired in 4.1.2: Chain Hysteria (Hysteria2 in Chain mode, terminated on
  Entry). Existing rows are revoked by migration and cannot be issued,
  re-issued, activated or exported; Chain Reality and Direct Hysteria remain.

Telegram Proxy uses a per-account Telemt secret. The control plane records the
grant, and block/revoke operations remove the runtime secret.

## Public-safe runtime inputs

- `bundles/base-entry` and `bundles/base-transit`;
- `deploy/systemd`;
- `scripts/check_host_runtime.py`;
- `tracegate-host-private-preflight` and `tracegate-host-private-reload`.

Private credentials, rendered production state and live deployment coordinates
remain outside the public repository.
