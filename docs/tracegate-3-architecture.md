# Tracegate 3 host architecture

Tracegate 3 uses two Linux host roles: Entry and Endpoint. Services are
supervised by systemd; containerized transports use host networking and bind
their public or loopback addresses explicitly.

## Endpoint

Endpoint owns client ingress and internet egress. HAProxy owns public TCP/443
and TCP/8443 and dispatches both ports by SNI, with identical rules, to
loopback-only Reality, TLS backup and Telegram Proxy backends. ShadowTLS
remains only on the source-gated Entry-to-Endpoint backhaul listeners, not on
the public TCP ports. Nginx terminates the public WebSocket surface.

## Entry

Entry provides the Chain ingress. Its public listener forwards client traffic
to Endpoint through a dedicated VLESS/REALITY RAW/TCP backhaul while Endpoint
remains the only internet egress role. Both Reality legs use RAW/TCP; the
retired split-HTTP transport is forbidden by the host runtime check.

## Public port model

| Surface | Entry | Endpoint |
| --- | --- | --- |
| TCP/443 | HAProxy: Chain Reality, Entry TLS, Telegram Proxy | HAProxy SNI demux |
| TCP/8443 | closed; optional MTProto-only listener | HAProxy SNI demux, same rules as TCP/443 |
| UDP/443 | Hysteria2 Gecko (Chain) | Hysteria2 Gecko (Direct) |
| UDP/8444 | closed | Hysteria2 Salamander (Direct) |
| UDP/4443 | Entry-to-Endpoint interconnect | Entry-to-Endpoint interconnect |
| UDP/8443 | closed | closed |

- Chain (client to Entry) is TCP/443 only. Reality is never reachable on
  Entry TCP/8443.
- Direct Reality (client to Endpoint): new and re-issued revisions use
  `REALITY_DIRECT_PORT` (default 8443). The previous revision stays active in
  the second slot, and Endpoint keeps serving TCP/443 for every profile issued
  there earlier.
- The WebSocket and gRPC backups stay on TCP/443.
- Telegram Proxy: delivered only through Entry on TCP/443; Entry never listens
  on TCP/8443 (except the legacy fallback mode with `MTPROTO_PUBLIC_PORT=8443`).
  No direct Endpoint backup route is delivered, and Endpoint renders no
  MTProto route on any public port (`MTPROTO_DIRECT_BACKUP_HOST` no longer
  affects Endpoint routing). Telegram reaches Endpoint-local Telemt only over
  the Entry link. Secrets never change.
- Hysteria2 port hopping (Direct only): a `LO-HI` range per obfs listener is
  redirected to that listener by a Tracegate-rendered `tracegate_hysteria_hop`
  nat table on Endpoint. The Endpoint host deploy generates private random
  ranges when none are configured and loads the table with
  `tracegate-hysteria-hop-apply`, which touches only that table and persists
  it through the host's `nftables.conf`. New and re-issued revisions carry the range;
  re-issue keeps the obfuscation chosen at creation.

None of these transports is described as resistant to every inspection
technique; the port model only changes which ports carry them.

## Client profiles

- Direct: Reality and Hysteria2 (Salamander or Gecko);
- Chain: the managed Entry path;
- Backup: VLESS gRPC and VLESS WebSocket;
- Retired: the client Shadowsocks-2022 + ShadowTLS v3 profile and WireGuard
  over WebSocket. Existing rows of both are revoked by migration and can no
  longer be issued; the inter-server backhaul keeps Shadowsocks-2022 inside
  ShadowTLS v3.

Telegram Proxy uses a per-account Telemt secret. The control plane records the
grant, and block/revoke operations remove the runtime secret.

## Public-safe runtime inputs

- `bundles/base-entry` and `bundles/base-transit`;
- `deploy/systemd`;
- `scripts/check_host_runtime.py`;
- `tracegate-host-private-preflight` and `tracegate-host-private-reload`.

Private credentials, rendered production state and live deployment coordinates
remain outside the public repository.
