# Telegram resilience under DPI and whitelist networks

This document defines the Tracegate 3 availability model for Telegram. It
does not claim that one proxy endpoint can remain reachable under every
filtering policy. If a provider allows no route to a Tracegate-controlled or
relay destination, a server-side change cannot create one.

## Scope

Tracegate has two separate Telegram paths:

1. **Native MTProxy** for an unmodified Telegram client. The client connects to
   Entry TCP/443; HAProxy forwards the no-SNI stream to the Endpoint-local
   official MTProxy; Telegram DC traffic exits from Endpoint.
2. **Telegram over a Tracegate tunnel**. The operating system or
   Tracegate-Router sends ordinary Telegram traffic through an HTTPS-shaped or
   other working Tracegate carrier. Telegram's own proxy setting is disabled.

The second path is the only generally useful design when a provider allows
HTTPS to a limited set of networks but blocks the DNS-only MTProxy address.

## Filtering model

The operator-provided research describes several independent failure modes:

- destination IP, subnet or ASN classification;
- TLS ClientHello/SNI/fingerprint classification;
- a temporary freeze after a burst of parallel TLS handshakes;
- payload-volume limits on one TCP flow;
- active probing and protocol-specific packet-size classification;
- a strict allowlist where the Entry address is never routable.

These modes require different transports. Changing SNI does not fix an
IP/ASN allowlist. REALITY or FakeTLS can imitate a TLS destination, but it does
not move packets to that destination's IP. A community `whitelist.txt` is an
input for carrier testing, not proof that an arbitrary server using one of its
names will be allowed.

The June 2026 field reports also conflict with one another: older observations
describe SNI allowlisting, while newer tests report no SNI whitelist for the
ClientHello concurrency limiter. Tracegate therefore treats every SNI and
fingerprint property as provider-specific and expiring.

## Transport matrix

| Lane | Native Telegram client | Survives direct Entry IP block | Main limitation |
| --- | --- | --- | --- |
| Official MTProxy + random padding | Yes | No | Address and MTProto behavior remain classifiable |
| Telemt/MTG FakeTLS | Yes | No | Telegram ClientHello/JA4 is client-controlled; changing the server is not a general fix |
| Cloudflare Spectrum TCP | Yes | Potentially | Custom TCP requires the Enterprise Spectrum add-on |
| Cloudflare-proxied gRPC/H2 Tracegate tunnel | No; requires TUN/router | Often, when the proxied hostname is allowed | Own hostname or Cloudflare can still be filtered |
| WSS/HTTPS Tracegate fallback | No; requires TUN/router | Same as above | More overhead and reconnect sensitivity |
| Hysteria2/Salamander | No; requires TUN/router | Only when UDP path is allowed | UDP/QUIC is commonly throttled or disabled |
| DNS tunnel | No; requires a local client/router | Sometimes | Low bandwidth, resolver interference, high operational cost |

Ordinary Cloudflare proxying and a public Cloudflare Tunnel hostname do not
turn a raw MTProxy socket into a native Telegram-compatible endpoint. Public
non-HTTP Tunnel services require `cloudflared` on the client. Cloudflare's
normal proxied gRPC service is appropriate for the Tracegate tunnel lane, not
for a `tg://proxy` link.

## Runtime policy

### Native lane

- Keep the official MTProxy random-padding transport as the production
  baseline while it has better measured availability than FakeTLS.
- Keep the raw 16-byte secret stable during runtime changes so existing links
  remain compatible. Rotate only after a staged overlap plan.
- Pin the MTProxy image by digest. A mutable `latest` image is forbidden by the
  production overlay check.
- Persist the upstream-owned `proxy.secret` and Telegram DC configuration in
  gateway state and update them atomically. A temporary `core.telegram.org`
  outage must not prevent a replacement pod from using its last known-good
  public runtime metadata. Keep the client/server access secret only in the
  Kubernetes Secret-backed `emptyDir`, not in this cache.
- Require startup, readiness and liveness TCP probes on the loopback MTProxy
  backend. HAProxy being alive is not proof that MTProxy is alive.
- Keep the Entry-to-Endpoint source ACL and exempt the trusted Entry address
  from Endpoint per-source abuse limits.
- Classify non-TLS traffic after the first two bytes so raw MTProto does not
  wait for the full TLS inspection timeout.
- Do not claim availability from a TCP-open check. The release gate must create
  a Telegram auth key or perform another authenticated, sustained protocol
  probe through the public path.

Telemt remains a canary candidate, not an automatic failover target. Its own
project notes that the June 2026 malfunction is caused by the Telegram
client's TLS ClientHello/JA4 fingerprint. Server failover between official
MTProxy and Telemt cannot repair a client-originated fingerprint while keeping
an unmodified native client.

### Tunnel lane

- Finish Universal Entry on a dedicated Cloudflare-proxied hostname using real
  TLS, HTTP/2 and one multiplexed gRPC connection.
- Keep reconnect jitter and `maxParallelHandshakes=1`; do not race all shards.
- Use the XHTTP/REALITY backhaul as primary and Hysteria2/Salamander as an
  independent UDP failure domain.
- Route Telegram service traffic through this lane in Tracegate-Router TUN
  mode. Do not simultaneously force the MTProxy bearer through the same tunnel
  by default; that creates an unnecessary nested route.
- Expose an explicit emergency override for users who intentionally need a
  nested MTProxy path. It must never be the default health policy.

### Ingress diversity

One Entry IP is a single filtering and provider failure domain. Alias rotation
on that IP does not change this. Production-grade rotation requires at least
two Entry addresses in different ASNs/providers, revision-sticky assignment,
overlap during drain and payload-based health scoring. Rotation on every
connection attempt is forbidden because it increases ClientHello bursts and
destabilizes clients.

## Whitelist-mode decision tree

1. If native MTProxy transfers sustained payload, use it.
2. If the MTProxy address is blocked but the proxied Universal Entry hostname
   works, disable Telegram's internal proxy and use the system/router tunnel.
3. If the HTTPS carrier fails but an independent UDP path works, use the
   Hysteria2/Salamander tunnel.
4. If only recursive DNS is usable, offer an explicitly low-bandwidth DNS
   tunnel profile for messaging and control traffic.
5. If none of the controlled or relay destinations is reachable, report the
   path as unavailable. Do not loop through endpoint/SNI rotations indefinitely.

## Required observability

- public-path authenticated MTProxy probe success and duration;
- Entry and Endpoint HAProxy backend availability and connection rate;
- MTProxy container readiness/restarts and runtime image digest;
- reconnect rate and successful payload duration per carrier;
- Universal Entry gRPC connection duration and backhaul selection;
- carrier result labelled by provider, access type and region, without storing
  user addresses or secrets;
- alerts for stale Telegram DC configuration and any secret-like value in
  container logs.

The upstream `mtproxy/mtproxy` entrypoint prints the raw secret and generated
links. The Tracegate chart replaces it with a non-logging runner. Deployments
from before that change still have sensitive MTProxy logs and must not export
them to a shared logging system; rotate their secret after the safe runner is
rolled out and active grants can be reissued.

## Rollout gates

1. Render and validate HAProxy/Helm with synthetic secrets.
2. Confirm the MTProxy image resolves to the expected digest.
3. Verify both gateway pods remain Ready during a sequential rollout.
4. Run an authenticated public-path MTProxy probe repeatedly, including a
   reconnect test and sustained payload interval.
5. Test Universal Entry from at least two real provider networks; localhost or
   Endpoint tests do not exercise provider DPI.
6. Promote a carrier only after it passes the provider matrix. Retain the
   previous generation through the configured overlap window.

The repository includes `scripts/probe_mtproto.py` for the authenticated part
of this gate. Feed the secret through stdin or an ignored file; never place it
on the command line. The probe creates a Telegram auth key but does not replace
the longer provider-specific sustained-payload test.

## References

- [Telegram MTProxy](https://github.com/TelegramMessenger/MTProxy)
- [Telemt](https://github.com/telemt/telemt)
- [Cloudflare gRPC](https://developers.cloudflare.com/network/grpc-connections/)
- [Cloudflare Spectrum](https://developers.cloudflare.com/spectrum/)
- [Cloudflare Tunnel routing](https://developers.cloudflare.com/tunnel/routing/)
- [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)
- [net4people issue 490](https://github.com/net4people/bbs/issues/490)
- [June 2026 ClientHello observations](https://habr.com/ru/articles/1044396/)
- [Siberian blocking observations](https://habr.com/ru/articles/1010336/)
- [Operator-provided whitelist dataset](https://github.com/hxehex/russia-mobile-internet-whitelist)
