# MTProto Shared Entry With Endpoint Runtime

Tracegate 3 uses MTG on Endpoint and exposes it through the same Entry
TCP/443 address used by the other Entry transports.

## Architecture

```text
Telegram client
  -> DNS-only MTProto hostname:443 on Entry
  -> HAProxy FakeTLS SNI demux
  -> Entry-local Xray tunnel inbound
  -> Reality/XHTTP Entry-to-Endpoint backhaul
  -> Endpoint-local MTG
  -> Telegram network through Endpoint egress
```

MTG does not run on Entry. Endpoint MTG is loopback-bound and has no
public frontend in `entry-endpoint-tunnel` mode. The tunnel fails closed when
the Endpoint backhaul is unavailable.

Because this mode shares Entry `tcp/443` with Universal Entry, direct source
filtering cannot live solely in nftables: nftables cannot inspect TLS SNI. The
host firewall allows `443` to HAProxy; HAProxy then rejects non-Cloudflare
origin traffic unless the SNI is the MTProto FakeTLS domain.

## Naming

The public connection hostname and FakeTLS SNI are separate values:

- public hostname: DNS-only record pointing to Entry;
- FakeTLS SNI: a validated, high-volume TLS domain that is not the public
  MTProto hostname.

User-facing delivery must show the public hostname from the profile `server`
field, not the FakeTLS SNI from the `domain` field.

The public-safe initial FakeTLS SNI is `2gis.ru`. Operators must
validate DNS/TLS reachability from target networks and rotate it when
necessary. Do not use `old-forbidden.tracegate-sni.ru` or
`old-mtproto-a.tracegate-sni.ru`.

Ordinary Cloudflare proxying cannot carry raw MTProto TCP. Keep the MTProto
public hostname DNS-only.

## Helm Values

```yaml
mtproto:
  enabled: true
  runtime: mtg
  domain: proto.example.net
  tlsDomain: 2gis.ru
  publicPort: 443
  fallback:
    enabled: false
  stealth:
    requireWhitelistedTlsDomain: true
    forbiddenTlsDomains: [old-forbidden.tracegate-sni.ru, old-mtproto-a.tracegate-sni.ru]
    validatedTlsDomains: [2gis.ru]
  route:
    mode: entry-endpoint-tunnel
    entry:
      tunnelPort: 11087
```

The raw 16-byte MTProto secret remains in an external private profile Secret.
The bot issues the derived FakeTLS Telegram link.

## Verification

1. Confirm Entry HAProxy routes only the configured FakeTLS SNI to
   `127.0.0.1:11087`.
2. Confirm direct non-Cloudflare `entry.example.net:443` is rejected by HAProxy.
3. Confirm the Entry Xray route uses the authenticated Endpoint backhaul.
4. Confirm MTG exists only in the Endpoint gateway pod.
5. Confirm MTG renders `proxy-protocol-listener = true` and no SOCKS proxy in
   `entry-endpoint-tunnel` mode.
6. Confirm Endpoint has no public MTProto frontend.
7. Test sustained Telegram traffic and reconnection through Endpoint egress.

No proxy configuration can guarantee permanent availability. Keep public
hostname, FakeTLS SNI and Entry address rotation operationally prepared.
