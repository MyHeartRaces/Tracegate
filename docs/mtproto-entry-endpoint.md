# MTProto Shared Entry With Endpoint Runtime

Tracegate 3 production uses the official MTProxy runtime on Endpoint and
exposes it through the same Entry TCP/443 address used by the other Entry
transports.

## Architecture

```text
Telegram client
  -> DNS-only MTProto hostname mtproto.entry.example:443 on Entry
  -> Entry HAProxy no-SNI demux
  -> Endpoint public TCP/443 from the Entry source only
  -> Endpoint HAProxy no-SNI demux
  -> Endpoint-local official MTProxy
  -> Telegram network through Endpoint egress
```

MTProxy does not run on Entry. The Endpoint runtime is loopback-bound; the only
public path to it is Endpoint HAProxy accepting no-SNI traffic from the Entry
source address. Telegram egress is physically on Endpoint, not Entry.

Because this mode shares Entry `tcp/443` with Universal Entry, direct source
filtering cannot live solely in nftables: nftables cannot inspect TLS SNI. The
host firewall allows `443` to HAProxy; HAProxy then rejects non-Cloudflare
origin traffic unless it is either the controlled TLS adapter SNI or a no-SNI
MTProto flow.

## Naming

The production public connection has no FakeTLS SNI:

- public hostname: DNS-only `mtproto.entry.example`, pointing to Entry;
- client secret: official random-padding MTProxy secret;
- `tlsDomain`: empty.

Legacy MTG/FakeTLS test profiles may still use a validated `.ru` FakeTLS SNI
such as `2gis.ru`, but production MTProto must not depend on SNI or Cloudflare
proxying.

Ordinary Cloudflare proxying cannot carry raw MTProto TCP. Keep the MTProto
public hostname DNS-only.

## Helm Values

```yaml
mtproto:
  enabled: true
  runtime: official
  transport: random_padding
  domain: mtproto.entry.example
  tlsDomain: ""
  publicPort: 443
  fallback:
    enabled: false
    officialBindAddress: ""
    officialExternalIp: 198.51.100.20
    officialInternalIp: 198.51.100.20
  route:
    mode: entry-endpoint-tunnel
    endpoint:
      allowedProxySources: [203.0.113.10]
    entry:
      endpointHost: 198.51.100.20
      endpointPort: 443
```

The raw 16-byte MTProto secret remains in an external private profile Secret.
The bot issues the derived official MTProxy Telegram link.

For official MTProxy, `domain` is the client-facing Entry hostname, but
`officialExternalIp` must be the Endpoint egress address that reaches Telegram
DCs. Do not set `officialBindAddress` in hostNetwork mode; `--address
127.0.0.1` also binds upstream DC sockets to loopback in the upstream image.

## Verification

1. Confirm Entry HAProxy contains `use_backend be_mtproto_tls if !request_sni_found`.
2. Confirm Entry HAProxy does not reject no-SNI flows with
   `WAIT_END !universal_origin_allowed_src`.
3. Confirm Endpoint HAProxy contains
   `use_backend be_mtproto if !request_sni_found mtproto_proxy_src`.
4. Confirm `mtproto_proxy_src` contains only Entry source addresses.
5. Confirm official MTProxy exists only in the Endpoint gateway pod.
6. Confirm the bot profile has `server=mtproto.entry.example`, `transport=random_padding`
   and an empty `tlsDomain`.
7. Test sustained Telegram traffic and reconnection through Endpoint egress.

No proxy configuration can guarantee permanent availability. Keep public
hostname, secret and Entry address rotation operationally prepared.
