# MTProto Shared Entry With Endpoint Runtime

Tracegate 3 production uses Telemt FakeTLS on Endpoint and exposes it through
the same Entry TCP/443 address used by the other Entry transports.

## Architecture

```text
Telegram client
  -> DNS-only MTProto hostname mtproto.entry.example:443 on Entry
  -> Entry HAProxy SNI demux for the validated FakeTLS domain
  -> Endpoint public TCP/443 from the Entry source only
  -> Endpoint HAProxy SNI demux
  -> Endpoint-local Telemt on loopback
  -> Telegram network through Endpoint egress
```

MTProxy does not run on Entry. The Endpoint runtime is loopback-bound; the
only public path is Endpoint HAProxy accepting the selected SNI from trusted
Entry source addresses. Telegram egress is physically on Endpoint.

Because this mode shares Entry TCP/443 with Universal Entry, source filtering
cannot live solely in nftables: nftables cannot inspect TLS SNI. The host
firewall allows TCP/443 to HAProxy, and HAProxy owns the protocol/SNI policy.

## Naming and masking

- public hostname: DNS-only `mtproto.entry.example`, pointing to Entry;
- client secret: Telemt `ee` FakeTLS secret;
- `tlsDomain`: a validated real site such as `example.ru`;
- Telemt `mask_host`: the same real site, so rejected or probe TLS sessions
  reach a genuine site rather than a synthetic local page.

Ordinary Cloudflare proxying cannot carry native MTProto TCP. Keep the MTProto
public hostname DNS-only.

## Helm values

```yaml
mtproto:
  enabled: true
  runtime: telemt
  transport: tls
  domain: mtproto.entry.example
  tlsDomain: example.ru
  publicPort: 443
  egress:
    domainFrontingHost: example.ru
  route:
    mode: entry-endpoint-tunnel
    endpoint:
      allowedProxySources: [203.0.113.10]
```

The raw 16-byte bootstrap secret remains in an external private profile
Secret. The bot issues per-user secrets and atomically regenerates
`access.users`; Telemt hot-reloads the file without a process restart.

Native Telegram does not implement MTProxy over WebSocket. WSS requires a
separate local TUN/router client and is not interchangeable with a
`tg://proxy` link.

## Verification

1. Confirm Entry HAProxy routes the configured FakeTLS SNI to
   `be_mtproto_tls`.
2. Confirm Endpoint HAProxy routes that SNI to `be_mtproto` only for trusted
   Entry sources.
3. Confirm Telemt exists only in the Endpoint gateway pod and its native
   readiness check succeeds.
4. Confirm the bot profile has `server=mtproto.entry.example`, `transport=tls`,
   the expected `tlsDomain` and a per-user secret.
5. Test an authenticated connection, sustained traffic and reconnection
   through the public path.

No proxy configuration can guarantee permanent availability. Keep public
hostname, bootstrap secret and Entry address rotation operationally prepared.
