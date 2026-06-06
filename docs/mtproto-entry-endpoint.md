# MTProto Entry With Endpoint Egress

Tracegate supports a production MTProto layout where the public proxy binary
runs on Entry while every outbound Telegram and domain-fronting connection is
forced through Endpoint.

## Architecture

```text
Telegram client
  -> Entry tcp/443 HAProxy SNI demux
  -> Entry MTG on loopback
  -> Entry ShadowTLS v3 client on loopback
  -> Endpoint tcp/443 HAProxy SNI and source-address demux
  -> Endpoint ShadowTLS v3 server on loopback
  -> Endpoint loopback SOCKS5 inbound
  -> Endpoint internet egress
```

The MTG proxy receives PROXY protocol v2 from HAProxy and has exactly one
configured network proxy: the Entry-side ShadowTLS client. An empty or direct
network path is not included. If the encrypted tunnel or Endpoint SOCKS inbound
is unavailable, Telegram upstream connections fail closed instead of leaving
through Entry.

Endpoint HAProxy accepts the dedicated ShadowTLS SNI only from configured Entry
source addresses. The Endpoint-side SOCKS inbound is loopback-only and uses
Endpoint's direct internet egress. This path is independent from the general
Entry-to-Endpoint Xray chain.

## Public Names

Use separate names for the address Telegram connects to and the FakeTLS
fronting site. Use `443` as the public profile port when alternate provider
ports are filtered:

- `proto.example.com`: DNS-only A/AAAA record for Entry.
- `yandex.ru`: real HTTPS site used as the FakeTLS SNI and MTG
  domain-fronting fallback.

A normal Cloudflare proxied record cannot carry arbitrary MTProto TCP without
Cloudflare Spectrum. Keep the proxy address DNS-only. Both names are routed to
MTG on Entry so a normal TLS probe of the proxy name does not expose another
Tracegate transport. Use a fronting-site certificate whose SANs cover the
proxy name. Serving a full HTTP decoy for the proxy hostname also requires the
fronting site to accept that hostname.

FakeTLS authenticates ClientHello timestamps. Keep Entry system time
synchronized; Tracegate defaults MTG's tolerance window to five minutes so a
short NTP outage does not immediately disconnect every Telegram client. When a
provider blocks NTP/UDP 123 but exposes an accurate virtual RTC, the opt-in
`deploy/systemd/tracegate-clock-sync-from-rtc.timer` can keep the host clock
aligned.

## Helm Values

```yaml
gateway:
  images:
    mtproto:
      repository: ghcr.io/your-org/tracegate
      digest: sha256:REPLACE_WITH_APP_IMAGE_DIGEST

mtproto:
  enabled: true
  runtime: mtg
  domain: proto.example.com
  tlsDomain: yandex.ru
  publicPort: 443
  egress:
    mode: socks5-only
    socksPort: 11084
    domainFrontingHost: yandex.ru
    domainFrontingPort: 443
    shadowtls:
      enabled: true
      serverName: splitter.wb.ru
      endpointHost: 198.51.100.20
      endpointPort: 443
      serverListenPort: 14444
      endpointSocksPort: 11085
      allowedSources:
        - 203.0.113.10
  fallback:
    enabled: false
  route:
    mode: entry-local-endpoint-egress
```

The raw 16-byte MTProto secret remains in the external private profile Secret.
Tracegate derives the FakeTLS client secret at runtime and the bot issues the
resulting Telegram link through the Entry agent.

The Tracegate application image includes the pinned MTG binary. Use that GHCR
image for the MTG container so production nodes do not need Docker Hub access
during rollout.

## Verification

Before promotion:

1. Render and lint Helm with the private overlay.
2. Run `mtg doctor` from the Entry pod.
3. Confirm MTG can generate a Telegram auth key through the Entry ShadowTLS
   client and Endpoint SOCKS inbound.
4. Confirm Entry HAProxy routes only the configured FakeTLS SNI to MTG.
5. Confirm Endpoint HAProxy routes the egress ShadowTLS SNI only for the Entry
   source allowlist.
6. Generate a Telegram auth key through the public host and port using the
   current bot-issued shared profile.

No MTProto configuration can guarantee permanent availability. Telegram client
JA3/JA4 fingerprints and destination IPs can be blocked before traffic reaches
the server. Keep replacement Entry IPs and fronting names operationally
rotatable.
