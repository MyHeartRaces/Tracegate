# MTProto Entry With Endpoint Egress

Tracegate supports a production MTProto layout where the public proxy binary
runs on Entry while every outbound Telegram and domain-fronting connection is
forced through Endpoint.

## Architecture

```text
Telegram client
  -> Entry tcp/443 HAProxy SNI demux
  -> Entry MTG on loopback
  -> dedicated loopback SOCKS5 inbound
  -> authenticated Entry-to-Endpoint Xray REALITY tunnel
  -> Endpoint internet egress
```

The MTG proxy receives PROXY protocol v2 from HAProxy and has exactly one
configured network proxy. An empty or direct network path is not included.
If the local SOCKS5 tunnel is unavailable, Telegram upstream connections fail
closed instead of leaving through Entry.

The dedicated MTProto SOCKS inbound has its own Xray routing rule before all
regional direct-routing rules. It can only use the encrypted Endpoint tunnel.

## Public Names

Use separate names for the address Telegram connects to and the FakeTLS
fronting site. Prefer the dedicated `8443` listener as the primary profile
port so Telegram ClientHello changes cannot be misrouted by the shared `443`
SNI demultiplexer; generated profiles also keep `443` as a fallback:

- `proto.example.com`: DNS-only A/AAAA record for Entry.
- `example.com`: real HTTPS site used as the FakeTLS SNI and MTG
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
  tlsDomain: example.com
  publicPort: 443
  egress:
    mode: socks5-only
    socksPort: 11084
    domainFrontingHost: example.com
    domainFrontingPort: 443
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
3. Confirm the dedicated SOCKS inbound reports Endpoint's egress address.
4. Confirm Entry HAProxy routes only the configured FakeTLS SNI to MTG.
5. Confirm the bot-issued link contains the proxy hostname and the configured
   FakeTLS domain.

No MTProto configuration can guarantee permanent availability. Telegram client
JA3/JA4 fingerprints and destination IPs can be blocked before traffic reaches
the server. Keep replacement Entry IPs and fronting names operationally
rotatable.
