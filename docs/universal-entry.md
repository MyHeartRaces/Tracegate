# Universal Entry

`V5-Universal-Entry` is added in the full phase after the four-IP Endpoint has
passed direct-profile validation. It replaces a user-visible set of Chain
transports with one cross-platform profile:

```text
Karing/sing-box client
  -> Cloudflare-proxied hostname, TCP/443, real TLS, HTTP/2, VLESS gRPC
  -> Entry origin
  -> shared fail-closed backhaul pool
       -> primary: Shadowsocks-2022 over ShadowTLS v3 (TCP)
       -> fallback: Hysteria2/Gecko (UDP/QUIC)
  -> Endpoint egress
```

The design does not claim permanent blocking resistance. A single hostname,
provider or IP can still be blocked. The purpose of the proxied ingress is to
avoid exposing the one Entry origin address as the normal client destination
and to keep client traffic on one long-lived HTTP/2 TLS connection.

## Required Contract

Enable `architecture.universalEntry` only with `architecture.mode=entry-endpoint`.
The chart then requires:

- Cloudflare as the proxied ingress provider;
- gRPC over real TLS/HTTP/2 on port `443`;
- one TLS connection per client transport and no parallel handshake burst;
- an operator-managed origin policy: host nftables passes shared `443` to
  HAProxy, while HAProxy accepts Universal Entry only from current Cloudflare
  IPv4 source ranges and keeps only explicitly declared direct exceptions:
  raw no-SNI MTProto and, in DNS-only deployments, the controlled TLS adapter
  SNI;
- `interconnect.endpointBackhaul.enabled=true` with Shadowsocks-2022 over
  ShadowTLS v3 as primary and Hysteria2/Gecko as the independent fallback;
- one authenticated TCP primary through a local ShadowTLS client and the
  Endpoint SS2022 inbound;
- `roundRobin` connection selection, one dial at a time and authenticated
  payload probes;
- one shared Hysteria2 client process on Entry, authenticated to the existing
  Endpoint Hysteria2 listener with a private backhaul token;
- fail-closed Endpoint-only egress for all Entry user-traffic inbounds;
- no four-IP Entry sharding; the independent four-IP Endpoint remains active.

The full control plane exposes all seven Tracegate 3 profile keys. Set the
active Entry node `proxy_fqdn` to the proxied hostname so generated Entry Chain
profiles never publish the origin address.

Render the mandatory host policy with:

```bash
python3 deploy/k3s/universal-entry-origin-firewall.py \
  --chart-values deploy/k3s/tracegate/values.yaml \
  --values /path/to/private-values.yaml \
  --output /etc/nftables.d/tracegate-universal-entry-origin.nft

```

Refresh `architecture.universalEntry.originFirewall.allowedSourceCidrs` from
Cloudflare's published list before every promotion. In shared MTProto mode the
generated nftables file must not reject non-Cloudflare `443` packets directly,
because SNI/no-SNI demux happens in HAProxy. If the public Entry hostname is
DNS-only rather than proxied, set
`architecture.universalEntry.originFirewall.allowDirectTlsAdapterSni=true` and
keep all other SNI routes source-restricted.

## Why This Transport

The reviewed filtering observations describe both payload-volume freezes on
some suspicious destination networks and penalties for bursts of similar TLS
ClientHello messages. A direct WireGuard ingress does not resemble ordinary
HTTPS and makes the single origin address the obvious block target. Merely
changing REALITY fingerprints, fragmenting ClientHello or changing TTL does not
address destination IP/ASN classification.

ShadowTLS v3 is used for the backhaul TCP primary because it is independent of
the client-facing Cloudflare gRPC path and does not depend on Xray transport
framing. XHTTP is removed and its legacy values are rejected by Helm and the
production overlay checker.

Hysteria2/Gecko is deliberately a different UDP/QUIC failure domain. It
uses conservative BBR, keepalive, path MTU discovery and private authentication.
Gecko fragments and pads packets but does not make the flow ordinary HTTP/3;
it remains a fallback, not a permanent-reachability claim.
Gecko clients require Hysteria 2.9.2+ or sing-box 1.14.0+; older issued
Salamander profiles are not wire-compatible and must be reissued.

Standard Cloudflare reverse proxy supports proxied gRPC endpoints when the
origin listens on `443`, uses TLS and HTTP/2, and advertises HTTP/2 through ALPN.
Cloudflare Tunnel public hostnames do not currently support gRPC, so Universal
Entry uses the normal proxied DNS record, not Cloudflare Tunnel. WARP remains an
optional separately managed emergency access path; it is not the primary
Tracegate client transport or Endpoint egress path.

## Operations

- Enable gRPC in the Cloudflare zone and use Full or Full (strict) origin TLS.
- Keep the proxied hostname on the Entry node TLS certificate.
- Apply the generated origin firewall and verify HAProxy contains the
  Cloudflare source ACL before publishing the profile.
- Probe sustained authenticated payload, not only TLS handshake success.
- Alert on reconnect rate, gRPC duration, ShadowTLS payload health,
  Hysteria2 fallback use and unexpected direct Entry egress.
- Keep Endpoint Hysteria2 public for direct clients; private backhaul auth and
  a separate backhaul token distinguish Entry backhaul use from direct clients.
- Do not enable host-wide NFQUEUE, speculative TTL rewriting or unconditional
  ClientHello fragmentation. Promote packet changes only after carrier-specific
  sustained-payload tests.
- Treat Cloudflare edge restarts and provider policy changes as normal failure
  modes; clients must use jittered bounded reconnects.

## References

- [Cloudflare gRPC connections](https://developers.cloudflare.com/network/grpc-connections/)
- [Cloudflare IPv4 ranges](https://www.cloudflare.com/ips-v4)
- [Xray routing and balancers](https://xtls.github.io/en/config/routing.html)
- [Hysteria2 full client configuration](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
- [Hysteria2 full server configuration](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)
- [net4people issue 490](https://github.com/net4people/bbs/issues/490)
- [Habr: ClientHello and connection concurrency observations](https://habr.com/ru/articles/1044396/)
- [Habr: HTTP/2 multiplexing observation](https://habr.com/ru/articles/1045684/)
- [Habr: Siberian blocking observations](https://habr.com/ru/articles/1010336/)
