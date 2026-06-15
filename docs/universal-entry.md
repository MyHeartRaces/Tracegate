# Universal Entry

`V5-Universal-Entry` is the one-address client ingress for new two-node
deployments. It replaces a user-visible set of Chain transports with one
cross-platform profile:

```text
Karing/sing-box client
  -> Cloudflare-proxied hostname, TCP/443, real TLS, HTTP/2, VLESS gRPC
  -> Entry origin
  -> one encrypted fail-closed VLESS/REALITY/XHTTP bridge
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
- an operator-managed origin firewall that accepts `443` only from current
  Cloudflare IPv4 source ranges;
- `interconnect.emergencyXrayChain.enabled=true` as the compatibility name for
  the single encrypted Entry-to-Endpoint bridge;
- fail-closed Endpoint-only egress for all Entry user-traffic inbounds;
- no four-IP Entry sharding and no ingress hostname rotation in the same mode.

The control plane must expose only the `universal` profile in a dedicated
Universal Entry deployment. Set the active Entry node `proxy_fqdn` to the
proxied hostname so generated profiles never publish the origin address.

Render the mandatory host policy with:

```bash
python3 deploy/k3s/universal-entry-origin-firewall.py \
  --chart-values deploy/k3s/tracegate/values.yaml \
  --values /path/to/private-values.yaml \
  --output /etc/nftables.d/tracegate-universal-entry-origin.nft
```

Refresh `architecture.universalEntry.originFirewall.allowedSourceCidrs` from
Cloudflare's published list before every promotion.

## Why This Transport

The reviewed filtering observations describe both payload-volume freezes on
some suspicious destination networks and penalties for bursts of similar TLS
ClientHello messages. A direct WireGuard ingress does not resemble ordinary
HTTPS and makes the single origin address the obvious block target. Merely
changing REALITY fingerprints, fragmenting ClientHello or changing TTL does not
address destination IP/ASN classification.

Standard Cloudflare reverse proxy supports proxied gRPC endpoints when the
origin listens on `443`, uses TLS and HTTP/2, and advertises HTTP/2 through ALPN.
Cloudflare Tunnel public hostnames do not currently support gRPC, so Universal
Entry uses the normal proxied DNS record, not Cloudflare Tunnel. WARP remains an
optional separately managed emergency access path; it is not the primary
Tracegate client transport or Endpoint egress path.

## Operations

- Enable gRPC in the Cloudflare zone and use Full or Full (strict) origin TLS.
- Keep the proxied hostname on the Entry node TLS certificate.
- Apply the generated origin firewall before publishing the profile.
- Probe sustained authenticated payload, not only TLS handshake success.
- Alert on reconnect rate, gRPC duration, bridge availability and unexpected
  direct Entry egress.
- Treat Cloudflare edge restarts and provider policy changes as normal failure
  modes; clients must use jittered bounded reconnects.

## References

- [Cloudflare gRPC connections](https://developers.cloudflare.com/network/grpc-connections/)
- [Cloudflare IPv4 ranges](https://www.cloudflare.com/ips-v4)
- [net4people issue 490](https://github.com/net4people/bbs/issues/490)
- [Habr: ClientHello and connection concurrency observations](https://habr.com/ru/articles/1044396/)
- [Habr: HTTP/2 multiplexing observation](https://habr.com/ru/articles/1045684/)
- [Habr: Siberian blocking observations](https://habr.com/ru/articles/1010336/)
