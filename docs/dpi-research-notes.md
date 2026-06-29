# DPI Research Notes

These notes record the design consequences of the external material reviewed
for the two-node migration. They are not claims that any bypass remains
permanently effective.

## Applied

- Health checks must transfer sustained authenticated payload, because some
  filtering modes allow a handshake and then freeze a TCP flow.
- Limit simultaneous new TLS sessions per public name; reuse healthy
  connections and add jittered backoff after failures.
- Keep several independent ingress IP/provider options. Domain aliases on one
  IP do not address IP- or ASN-based filtering.
- When only one Entry IP is available, prefer one proxied TLS/H2 ingress and
  multiplex application streams over one connection instead of opening a
  burst of similar ClientHello sessions to the origin.
- Restrict a proxied origin to the provider's current source ranges. A proxied
  DNS record without an origin firewall still leaves a directly reachable
  blocking and probing target.
- Keep real TLS-compatible decoys and TLS 1.2 compatibility as optional
  fallbacks, not as proof of indistinguishability.
- Use DNS-tunnel concepts such as health scoring, MTU discovery and generation
  drain only for an emergency low-bandwidth transport.
- Keep packet manipulation scoped to a dedicated transport. Host-wide NFQUEUE
  interception is not a production default.

## Rejected As Defaults

- 3X-UI as an operational dependency.
- WARP as a mandatory egress path.
- DNS tunneling as the primary user transport.
- aggressive ClientHello fragmentation without measured carrier-specific
  evidence.
- rotation on every connection attempt.
- claims that one configuration will always work.
- WARP or Cloudflare Tunnel as the mandatory Universal Entry client path.

## Sources

- [MasterDnsVPN README](https://github.com/masterking32/MasterDnsVPN/blob/main/README.MD)
- [net4people issue 490](https://github.com/net4people/bbs/issues/490)
- [Habr: TLS/DPI observations](https://habr.com/ru/articles/1045684/)
- [Habr: ClientHello and connection concurrency observations](https://habr.com/ru/articles/1044396/)
- [Habr: Siberian blocking observations](https://habr.com/ru/articles/1010336/)
- [Cloudflare gRPC connections](https://developers.cloudflare.com/network/grpc-connections/)
- [Cloudflare IPv4 ranges](https://www.cloudflare.com/ips-v4)
- [Operator-provided Pastebin notes](https://pastebin.com/raw/9gLsyeLp)

Telegram-specific consequences and the whitelist-mode decision tree are kept
in [telegram-resilience.md](telegram-resilience.md).
