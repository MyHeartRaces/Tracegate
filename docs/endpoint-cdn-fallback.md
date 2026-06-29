# Endpoint Cloudflare fallback

Tracegate can reuse the normal Cloudflare-proxied Endpoint hostname as a
backup gRPC/TLS/HTTP/2 lane. This lane is intended for Tracegate-Router or a
system TUN client when the provider blocks the direct Entry or native
MTProxy address. It does not make a raw `tg://proxy` connection compatible
with Cloudflare's HTTP proxy.

## DNS and origin contract

The proxied `A` record must target exactly one active Endpoint shard address.
It must never target the Endpoint service/egress address: that address is
deliberately excluded from public listeners. Cloudflare `521` on the public
hostname normally means that the selected origin is refusing or cannot
receive the Cloudflare connection.

The selected shard must:

- terminate a certificate covering the Endpoint public hostname;
- accept the gRPC path used by the `backup-grpc` profile;
- allow TCP/443 from the published Cloudflare IPv4 source ranges;
- reject the same hostname when the source is not a Cloudflare edge;
- keep long-lived gRPC read and send timeouts.

Set `architecture.endpointIngress.cdnFallback.enabled=true` only after the
DNS target, certificate and firewall contract are ready. The Helm chart and
strict production overlay check fail closed when the public hostname differs
from the Endpoint TLS/default/service-facing hostname, the origin shard is
not active, the source ranges are absent, or `backup-grpc` is disabled.

## Client policy

Use the generated `backup-grpc` profile from Tracegate-Router TUN mode. Keep
one parallel TLS handshake, exponential reconnect backoff and jitter. If an
operator explicitly nests MTProxy inside the TUN, the proxied gRPC path is the
outer carrier; this remains an emergency override rather than the default.

This fallback changes the network path seen by the access provider, but the
origin is still the existing Endpoint server and ASN. It protects against an
allowlist that admits Cloudflare while blocking the direct address; it is not
independent server, provider or ASN redundancy. A second Endpoint in another
provider remains necessary for infrastructure-level failover.

Cloudflare publishes its current source ranges at
[Cloudflare IP ranges](https://www.cloudflare.com/ips/) and documents the
proxied HTTP/2 gRPC requirements in
[gRPC connections](https://developers.cloudflare.com/network/grpc-connections/).
