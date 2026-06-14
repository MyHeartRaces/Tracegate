# Ingress Rotation

Tracegate can assign a different ingress hostname when a new connection
revision is issued.

## Behavior

`architecture.ingressRotation.strategy: revision-sticky` selects a hostname
deterministically from the configured Entry or Endpoint ingress pool. The
selected hostname is stored in the revision's effective config, so an active
revision never changes underneath a connected client. Issuing another revision
can select another pool member while the previous revision remains usable.

This is deliberately not per-packet or per-TCP-session rotation. Fast rotation
creates reconnect loops, makes failures difficult to attribute and can trigger
concurrency-based DPI limits.

## Requirements

- Configure hostnames only in the private operator overlay.
- Keep arbitrary TCP proxy records DNS-only.
- Each pool hostname must terminate the same authenticated profile surface.
- Use at least two distinct ingress public IPs.
- Prefer independent providers and ASNs; aliases on one IP are only
  domain/SNI diversification.
- Keep Endpoint egress stable. `rotateEndpointEgress` is forbidden.
- Use at least a five-minute revision overlap and drain old revisions before
  removing DNS.

The bot already delivers revision effective configs, so newly issued client
profiles receive the selected hostname without a separate export path.
Shared MTProto grants are not rotated by this mechanism; they require a
separate operator-managed public profile pool.
