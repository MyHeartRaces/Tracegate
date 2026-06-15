# Endpoint ingress assignment

New production uses three Endpoint client-ingress shard IPs and one
service/egress IP. Direct VLESS Reality revisions receive a deterministic
personal hostname alias and an exclusive active `(Endpoint shard IP, SNI)`
lease. Active revisions never change underneath a connected client.

The service/egress IP is not part of ingress rotation and must reject client
ports. Endpoint egress rotation is forbidden.

This is revision-level assignment, not per-packet or per-session rotation.
Rapid rotation creates reconnect loops and unstable DPI behavior.

The older `architecture.entryIngress` allocator remains compatibility-only and
is disabled in the new-production overlays.
