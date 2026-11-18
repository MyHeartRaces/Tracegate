# Ingress assignment

Tracegate can give each Direct VLESS Reality revision a deterministic
personal hostname alias and an exclusive active `(ingress address, SNI)`
lease from operator-configured pools (`ENDPOINT_INGRESS_*`; Chain has the
equivalent `ENTRY_INGRESS_*` settings). The pools, addresses and names are
private deployment state.

Assignment is per revision. An active revision never changes underneath a
connected client; a re-issue may move the connection to a new pair, and the
previous revision stays served. Egress addresses are never part of ingress
assignment.

This is revision-level assignment, not per-packet or per-session rotation.
Rapid rotation creates reconnect loops and unstable DPI behaviour.

The older `architecture.entryIngress` allocator remains compatibility-only.
