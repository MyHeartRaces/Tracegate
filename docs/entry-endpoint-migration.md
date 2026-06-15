# Entry and Endpoint Migration

New Tracegate production installations use two nodes:

```text
client -> Entry ingress -> encrypted, fail-closed backhaul -> Endpoint egress
```

The historical internal name `gateway.roles.transit` remains as a compatibility
alias for the gateway workload placed on Endpoint. It does not justify a third
Transit node.

## Required Shape

- `architecture.mode: entry-endpoint`
- Entry is the public rotating ingress surface.
- Endpoint owns stable outbound internet egress.
- `gateway.roles.transit.canonicalServer: endpoint`
- `transitRouter.enabled: false`
- every legacy `interconnect.entryTransit` switch is disabled
- Universal Entry uses `interconnect.endpointBackhaul`: shared XHTTP/REALITY
  connect/SNI shards with a Hysteria2/Salamander fallback
- MTProto clients enter through shared Entry TCP/443; Telemt runs only on
  Endpoint and uses `entry-endpoint-tunnel`
- no Kubernetes node has `tracegate.io/role=transit` or
  `tracegate.io/role=chain-transit`

Start from the private production overlay and apply the shape from
`deploy/k3s/values-entry-endpoint.example.yaml`. Do not put real coordinates in
the public example.

## Promotion Gate

```bash
python3 deploy/k3s/prod-overlay-check.py --strict \
  --chart-values deploy/k3s/tracegate/values.yaml \
  --values /path/to/private-values.yaml

KUBECONFIG=/path/to/private-kubeconfig \
python3 deploy/k3s/cluster-preflight-check.py \
  --chart-values deploy/k3s/tracegate/values.yaml \
  --values /path/to/private-values.yaml
```

The overlay check rejects legacy Transit paths. Cluster preflight rejects
legacy Transit node labels, even when no workload currently selects them.

## Migration Order

1. Provision ordinary protected runtime paths and host policy on new Entry and
   Endpoint; keep every `gateway.nodeEncryption` guard disabled.
2. Deploy with ingress rotation disabled.
3. Validate authenticated, sustained payload transfer through every XHTTP shard
   and through the Hysteria2 fallback. A successful TCP or QUIC handshake is
   not a release gate.
4. Validate Entry failure cannot cause client traffic to leave directly from
   Entry.
5. Move a canary DNS name, wait through TTL, then issue new revisions.
6. Keep old revisions alive during the overlap window.
7. Move the remaining DNS names and retire legacy Transit labels and nodes.
8. Enable revision-sticky ingress rotation only after every pool member passes
   the same payload probes.

Keep the old control-plane/decoy name available during the overlap. Use a
separate DNS-only ingress zone for the new gateway pool so domain reputation
and rollback are not coupled to one name.
