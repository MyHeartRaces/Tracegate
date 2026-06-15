# Tracegate k3s Chart

`deploy/k3s/tracegate` is the public Helm chart for Tracegate. It is suitable
for local rendering, review and validation with placeholder inputs. It is not a
complete production deployment repository.

## Public Scope

This directory may contain:

- generic chart templates;
- safe default values;
- placeholder production-shaped examples;
- validation code that rejects unsafe overlays;
- public notes about required external resources.

This directory must not contain:

- live hostnames, addresses, node inventory or provider metadata;
- exact public endpoint layout;
- rendered manifests from a real environment;
- decrypted Secrets or plaintext disk encryption keys;
- decoy content;
- generated client artifacts;
- live deployment automation.

The shell wrappers in this directory are decoys that fail closed. Production promotion scripts live with the operator material.

## Chart Validation

For public review, render the chart with placeholder values:

```bash
helm lint ./deploy/k3s/tracegate
helm template tracegate ./deploy/k3s/tracegate
```

Strict checks and cluster preflight are designed to run from the operator
environment with private overlays. They validate shape and prerequisites without
printing secret material.
The operator overlay supplies the actual deployment-specific values; public
examples keep placeholders.

```bash
python3 deploy/k3s/prod-overlay-check.py --strict \
  --chart-values deploy/k3s/tracegate/values.yaml \
  --values deploy/k3s/values-prod.yaml
```

## Required External Inputs

Real deployments must provide these inputs outside the public repository:

- control-plane secrets and database credentials;
- private profile material for gateway roles;
- a registry-pushed NaiveProxy Caddy image built from
  `deploy/images/naiveproxy-caddy/Dockerfile` and pinned by digest;
- TLS material and decoy content for any externally exposed surfaces;
- node labels, annotations and host policy;
- production image pins;
- encrypted Entry and Endpoint runtime storage. V4 placement and fronting details
  are operator-managed and must stay outside public documentation.

Entry traffic shaping and chain-client limits are enabled in public values as
guardrails. The real Entry network interface must be set in the operator
overlay.

The optional four-address Entry contract is configured under
`architecture.entryIngress`: one service-facing IPv4 address and exactly three
client shard IPv4 addresses. HAProxy binds only shard addresses. Because UDP
runtimes may bind wildcard sockets, operators must render and persist the
required host policy with `deploy/k3s/entry-ingress-firewall.py`.

New four-address deployments should enable
`architecture.entryIngress.exclusiveSniPairs`. The control plane then leases a
unique active `(Entry shard, SNI)` pair to each V1 Chain Reality revision.
Configure 12 to 15 pool domains and exactly one
`gateway.realityMultiInboundGroups` row per domain. Three active shards and 15
domains provide 45 active revision slots, including overlap revisions.

The alternative one-address contract is configured under
`architecture.universalEntry`. It exposes one `V5-Universal-Entry` profile via
a Cloudflare-proxied gRPC/TLS/H2 hostname and routes it through a shared
Entry-to-Endpoint backhaul pool: connect-level VLESS/REALITY/XHTTP SNI shards
with Hysteria2/Salamander fallback. It disables direct Entry user egress and
forbids four-address sharding in the same deployment. Start from
`values-universal-entry.example.yaml`, then render and persist its mandatory
Cloudflare-only origin policy with
`deploy/k3s/universal-entry-origin-firewall.py`.

Legacy three-node deployments retain the encrypted-runtime guard documented in
[docs/node-encryption-runbook.md](../../docs/node-encryption-runbook.md).
Future `entry-endpoint` deployments disable the host-level LUKS/dm-crypt
marker and node-annotation contract; transport encryption and external Secret
handling remain unchanged.

V4 fronting, port ownership and client import details belong in the private
operator runbook, not in this public chart README.

## Operational Notes

- Keep user and connection mutations on the API or narrow reload hooks.
- Keep private profile material in external Secrets.
- Production decoy sites must stay outside the chart; the chart does not ship a built-in decoy page.
- Keep bot copy and decoy surfaces outside the public chart.
- Keep generated runtime state out of Git.
- Keep rollout and preflight guards enabled in operator gates.
- Keep observability endpoints and alert routing in operator-managed values.
- Keep public examples generic enough that they cannot identify a live
  deployment.
