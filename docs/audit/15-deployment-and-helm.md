# Deployment & Helm Chart

The k3s Helm chart (`deploy/k3s/tracegate`), its safety guards, the runtime
seeding flow, and the validation tooling. The chart is for rendering/validation/
review with placeholder values; real environments use operator-managed private
overlays.

## 1. Chart layout

```
deploy/k3s/tracegate/
  Chart.yaml, values.yaml            # generic chart + placeholder values
  templates/
    namespace.yaml, _helpers.tpl, NOTES.txt
    secrets.yaml                     # external-Secret wiring + ~40 fail-closed guards
    configmaps.yaml                  # runtime-contract + per-role haproxy/nginx/xray/hysteria
    gateways.yaml                    # the gateway Deployment(s): init + sidecar containers
    control-plane.yaml               # API/dispatcher/bot
    observability.yaml               # Prometheus/Grafana/exporters
    transit-router.yaml              # legacy role (guarded off in new prod)
    gateways.yaml (naiveproxy)       # legacy, excluded in entry-endpoint mode
  files/russia-mobile-internet-whitelist.txt
```

## 2. Values contract (highlights)

- `architecture.mode: entry-endpoint`, `architecture.podRuntimeOnly: true`,
  `architecture.deploymentPhase`.
- `architecture.endpointIngress` (service IP + shard IPs), `entryIngress`,
  `universalEntry` (Cloudflare origin firewall, `multiplexSingleTls`,
  `maxParallelHandshakes: 1`).
- `gateway.roles.{entry,transit}` (ports, reality dest/serverNames/shortIds, tls).
- `network.egressIsolation` (the egress contract; see
  [13-network-boundary-and-egress.md](13-network-boundary-and-egress.md)).
- `shadowsocks2022` (+ `shadowtls`), `wireguard` (+ `wstunnel`), `mtproto`,
  `interconnect.endpointBackhaul`, `privateProfiles` (external Secret keys).
- `gateway.seccompProfileType: RuntimeDefault` (added by F7).
- `gateway.nodeEncryption` (optional encrypted-runtime marker validation).

## 3. Runtime seeding (init containers)

`gateways.yaml` runs init containers in order:

1. `validate-private-profiles` (preflight) — fails closed if a required private
   key is missing or still a placeholder (`forbidPlaceholders`).
2. `validate-node-encryption` (optional) — checks the encrypted-runtime marker /
   dm-crypt source when `nodeEncryption.required`.
3. `seed-runtime` — copies base xray/hysteria/haproxy/nginx configs into the state
   volume and `sed`-replaces `REPLACE_*` placeholders with values read from the
   mounted private-profile Secret (Reality key, SS-2022 password, Salamander
   password, Hysteria stats secret, MTProto secret, VLESS encryption). The MTProto
   secret is validated to 16 bytes / 32 hex. Generates the Telemt/mtg config.

Then the sidecar containers start (agent, xray, hysteria, shadowtls-v3, wireguard,
wstunnel, telemt, haproxy, nginx) — each with a capability-scoped
`securityContext` and the pod-level `seccompProfile`.

## 4. Fail-closed render guards (`secrets.yaml`)

The chart encodes ~40 invariants as `{{ fail ... }}` gates, e.g.:
- ShadowTLS `serverNameTransit` must not reuse an Endpoint direct SNI (collision);
  chain-bridge SNIs must not collide either.
- `architecture.universalEntry` requires `entry-endpoint` mode, Cloudflare
  provider, `grpc-tls-h2` transport, origin firewall required + deny-direct +
  allowed CIDRs, `multiplexSingleTls`, `maxParallelHandshakes: 1`,
  multi-transport backhaul, fail-closed.
- Rollout must be a safe single-hostNetwork shape (`maxUnavailable=0/maxSurge>0` or
  `1/0`); `progressDeadlineSeconds >= 300`.
- `shadowsocks2022.shadowtls` must stay enabled + v3 when SS-2022 is on.
- vless-encryption realitySni must not reuse a demux SNI.

These turn many classes of misconfiguration into a render-time failure rather than
a silent runtime weakness — a strong defensive pattern.

## 5. Validation tooling (`deploy/k3s/*.py`, `*.sh`)

| Tool | Purpose |
|------|---------|
| `cluster-preflight-check.py` | cluster-level readiness |
| `prod-overlay-check.py` | strict production overlay shape (pod-only, no host data-plane) |
| `pod-runtime-readiness.py` | pod runtime readiness |
| `new-production-values-adapter.py` | adapts the private values file into chart values |
| `endpoint-ingress-firewall.py`, `endpoint-egress-firewall.py`, `entry-ingress-firewall.py`, `universal-entry-origin-firewall.py`, `universal-entry-endpoint-backhaul-firewall.py` | render host nftables |
| `deploy-prod.sh`, `deploy-ready-check.sh` | render + gate the rollout |

The private `deploy-ready/tracegate-3-new-prod/deploy.sh` orchestrates phases
(`endpoint-first` / `entry-staged` / `full`) and is **fail-closed** on firewall
state (and, after F9, requires `TRACEGATE_PUBLIC_REPO`).

## 6. Rollout safety

`replicas: 1` per gateway with a single-hostNetwork-safe RollingUpdate; a PDB
(`minAvailable: 1`); a `progressDeadlineSeconds >= 300` so a stalled hostNetwork
upgrade fails slow rather than dropping the only gateway pod. The runtime contract
records the rollout invariants so preflight can verify an upgrade cannot drop the
sole Entry/Endpoint pod.

## 7. Verification

`helm template` (helm v4.x) renders the chart in `tests/test_k3s_chart.py`; the
audit's chart changes (F7 seccomp, F8 SNI) were validated through it. Run locally:

```bash
helm template tracegate deploy/k3s/tracegate -f deploy/k3s/values-endpoint-first.example.yaml >/dev/null
python3 deploy/k3s/endpoint-ingress-firewall.py --chart-values deploy/k3s/tracegate/values.yaml --values deploy/k3s/values-endpoint-first.example.yaml
pytest tests/test_k3s_chart.py -q
```
