# Tracegate 2.1 k3s deployment

Tracegate 2.1 is deployed as one Helm chart from `deploy/k3s/tracegate`.

This chart is the production target for the 2.1 runtime. The old plain-host
`deploy/systemd` kit remains in the repository only as the Tracegate 2 migration
surface until the Helm rollout is complete.

## Rules

- Keep user and connection changes out of pod-template checksums.
- Keep rollout guard values visible in the rendered runtime-contract ConfigMap
  so private validation and observability can detect unsafe overlays.
- Keep private Mieru, zapret2, ShadowTLS, WireGuard and MTProto profiles in a
  Kubernetes Secret created outside Git.
- Keep control-plane auth and database credentials in external Kubernetes
  Secrets for production. The chart defaults reference
  `tracegate-control-plane-auth` and `tracegate-database-url`; inline auth
  values and embedded PostgreSQL are accepted only when the required secret
  values are explicitly provided.
- Keep the Telegram bot welcome/warning copy in an external Kubernetes Secret.
  The chart default references `tracegate-bot-welcome`; the repository contains
  only placeholder settings, not the production message.
- Keep the Telegram bot `/guide` copy in an external Kubernetes Secret. The
  chart default references `tracegate-bot-guide`; the repository does not ship a
  bundled guide body.
- Pin production images by version tag or OCI digest. Every image block supports
  `digest: sha256:...`, which renders as `repository@sha256:...` and overrides
  `tag`.
- Keep generated runtime desired state under `/var/lib/tracegate/private`; the
  `/etc/tracegate/private` Secret mount is read-only static material.
- Keep ingress and egress public IPs separated. Production overlays must set
  `network.egressIsolation.ingressPublicIPs` and
  `network.egressIsolation.egressPublicIPs` to disjoint real public IPs, keep
  `forbidIngressIpAsEgress=true`, and annotate gateway nodes with the configured
  `tracegate.io/ingress-public-ip` / `tracegate.io/egress-public-ip` keys before
  cluster preflight. The actual SNAT/firewall rules live in private host policy
  under `/etc/tracegate/private/egress-isolation`.
- Keep default client delivery VPN/TUN-first. Local SOCKS/mixed listener exports
  are advanced-only; generated local proxy material must never enable LAN
  sharing or anonymous localhost.
- Keep `privateProfiles.defaultMode=256` (`0400`) unless a specific sidecar
  image is intentionally run as a non-root user and the Secret ACL model is
  changed with it.
- Keep `gateway.strategy=RollingUpdate` with `maxUnavailable=0`. On a single
  hostNetwork node this may stall an unsafe upgrade instead of deleting the
  current gateway pod first, which is the intended failure mode for production.
  `gateway.strategy=Recreate` is a lab-only maintenance opt-in. Keep
  `maxSurge` non-zero, `progressDeadlineSeconds>=300`, probes enabled, and the
  gateway PDB at `minAvailable=1`.
- Do not use host-wide NFQUEUE or broad userspace interception for all traffic.
- Keep Entry-to-Transit chaining outside Xray. In the k3s chart the V2/V4/V6
  chain bridge is owned by `link-crypto`, encrypted by Mieru, and wrapped in a
  required WSS carrier on `tcp/443`; Xray backhaul is rejected at render time.
  Direct backhaul fallback is also rejected; the
  `interconnect.entryTransit.fallback` value must stay `none`.
  `interconnect.entryTransit.primary`, `chainBridgeOwner`, `remotePort` and
  `outerCarrier.mode` must stay `mieru`, `link-crypto`, `443` and `wss`.
  The bridge WSS `serverName` must be a dedicated hostname separate from the
  Transit user-facing TLS name and the MTProto domain. The Transit TLS Secret
  must cover that bridge hostname, either as a SAN on the existing certificate
  or through an operator-provided equivalent TLS termination layout. When the
  carrier is enabled, the private Mieru client profile must target the
  `outerCarrier` loopback listener on Entry, not the Transit public address.
- Keep role topology explicit. At least one gateway role must be enabled. A
  single-role Transit deployment must set `gateway.roles.entry.enabled=false`
  and `interconnect.entryTransit.enabled=false`; the Entry-Transit bridge is
  accepted only when both Entry and Transit roles are rendered. V7 WireGuard,
  MTProto and router-transit require Transit. Router-entry requires Entry.
  Enabling the V5/V6 Shadowsocks-2022 + ShadowTLS surface requires both roles
  plus the Entry-Transit bridge, because V6 is a chained production profile.
  When `gateway.hostNetwork=true` and both roles are enabled, Entry and Transit
  must use non-empty, distinct `nodeSelector` values so Kubernetes cannot place
  two `:443` gateway pods on the same node.
- Preserve the existing decoy files and mount them read-only into gateway pods.
- Keep decoy and public transport paths clean and absolute. The chart rejects
  relative `decoy.hostPath`, unsafe `decoy.mountPath`, and malformed VLESS
  WebSocket/gRPC paths before rendering manifests.
- Prefer live API updates and narrow reload hooks over process restarts.
- Keep ShadowTLS V3 outer credentials static during user churn. V5/V6 private
  handoff rows must reference the role's private ShadowTLS config file and must
  keep `credentialScope=node-static`, `manageUsers=false` and
  `restartOnUserChange=false`; per-user lifecycle belongs to Shadowsocks-2022.
- Keep V7 peer churn in the private profile adapter. The generated V7
  handoff must declare `sync.strategy=wg-set`, `applyMode=live-peer-sync`,
  `removeStalePeers=true`, and must keep `restartWireGuard=false` plus
  `restartWSTunnel=false`. Server-side peer `allowedIps` must be host routes
  derived from the client's tunnel address, not client default-route values.
- Keep gateway probes local-only. `startup` / `liveness` for the agent use
  `/v1/live`, readiness uses `/v1/health`, and data-plane probes inspect local
  config files or the in-pod HAProxy listener only.
- Keep the gateway PodDisruptionBudget enabled for production role pods.
- Keep `gateway.privatePreflight.enabled=true` in production. The gateway
  initContainer validates the mounted private Secret before `xray`, `Mieru`,
  `ShadowTLS`, `WSTunnel` or MTProto helpers start, rejects placeholder
  material, refuses host-wide zapret2 / NFQUEUE settings, and rejects
  `wg-quick` lifecycle hooks, DNS rewrites, saved config, broad AllowedIPs
  routes, unsafe MTU values or long keepalive timers in the WireGuard config.
  It also verifies that Shadowsocks private files use a `2022-*` method with
  secret material, ShadowTLS files declare v3 with password material, Mieru
  files contain private credential material without anonymous/no-auth mode, and
  MTProto files contain exactly one raw 32-hex-character server secret. zapret2
  env files must stay scoped; broad target lists like `all`, `*` or `all-flows`
  are rejected unless the operator explicitly bypasses the guard for lab work.
  RESTLS lab files must contain private credentials without disabling TLS
  verification, and TUIC lab files must contain private credentials and keep
  0-RTT disabled.
  Mounted private files must not have world read/write/execute permission bits.
- Keep `privateProfiles.required=true` and
  `gateway.privatePreflight.forbidPlaceholders=true`. The chart rejects values
  that would let gateway pods start without mounted private material or with
  placeholder-filled private files.
- Keep `gateway.containerResources.zapret2` bounded. The default zapret2
  sidecar budget is intentionally small so scoped shaping cannot starve Entry
  or Transit data-plane containers. When zapret2 is enabled, the sidecar starts
  separate scoped profile processes for the role profile and, only when a
  bridge/router link is enabled, the Entry-Transit profile. On Transit with
  MTProto enabled it also starts the private `zapret/mtproto-extra.env`
  profile. That MTProto profile is isolated to the Transit pod and must not
  widen zapret2 scope for V1-V7 traffic. If any scoped zapret2 profile process
  exits, the sidecar terminates and Kubernetes restarts only that container;
  gateway data-plane containers keep running.
- Keep the default `profiles` and `linkCrypto` reload commands unless replacing
  them with an equivalent private runner. They call
  `tracegate-k3s-private-reload`, validate generated handoff JSON/ENV and write
  redacted markers under `/var/lib/tracegate/private/runtime` without restarting
  gateway sidecars. Mieru/link-crypto and profile-driven sidecars wait for the
  generated desired-state, generated env file and a matching marker that is not
  older than either file, so an upgrade or rotation with a missing/stale marker
  forces a narrow validation hook instead of starting private transports
  unchecked. The chart also passes the desired-state/env/marker paths to those
  sidecars through `TRACEGATE_PROFILE_*` and `TRACEGATE_LINK_CRYPTO_*`
  environment variables for private entrypoint adapters.

## Decoy Content

Production decoy sites must stay outside the chart and be mounted read-only into
gateway pods. Use exactly one of:

- `decoy.hostPath` for an existing node-local decoy tree, for example
  `/srv/tracegate/decoy`.
- `decoy.existingClaim` for a PVC managed outside this chart.
- `decoy.existingConfigMap` for a ConfigMap created outside this chart.

The chart does not ship a built-in decoy page and rejects inline `decoy.files`.
If no external source is set while gateway pods are enabled, rendering fails.

## Lab Profiles

`experimentalProfiles` is disabled by default. It reserves the V8/V9 lab surface
without making it part of the production client list:

- `V8-Mieru-TCP-Direct` / `V8-Mieru-RESTLS-Direct` are direct Transit
  obfuscation candidates backed only by external private profile files.
- `V9-TUICv5-QUIC-Direct` / `V9-TUICv5-QUIC-Chain` are TUIC v5 evaluation
  profiles. They must not replace V3/V4 Hysteria2 in the Tracegate 2.1
  production cut.

When a lab surface is enabled, the chart mounts only the required Secret keys
for that role and validates them with `tracegate-k3s-private-preflight` before
the lab sidecar starts. Nested V8/V9 switches are rejected unless
`experimentalProfiles.enabled=true` is set explicitly, and V8/V9 names must stay
out of `transportProfiles.clientNames`. The guard
`experimentalProfiles.tuicV5.productionReplacementAllowed=true` is rejected at
render time.

## Minimal render

```sh
helm template tracegate ./deploy/k3s/tracegate \
  --namespace tracegate \
  --create-namespace
```

For production, copy `values-prod.example.yaml` outside tracked Git as
`values-prod.yaml` or another ignored private values file.

## Deploy-ready check

Before promoting a Tracegate 2.1 chart build, run the repository release gate:

```sh
deploy/k3s/deploy-ready-check.sh
```

The script runs `ruff`, `pytest`, `helm lint`, default and production-example
`helm template`, `git diff --check` and `alembic heads`. Rendered manifests are
written to `${TRACEGATE_DEPLOY_READY_OUT:-/tmp/tracegate-deploy-ready}` so the
exact default/prod-example output can be inspected or archived. Override
`TRACEGATE_K3S_PROD_VALUES` to point at an ignored private values file when
validating the real production overlay.

For the final production gate, enable strict overlay validation:

```sh
TRACEGATE_STRICT_PROD=1 \
TRACEGATE_CLUSTER_PREFLIGHT=1 \
TRACEGATE_K3S_PROD_VALUES=/path/to/ignored/values-prod.yaml \
deploy/k3s/deploy-ready-check.sh
```

Strict mode runs `prod-overlay-check.py` and rejects example domains, the
example image repository, mutable image tags, missing external auth/database
Secrets, built-in decoy fallback, unsafe rollout switches, anonymous SOCKS5,
shared ingress/egress public IPs, disabled egress isolation, host-wide
zapret2/NFQUEUE and missing MTProto core settings before rendering the
production manifests. `TRACEGATE_CLUSTER_PREFLIGHT=1` additionally runs
`cluster-preflight-check.py` through `kubectl` and verifies that required
external Secret keys, TLS Secrets, external decoy ConfigMap/PVC references and
Entry/Transit node labels already exist in the target namespace. When
`network.egressIsolation.nodeAnnotations.enabled=true`, it also checks the
gateway node public-IP annotations against the production values. It only checks
metadata and Secret key names; it does not print or decode Secret values. Use
`TRACEGATE_KUBECTL` or `TRACEGATE_KUBE_CONTEXT` when targeting a non-default
kubectl binary or context.

## Production deploy wrapper

Use `deploy-prod.sh` for the actual production promotion. It refuses
`values-prod.example.yaml`, runs the strict deploy-ready gate by default,
verifies that the rendered chart namespace matches `TRACEGATE_NAMESPACE`, then
executes Helm with atomic rollback semantics:

```sh
TRACEGATE_K3S_PROD_VALUES=/path/to/ignored/values-prod.yaml \
TRACEGATE_KUBE_CONTEXT=prod-k3s \
deploy/k3s/deploy-prod.sh
```

The wrapper uses `helm upgrade --install --atomic --wait` with no `--force`.
After Helm reports success it also runs Kubernetes rollout, pod readiness and
PDB checks for the Tracegate release labels. Set `TRACEGATE_HELM_DRY_RUN=1` to
inspect Helm's upgrade path without applying it. `TRACEGATE_SKIP_PREFLIGHT=1`
exists only for emergency operator-controlled reruns after the same private
values file has already passed the full gate. `TRACEGATE_POST_DEPLOY_CHECKS=0`
disables only the final smoke checks; keep it enabled for normal production
promotion.
