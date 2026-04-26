<p align="center">
  <img src="docs/assets/tracegate-wordmark.svg" alt="TRACEGATE" width="720">
</p>

## Connection Surfaces

| Surface | Protocol | Public node | Default port | Notes |
| --- | --- | --- | --- | --- |
| `V1` | `VLESS + REALITY` | `Transit` | `443/tcp` | Main direct TCP profile |
| `V1` | `VLESS + gRPC + TLS` | `Transit` | `443/tcp` | Main HTTPS carrier profile |
| `V1` | `VLESS + WS + TLS` | `Transit` | `443/tcp` | Legacy WS/TLS fallback |
| `V2` | `VLESS + REALITY` | `Entry` | `443/tcp` | Optional chain path to `Transit` |
| `V3` | `Hysteria2` via `Xray` | `Transit` | `443/udp` | Main UDP profile |
| `V4` | `Hysteria2` via `Xray` | `Entry` | `443/udp` | Optional chain path to `Transit` |
| `V5` | `Shadowsocks-2022 + ShadowTLS V3` | `Transit` | `443/tcp` | Optional direct TCP profile |
| `V6` | `Shadowsocks-2022 + ShadowTLS V3` | `Entry` | `443/tcp` | Optional chain path to `Transit` |
| `V7` | `WireGuard over WebSocket` | `Transit` | `443/tcp` | Optional WireGuard profile |
| `Telegram Proxy` | `MTProto` | `Transit` | `443/tcp` | Dedicated domain recommended |

Tracegate 2.1 is a `k3s` + Helm managed control plane, node-agent and Telegram bot stack for a privacy gateway built around a primary `Transit` node and an optional `Entry -> Transit` chain.

The repository contains the public control logic, bundle templates, bot UX, observability hooks and deployment contracts. Private packet camouflage, `Mieru` profiles, `zapret2` policies, MTProto secrets and local overlay files stay outside Git and are consumed through explicit runtime handoff surfaces.

Release notes live in [`CHANGELOG.md`](CHANGELOG.md).

## What the project does

- issues `VLESS`, `Hysteria2`, `Shadowsocks-2022 + ShadowTLS`, `WireGuard over WebSocket` and persistent Telegram Proxy access through a Telegram bot
- stores users, devices, connections, revisions and admin state in a central control plane
- delivers runtime changes to node agents through an outbox + dispatcher pipeline
- keeps `Xray` hot while ordinary config issuance changes only users, not the full runtime
- renders public bundles from repo templates and applies private overlays only on the target host
- exposes optional Prometheus + Grafana observability with bot-delivered Grafana access
- supports Transit-only rollout and Transit node replacement as first-class operational paths
- ships a single Tracegate 2.1 Helm chart under `deploy/k3s/tracegate`

## Product boundary

### Included in Tracegate 2.1

- `V1`: direct `VLESS + REALITY` on `Transit`
- `V1`: `VLESS` over gRPC-first HTTPS carrier, with `WebSocket + TLS` fallback
- `V3`: direct `Hysteria2` on `Transit`, terminated by `Xray`
- `V2`: chained `Entry -> Transit` `VLESS + REALITY`
- `V4`: chained `Entry -> Transit` `Hysteria2`
- `V5`: direct `Shadowsocks-2022 + ShadowTLS V3`
- `V6`: chained `Shadowsocks-2022 + ShadowTLS V3`
- `V7`: `WireGuard over WebSocket`
- persistent Telegram Proxy delivery through the bot
- scoped `Mieru` link encryption wrapped by a dedicated WSS bridge carrier, plus `zapret2` interconnect camouflage with no host-wide NFQUEUE by default
- optional host-local static/auth surfaces on `Transit`, staged outside Git
- host-local private handoff contracts for `zapret2`, Transit TCP/443 fronting and MTProto

### Explicitly not part of the active repository contract

- separate standalone `hysteria` daemon path
- temporary "burner" MTProto access
- client-side OpenWRT / desktop-local obfuscation bundles

## Design principles

- Helm owns the static topology; live APIs and narrow reload hooks own user/runtime state.
- `Xray` remains the runtime center for `VLESS` and `Hysteria2` public connection surfaces.
- `Transit` is the primary public endpoint; `Entry` is optional chain ingress.
- Public topology should stay static; ordinary user churn should update `Xray` over gRPC API instead of restarting the runtime.
- All public-facing profiles stay on `443`.
- On constrained `~1 GB RAM` hosts, keep the default rollout narrow: static public topology first, optional extra wrappers only when they are operationally justified.
- Public repo files describe contracts and templates; secrets and private camouflage live in external Kubernetes Secrets or host-local `/etc/tracegate/private`.

## Architecture

### Control plane

- `tracegate-api`: FastAPI service for users, devices, connections, revisions, admin flows, MTProto grants and scoped API tokens
- `tracegate-dispatcher`: outbox delivery worker with retry, backoff, dead-letter handling and optional ops alerts
- `tracegate-bot`: Telegram UX for provisioning, admin flows, Grafana access and feedback
- PostgreSQL: durable storage for users, revisions, dispatcher state and grants

### Transit node

`Transit` is the main public node. It can host:

- direct `VLESS + REALITY`
- optional `VLESS + WS + TLS`
- direct `Hysteria2` through `Xray`
- optional host-local static/auth surfaces staged outside Git
- persistent Telegram Proxy
- host-local private TCP/443 fronting and `zapret2` wrappers

### Entry node

`Entry` is optional and exists for chained `V2/V4` rollout. It exposes the public chain ingress and forwards traffic toward `Transit` while sharing the same control-plane and bundle contract.

### Private host-local boundary

The public repository never stores the real packet manipulation or MTProto secrets. Instead it emits machine-readable handoff surfaces that private host-local wrappers can consume:

- Helm-mounted private profile Secret under `/etc/tracegate/private`
- `runtime-contract.json` under each agent runtime tree
- private runtime-state handoffs under the effective private runtime root
- private per-role profile desired state under `<private-runtime-root>/profiles/<role>/desired-state.{json,env}`
- private Mieru link handoff under `<private-runtime-root>/link-crypto/<role>/desired-state.{json,env}`
- k3s private Secret preflight through `tracegate-k3s-private-preflight` before gateway listeners start
- k3s private reload validation through `tracegate-k3s-private-reload` with redacted marker files only
- k3s sidecar startup gates that require generated desired-state/env and a non-stale redacted reload marker
- k3s sidecar env pointers for private profile and link-crypto desired-state/env/marker files
- seeded example files under `deploy/systemd/private-example`

The Helm chart mounts private transport Secret files read-only with
`privateProfiles.defaultMode=256` (`0400`) by default.

The k3s private preflight is intentionally narrow but strict on version class:
Shadowsocks private files must advertise a `2022-*` method with secret material,
ShadowTLS private files must declare v3 with password material, MTProto files
must contain exactly one raw 32-hex-character server secret, and WireGuard
files must not use `wg-quick` lifecycle hooks, DNS rewrites, saved config, broad
AllowedIPs routes, unsafe MTU values or long keepalive timers. zapret2 private
env files must not target broad host traffic through values like `all`, `*` or
`all-flows`; mounted private files must not be world-accessible.

This is the intended boundary for:

- private `zapret2` logic
- private `Mieru` Entry-Transit and Router-Entry/Transit link encryption
- private `sing-box`, `ShadowTLS`, `WSTunnel` and `WireGuard` profile adapters
- private Transit TCP/443 fronting
- private MTProto runner configuration
- local post-render hooks and secret overlays

## Zero-downtime runtime model

Tracegate 2 is designed so ordinary config issuance does not restart `Xray`.

The intended steady state is:

1. pre-seed a stable public topology
2. keep REALITY inbound mapping fixed, ideally through `REALITY_MULTI_INBOUND_GROUPS`
3. update users through the server-side loopback-only `Xray` gRPC `HandlerService`
4. reload only when the structure changes

Typical structural changes that still require reload:

- new inbound layout
- changed REALITY group mapping
- changed routing rules
- changed public fronting layout

Ordinary user issuance, rotation and revocation should stay within the live API sync path.

## Observability

The project can expose:

- Prometheus metrics from API, dispatcher, bot and agent surfaces
- Grafana with bot-delivered one-time access links
- pseudonymized user labels for safer dashboards
- dispatcher health and outbox alerts
- runtime and handoff validation through preflight tooling

## Repository layout

- `src/tracegate`: application code
- `bundles/base-entry`, `bundles/base-transit`: public runtime bundle templates
- `deploy/k3s/tracegate`: Tracegate 2.1 production Helm chart
- `deploy/systemd`: host deployment kit for plain Linux installs
- `deploy/systemd/private-example`: seeded examples for private overlays and wrappers
- `alembic`: database migrations
- `tests`: regression tests for API, bot, deployment and runtime logic

## Local development

Use Docker Compose for the control-plane development stack:

```bash
cp .env.example .env
docker compose up --build
docker compose exec api tracegate-init-db
curl http://localhost:8080/health
pytest -q
```

Local development is mainly for the control plane and template logic. Production runtime deployment is covered by the Tracegate 2.1 Helm chart.

## k3s deployment

Tracegate 2.1 targets `k3s` with a single Helm chart:

```bash
helm template tracegate ./deploy/k3s/tracegate --namespace tracegate --create-namespace
helm upgrade --install tracegate ./deploy/k3s/tracegate \
  --namespace tracegate \
  --create-namespace \
  -f deploy/k3s/values-prod.yaml
```

Production values and private transport profiles must stay outside Git. The repo ignores `deploy/k3s/values-prod.yaml`, `deploy/k3s/values-*.private.yaml`, `deploy/k3s/private/` and `deploy/k3s/link-profiles/`.

The chart keeps user and connection state out of pod-template checksums, uses
`RollingUpdate` with `maxUnavailable=0` for gateway pods, mounts decoys
read-only, enables `Xray` API updates and routes private
Mieru/zapret2/ShadowTLS/WireGuard/MTProto material through an external Secret.

## Plain-host migration kit

The old Tracegate 2 plain-host `systemd` kit remains available while 2.1 migrates production traffic to k3s.

Start with the deployment kit in [`deploy/systemd`](deploy/systemd):

- `tracegate.env.example`: shared control-plane and bundle-rendering values
- `entry.env.example`: Entry-only runtime values
- `transit.env.example`: Transit-only runtime values
- `transit-single.env.example`: single-file Transit replacement profile
- `install.sh`: installs the repo, Python package, units and seeded private examples
- `install-runtime.sh`: installs upstream runtime binaries
- `render-materialized-bundles.sh`: renders host-ready bundle files
- `render-xray-centric-overlays.sh`: optional full private `xray.json` overlay generator
- `validate-runtime-contracts.sh`: rollout preflight
- `replace-transit-node.sh`: Transit-only replacement workflow

Typical host flow:

```bash
sudo ./deploy/systemd/install.sh
sudo /opt/tracegate/deploy/systemd/install-runtime.sh
sudo /opt/tracegate/deploy/systemd/render-materialized-bundles.sh
sudo /opt/tracegate/deploy/systemd/validate-runtime-contracts.sh
```

By default the public repository only provides the runtime contract for the shared static root. A fresh node will boot
with an empty `XRAY_CENTRIC_DECOY_DIR` until private static/auth content is staged through `/etc/tracegate/private/overlays`.
Bot-facing copy such as `/guide` and the welcome warning must also be mounted from private runtime storage or external
Kubernetes Secrets; the repository only contains placeholder settings.

Transit-only rebuild flow:

```bash
sudo TRACEGATE_INSTALL_ROLE=transit TRACEGATE_SINGLE_ENV_ONLY=true ./deploy/systemd/install.sh
sudo TRACEGATE_ENV_FILE=/etc/tracegate/tracegate.env /opt/tracegate/deploy/systemd/replace-transit-node.sh
```

The repository also ships a GitHub Actions workflow for Transit replacement:

- [`.github/workflows/transit-node-replacement.yml`](.github/workflows/transit-node-replacement.yml)

For legacy deployment details, environment layout and private overlay rules, read [`deploy/systemd/README.md`](deploy/systemd/README.md).

## Container image

The repository also builds a container image through the `images` workflow.

- the image embeds `Xray` from the official release asset
- `XRAY_VERSION=latest` resolves through the stable GitHub release download URL, not the unauthenticated API
- a fixed `XRAY_VERSION` build arg can still be supplied when an operator wants a pinned image build

The container image is used by the Helm chart for the control plane and gateway agent sidecars.

## Operations

Important operator surfaces:

- `POST /dispatch/reapply-base`: resend current base bundle set to node agents
- `POST /dispatch/reissue-current-revisions`: reissue active user revisions
- `tracegate-render-materialized-bundles`: render public templates with operator values
- `tracegate-render-xray-centric-overlays`: generate host-local `Xray` replacements for the active runtime
- `tracegate-validate-runtime-contracts`: verify public/private handoff consistency before rollout
- `tracegate-k3s-private-preflight`: validate mounted private Secret files before gateway listeners start
- `tracegate-k3s-private-reload`: validate generated k3s private handoffs and write redacted reload markers

Useful operational rules:

- keep decoy auth credentials only in host env files
- keep optional decoy HTML/CSS/JS assets out of the public repository
- keep MTProto secrets only in host-local files or external Secrets
- keep private Mieru, ShadowTLS and WireGuard profiles in external Secrets
- keep `zapret2` policy logic out of the public repository
- keep k3s `profiles` and `linkCrypto` reload markers newer than their desired-state/env files before private sidecars are allowed to launch
- keep WireGuard `wg-quick` hooks, DNS rewrites and default-route AllowedIPs out of k3s private Secrets
- prefer dedicated real domains for Telegram Proxy surfaces
- treat `VLESS + WS + TLS` as a legacy fallback, not as the core architecture

## Security and private data

The repository is designed so sensitive runtime logic can stay private:

- public bundle templates are safe to commit
- production Helm values live in ignored files under `deploy/k3s`
- host-local overlays live under `/etc/tracegate/private/overlays`
- post-render hooks live under `/etc/tracegate/private/render-hook.sh`
- private obfuscation/fronting/link-crypto/MTProto helpers live under `/etc/tracegate/private/{systemd,fronting,link-crypto,zapret,mtproto}`
- agent-generated private runtime state lives under the effective private runtime root, typically `/var/lib/tracegate/private`
- generated V5/V6/V7 private desired-state files contain credentials and must stay under that private runtime root
- profile adapter scaffolds emit only redacted manifests; real V5/V6/V7 process wiring stays in private runners
- generated link-crypto handoffs contain only public pointers to private Mieru/zapret2 files; the referenced profiles still stay outside Git
- production overlays must declare dedicated ingress and egress public IP sets; strict preflight rejects shared ingress/egress IPs before deploy
- user traffic SNAT and any rule that forbids outbound through ingress IPs belongs to private host policy under `/etc/tracegate/private/egress-isolation`
- preflight validation rejects profile handoffs that disable local SOCKS5 auth, expose local adapters outside loopback, or enable host-wide interception
- default client UX is VPN/TUN-first; local SOCKS/mixed exports are advanced-only and must use required username/password plus stable per-connection high local ports instead of common `1080` defaults
- per-connection `local_socks_username` / `local_socks_password` overrides are allowed only as a non-empty pair and remain required-auth credentials, not an auth bypass
- connection read responses redact sensitive override values such as passwords, private keys, preshared keys, secrets and tokens
- runtime-contract preflight rejects public or widened Xray API surfaces; server-side API is limited to loopback `HandlerService`/`StatsService`

Do not commit:

- API tokens
- bot tokens
- MTProto secrets
- REALITY private keys
- private `Mieru`, `ShadowTLS` or `WireGuard` profiles
- private `zapret2` rules or classifiers
- decoy auth credentials
- decoy HTML/CSS/JS assets

## Current runtime note

Tracegate 2.1 uses `tracegate-2.1` as the k3s production runtime profile. It keeps the public Xray/Hysteria surface but forbids Xray Entry-to-Transit backhaul; V2/V4/V6 chaining is handed to the private `link-crypto`/Mieru layer wrapped by the bridge WSS carrier. The `xray-centric` profile remains only for the systemd migration surface.

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).
