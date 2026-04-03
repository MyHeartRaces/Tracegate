# Tracegate v0.6

Tracegate is a control-plane, node-agent and Telegram bot stack for managing a two-node privacy gateway topology on k3s.

It provisions client configs, dispatches revisions to node agents, reconciles gateway runtime state, and exposes an admin/operator workflow through API, bot and observability tooling.

Current release notes: [`CHANGELOG.md`](CHANGELOG.md)

## What Tracegate manages

- Direct profiles on `VPS-T`
- Chain profiles that enter on `VPS-E` and transit through `VPS-T`
- Xray, Hysteria2 and WireGuard gateway runtime configs
- Telegram bot provisioning, admin actions, feedback intake and blocking
- Revision delivery, retries and dead-letter handling
- Optional Prometheus + Grafana stack for observability

SOCKS5 remains client-local (`127.0.0.1:1080`) and is not exposed as a server port.

## Supported connection profiles

| Profile | Protocol | Entry | Transit | Port |
| --- | --- | --- | --- | --- |
| `B1` | `VLESS + REALITY` | `VPS-T` | none | `443/tcp` |
| `B2` | `VLESS + REALITY` | `VPS-E` | `VPS-E -> VPS-T` | `443/tcp` |
| `B3` | `Hysteria2` | `VPS-T` | none | `443/udp` |
| `B4` | `Hysteria2` | `VPS-E` | `VPS-E -> VPS-T` via Xray/REALITY | `443/udp` + `443/tcp` |
| `B5` | `WireGuard` | `VPS-T` | none | `51820/udp` |

Optional `VLESS + WebSocket + TLS` is also supported when you control a domain and certificate.

## Topology

### Control-plane path

- `tracegate-api` stores users, devices, connections, revisions and scoped API tokens
- `tracegate-dispatcher` delivers outbox events to node agents with retry/backoff
- `tracegate-agent` applies bundles and user artifacts, reconciles local runtime state and exposes health/metrics
- `tracegate-bot` provisions configs, performs admin actions and relays user feedback

### Data-plane path

- `VPS-T` is the primary direct node
- `VPS-E` is the public chain entry node
- Chain traffic from `VPS-E` can use selector-driven interconnect routing toward `VPS-T`
- Interconnect candidates can include direct hostnames/IPs plus optional `Hysteria` and `WireGuard` backplanes

## Major changes in v0.6

- Adaptive `VPS-E -> VPS-T` transit selector with health probes, hysteresis and multi-path candidate selection
- Dedicated inter-node backplanes:
  - `Hysteria` backplane with TCP encapsulation through `VPS-T entry-mux :443`
  - `WireGuard` backplane on dedicated `wgs2s`
- Hardened `VPS-E` runtime:
  - dedicated `xray-b2` sidecar for managed B2 REALITY inbounds
  - grouped REALITY routing and transit self-heal improvements
  - bundled Xray geodata in the app image
- Gateway stability improvements:
  - startup probes for entry points
  - safer Hysteria reload behavior
  - better entry-mux capacity and rollout behavior
  - host-network DNS behavior aligned with live topology
- Bot/admin improvements:
  - permanent and timed bot blocks
  - full bot-user registry views: all, active, blocked
  - user feedback flow with admin relay and targeted bans
- Ops/observability improvements:
  - debounced transient OPS alerts
  - safer Grafana alerting behavior for short-lived flaps

## Components

### `tracegate-api`

- FastAPI control-plane
- users, devices, connections, revisions
- static SNI catalog
- revision slot policy
- scoped API tokens
- optional Grafana OTP login proxy
- Alembic migrations on startup

### `tracegate-dispatcher`

- polls pending outbox deliveries
- at-least-once retries with backoff
- dead-letter handling for failed deliveries
- Prometheus metrics
- optional OPS alerting pipeline

### `tracegate-agent`

- idempotent event processing
- bundle, user and WireGuard artifact apply
- runtime reconcile for Xray, Hysteria and WireGuard
- health checks for ports, sidecars and runtime expectations
- Prometheus metrics

### `tracegate-bot`

- client provisioning and revision resend flows
- admin and superadmin tooling
- all/active/blocked bot-user registries
- immediate access revoke on blocks
- feedback relay from users to admins
- Grafana OTP issuing

### Gateway pods

`VPS-T` can run:
- `entry-mux`
- `xray`
- `hysteria`
- `wireguard`
- optional `hysteria-backplane`
- optional `wireguard-backplane`
- `agent`

`VPS-E` can run:
- `entry-mux`
- `xray`
- optional `xray-b2`
- optional `hysteria`
- optional `transit-selector`
- optional `hysteria-backplane-client`
- optional `wireguard-backplane`
- `agent`

## Local development

Local `docker-compose` is intended for control-plane development: API, Postgres, dispatcher and optional bot.

### 1. Create env file

```bash
cp .env.example .env
```

### 2. Start the stack

```bash
docker compose up --build
```

### 3. Initialize or migrate DB

```bash
docker compose exec api tracegate-init-db
```

### 4. Check health

```bash
curl http://localhost:8080/health
```

## API basics

All management endpoints require:

```text
x-api-token: <API_INTERNAL_TOKEN>
```

Bootstrap `API_INTERNAL_TOKEN` has full access. Issued tokens can be scoped, for example:

```json
{
  "name": "bot-token",
  "scopes": ["users:rw", "devices:rw", "connections:rw", "revisions:rw", "sni:read", "grafana:otp", "bot_messages:rw"]
}
```

Examples:

```bash
curl -H 'x-api-token: change-me' http://localhost:8080/sni
curl -H 'x-api-token: change-me' -X POST http://localhost:8080/dispatch/reapply-base -H 'Content-Type: application/json' -d '{}'
curl -H 'x-api-token: change-me' -X POST http://localhost:8080/dispatch/reissue-current-revisions -H 'Content-Type: application/json' -d '{}'
```

## Production deployment on k3s

The recommended production target is the Helm chart in [`deploy/k3s/tracegate`](deploy/k3s/tracegate).

### 1. Build and push images

Use the GitHub Actions workflow `images` or build manually:

- app image: `ghcr.io/<org>/tracegate:<tag>`
- wireguard image: `ghcr.io/<org>/tracegate-wireguard:<tag>`

### 2. Label nodes

```bash
./deploy/scripts/k3s_label_nodes.sh <vps-t-node-name> <vps-e-node-name>
```

### 3. Prepare production values

Start from:

```bash
cp deploy/k3s/values-prod.example.yaml deploy/k3s/values-prod.yaml
```

At minimum override:

- image repositories and tags
- auth tokens
- `controlPlane.env.superadminTelegramIds`
- public IP/FQDN for `VPS-T` and `VPS-E`
- Xray, Hysteria and WireGuard configs
- `gateway.interconnect.*` if you use selector-driven transit or backplanes

### 4. Install or upgrade

```bash
./deploy/scripts/k3s_helm_install.sh tracegate tracegate deploy/k3s/values-prod.yaml
```

### 5. Verify

```bash
kubectl -n tracegate get pods -o wide
kubectl -n tracegate logs deploy/tracegate-api
kubectl -n tracegate logs deploy/tracegate-gateway-vps-t -c agent
kubectl -n tracegate logs deploy/tracegate-gateway-vps-e -c agent
```

Detailed k3s notes: [`deploy/k3s/README.md`](deploy/k3s/README.md)

## Base bundles

Base bundles are optional but useful for reapplying known-good host configs:

- `bundles/base-vps-t`
  - `xray.json`, `hysteria.yaml`, `wg0.conf`, `nftables.conf`, `decoy/index.html`
- `bundles/base-vps-e`
  - `xray.json`, `hysteria.yaml`, `nftables.conf`

`/dispatch/reapply-base` loads these files and sends them to node agents through outbox events.
On k3s, node agents also mirror known service configs into `base/*`, run reconcile and apply reload hooks.

## Observability

The Helm chart can optionally deploy Prometheus + Grafana with `observability.enabled=true`.

- Grafana is exposed only through the control-plane reverse proxy at `/grafana/*`
- users request one-time Grafana login links in the Telegram bot
- regular users are scoped by pseudo-ID
- admins and superadmins receive admin dashboards and metadata views

## Operations notes

- IPv4-only assumptions
- VLESS and Hysteria stay on `443`; WireGuard stays on `51820`
- Hysteria Traffic Stats API must remain secret-protected
- `gateway.vpsE.mode=tcpForward` is the simpler legacy chain mode
- `gateway.vpsE.mode=xray` enables split routing on `VPS-E`:
  - `geosite:category-ru`
  - `.ru`, `.su`, `.xn--p1ai`
  - `geoip:ru`
  - default traffic goes to `VPS-T` transit
- `VPS-E` interconnect selector is optional; if you want minimal overhead, keep a single backplane instead of probing multiple candidates
- `VPS-T` runs `ClusterFirstWithHostNet`; `VPS-E` uses host DNS when `hostNetwork=true`
- recommended Xray user update mode is gRPC API to avoid full reloads

## Node replacement and disaster recovery

### Replace one node

1. Bring up the new node and register it in `node_endpoint`
2. Run `reapply-base` for the role
3. Update the endpoint (`public_ipv4` and/or `fqdn`) in control-plane
4. Run `reissue-current-revisions`

### Full rebuild

1. Back up Helm values and secrets:
   - `helm -n tracegate get values tracegate -o yaml`
   - external `values-*.yaml` overrides
2. Recreate the k3s cluster
3. Restore Postgres
4. Reinstall the Helm release with the same production values
5. Run:
   - `/dispatch/reapply-base`
   - `/dispatch/reissue-current-revisions`

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).
