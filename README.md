# Tracegate v0.2

Tracegate implements a control-plane + node-agent architecture for:
- B1 `VLESS + REALITY` direct (443/tcp)
- B2 `VLESS + REALITY` chain via VPS-E -> VPS-T (443/tcp), with identical SNI on both legs
- Optional: `VLESS + WebSocket + TLS` (requires a domain + certificate you control)
- B3 `Hysteria2` direct (443/udp), masquerade file mode
- B5 `WireGuard` direct (51820/udp)

SOCKS5 is intentionally local on the client (`127.0.0.1:1080`) and not exposed as a server port.

## Components

- `tracegate-api` (FastAPI)
  - users/devices/connections/revisions
  - SNI catalog (static, repo-owned)
  - revision slot policy (0..2 active)
  - grace period enforcement (7 days: no new revisions/devices)
  - outbox event creation
  - Alembic migrations on startup
  - Grafana OTP login + reverse proxy (`/grafana/*`) (optional)
- `tracegate-dispatcher`
  - polls pending deliveries
  - pushes events to node-agents
  - at-least-once retries with backoff
  - delivery locking (`FOR UPDATE SKIP LOCKED`) and dead-lettering (`DEAD`)
- `tracegate-agent` (FastAPI)
  - idempotent event processing
  - bundle/user/WG artifact apply
  - health checks (ports, hysteria stats auth, WG listen-port, sidecar process checks)
  - Prometheus metrics (`/metrics`)
- `tracegate-bot` (aiogram)
  - inline keyboards for devices and connection provisioning
  - admin/superadmin mode (Telegram ID roles)
  - Grafana OTP issuing

Monetization objects are intentionally removed in this state: there is no `wallet`, `coins`, or billing ledger in the DB model.
`API_INTERNAL_TOKEN`, `AGENT_AUTH_TOKEN`, `BOT_TOKEN` are auth credentials, not payment tokens.

SNI is a static catalog bundled with the app: `src/tracegate/staticdata/sni_catalog.yaml` (no Postgres SNI table).
Bot users are keyed by Telegram `telegram_id` (primary key).

## v0.2 highlights

- Alembic migrations (v0.1 baseline stamping + upgrade to head).
- WireGuard peer lifecycle fix: single peer per device, consistent slot0 state, IPAM reuse/release.
- Outbox dispatcher hardening: locking, concurrency, max-attempt dead-letter.
- k3s-only deployment pipeline (legacy non-k3s assets removed).
- Optional observability stack (Prometheus + Grafana) with Telegram OTP login via bot.

## Quick start

Local docker-compose is intended for control-plane development (API + DB + dispatcher, optional bot).
Gateway (xray/hysteria/wireguard + agent sidecar) is deployed via k3s Helm chart.

1. Create env file:

```bash
cp .env.example .env
```

2. Start stack:

```bash
docker compose up --build
```

3. Initialize DB (creates/updates schema via Alembic + seeds IPAM pool):

```bash
docker compose exec api tracegate-init-db
```

4. Health check:

```bash
curl http://localhost:8080/health
```

## API essentials

All management endpoints require header:

```text
x-api-token: <API_INTERNAL_TOKEN>
```

Examples:

```bash
curl -H 'x-api-token: change-me' http://localhost:8080/sni
curl -H 'x-api-token: change-me' -X POST http://localhost:8080/dispatch/reapply-base -d '{}' -H 'Content-Type: application/json'
curl -H 'x-api-token: change-me' -X POST http://localhost:8080/dispatch/reissue-current-revisions -d '{}' -H 'Content-Type: application/json'
```

## Deploy on k3s (recommended)

### 1) Build/push images

Use GitHub Actions workflow `images` or build manually:
- app image: `ghcr.io/<org>/tracegate:<tag>`
- wireguard image: `ghcr.io/<org>/tracegate-wireguard:<tag>`

### 2) Label k3s nodes

```bash
./deploy/scripts/k3s_label_nodes.sh <vps-t-node-name> <vps-e-node-name>
```

### 3) Prepare values override

Create `deploy/k3s/values-prod.yaml` and set:
- image repositories/tags
- auth tokens
- public IP/FQDN for VPS-T and VPS-E
- xray/hysteria/wireguard config blocks

### 4) Install/upgrade chart

```bash
./deploy/scripts/k3s_helm_install.sh tracegate tracegate deploy/k3s/values-prod.yaml
```

Detailed guide: `deploy/k3s/README.md`

## Base bundles (optional)

- `bundles/base-vps-t`
  - `xray.json`, `hysteria.yaml`, `wg0.conf`, `nftables.conf`, `decoy/index.html`
- `bundles/base-vps-e`
  - `xray.json`, `nftables.conf`

`/dispatch/reapply-base` loads these files and sends them to node agents via outbox events.

## Observability (Prometheus + Grafana)

The Helm chart can optionally deploy Prometheus + Grafana (`observability.enabled=true`).

Grafana is exposed only via the control-plane reverse proxy at `/grafana/*`.
Users request a one-time login link (OTP) in Telegram bot: `Статистика (Grafana)`.

Regular users are scoped in dashboards by `${__user.login}` (Telegram ID); Explore is disabled.
Admins/superadmins have access to the Admin dashboard folder.

## Node replacement flow (VPS-E or VPS-T)

1. Bring up new node and register it in `node_endpoint`.
2. Run `reapply-base` for the role.
3. Update endpoint (`public_ipv4`/`fqdn`) in control-plane.
4. Run `reissue-current-revisions`.

No full DB restore is required for architecture migration if control-plane data is intact.

## Notes

- IPv4-only assumptions.
- VLESS/Hysteria fixed on 443; WireGuard fixed on 51820.
- Hysteria Traffic Stats API must remain secret-protected.
- Chain mode enforces the same SNI on client->E and E->T legs.
- User device limit defaults to `5`.
- Active revision limit is enforced to `3` slots (`0..2`).
