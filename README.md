# Tracegate v0.1

Tracegate v0.1 implements a control-plane + node-agent architecture for:
- B1 `VLESS + REALITY` direct (443/tcp)
- B2 `VLESS + REALITY` chain via VPS-E -> VPS-T (443/tcp), with identical SNI on both legs
- B3 `Hysteria2` direct (443/udp), masquerade file mode
- B5 `WireGuard` direct (51820/udp)

SOCKS5 is intentionally local on the client (`127.0.0.1:1080`) and not exposed as a server port.

## Components

- `tracegate-api` (FastAPI)
  - users/devices/connections/revisions
  - SNI table management
  - revision slot policy (0..2 active)
  - grace period enforcement (7 days: no new revisions/devices)
  - outbox event creation
- `tracegate-dispatcher`
  - polls pending deliveries
  - pushes events to node-agents
  - at-least-once retries with backoff
- `tracegate-agent` (FastAPI)
  - idempotent event processing
  - bundle/user/WG artifact apply
  - health checks (ports, systemd, hysteria stats auth, WG listen-port)
- `tracegate-bot` (aiogram)
  - inline keyboards for devices and connection provisioning

Monetization objects are intentionally removed in this state: there is no `wallet`, `coins`, or billing ledger in the DB model.
`API_INTERNAL_TOKEN`, `AGENT_AUTH_TOKEN`, `BOT_TOKEN` are auth credentials, not payment tokens.

## GitHub-ready state

Repository now includes:
- CI workflow: `.github/workflows/ci.yml`
- Container image workflow: `.github/workflows/images.yml`
- k3s Helm deploy assets: `deploy/k3s/*`, `deploy/scripts/k3s_*`
- Production deploy assets: `deploy/systemd/*`, `deploy/env/*`, `deploy/scripts/*` (legacy/non-k3s path)
- Docker ignore and local cache ignores for clean commits.

## Quick start

1. Create env file:

```bash
cp .env.example .env
```

2. Start stack:

```bash
docker compose up --build
```

3. Initialize DB seed (optional if API startup has already created schema):

```bash
docker compose exec api tracegate-init-db
```

4. Health check:

```bash
curl http://localhost:8080/health
curl http://localhost:8070/v1/health
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

Detailed guide: `/Users/sgk/PycharmProjects/Tracegate/deploy/k3s/README.md`

## Deploy on VPS-T / VPS-E (legacy, non-k3s)

### 1) Control-plane host (can be VPS-T for v0.1)

```bash
sudo ./deploy/scripts/bootstrap_control_plane.sh <your-github-repo-url> main
sudo nano /etc/tracegate/control-plane.env
sudo systemctl restart tracegate-api tracegate-dispatcher
sudo /opt/tracegate/.venv/bin/tracegate-init-db
```

For all-in-one on VPS-T (control-plane + agent on one host):

```bash
sudo ./deploy/scripts/bootstrap_all_in_one_vps_t.sh <your-github-repo-url> main
```

### 2) Agent on VPS-T

```bash
sudo ./deploy/scripts/bootstrap_agent.sh <your-github-repo-url> VPS_T main
sudo nano /etc/tracegate/agent.env
sudo systemctl restart tracegate-agent
```

### 3) Agent on VPS-E (optional chain mode)

```bash
sudo ./deploy/scripts/bootstrap_agent.sh <your-github-repo-url> VPS_E main
sudo nano /etc/tracegate/agent.env
sudo systemctl restart tracegate-agent
```

### 4) Register nodes and trigger rollout from control-plane

```bash
./deploy/scripts/register_nodes.sh \
  http://127.0.0.1:8080 \
  <API_INTERNAL_TOKEN> \
  https://<vps-t-agent-host>:8070 \
  <vps-t-public-ip> \
  https://<vps-e-agent-host>:8070 \
  <vps-e-public-ip>

./deploy/scripts/reapply_and_reissue.sh http://127.0.0.1:8080 <API_INTERNAL_TOKEN>
```

## Base bundles

- `bundles/base-vps-t`
  - `xray.json`, `hysteria.yaml`, `wg0.conf`, `nftables.conf`, `decoy/index.html`
- `bundles/base-vps-e`
  - `xray.json`, `nftables.conf`

`/dispatch/reapply-base` loads these files and sends them to node agents via outbox events.

## Fast migration flow (VPS-E or VPS-T replacement)

1. Bring up new node and register it in `node_endpoint`.
2. Run `reapply-base` for the role.
3. Update endpoint (`public_ipv4`/`fqdn`) in control-plane.
4. Run `reissue-current-revisions`.

No full DB restore is required for architecture migration if control-plane data is intact.

## Notes on constraints from v0.1

- IPv4-only assumptions.
- VLESS/Hysteria fixed on 443; WireGuard fixed on 51820.
- Hysteria Traffic Stats API must remain secret-protected.
- Chain mode enforces the same SNI on client->E and E->T legs.
- User device limit defaults to `5`.
- Active revision limit is enforced to `3` slots (`0..2`).
