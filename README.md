<p align="center">
  <img src="docs/assets/tracegate-wordmark.svg" alt="TRACEGATE" width="720">
</p>

Tracegate 2.2 is a managed privacy-gateway stack with a Telegram bot, API control plane, node agents and production deployment templates.

It is built around a simple user flow: add a device, select it as active, create a connection profile, then rotate or revoke revisions when needed.

Release notes live in [`CHANGELOG.md`](CHANGELOG.md).

## Connection Surfaces

| Surface | Profile family | Role | Notes |
| --- | --- | --- | --- |
| `V1-Direct` | VLESS + REALITY | Direct | Primary TCP profile |
| `V1-Chain` | VLESS + REALITY | Chain | Entry-routed TCP profile |
| `V2-Direct` | Hysteria2 + Salamander | Direct | Primary UDP profile |
| `V2-Chain` | Hysteria2 + Salamander | Chain | Entry-routed UDP profile |
| `V3-Direct` | Shadowsocks-2022 + ShadowTLS | Direct | Optional TCP profile |
| `V3-Chain` | Shadowsocks-2022 + ShadowTLS | Chain | Optional chain TCP profile |
| `V0` | VLESS gRPC | Other | Direct compatibility profile |
| `V0` | VLESS WebSocket | Other | Direct compatibility profile |
| `V0` | WGWS | Other | Direct compatibility profile |
| `Telegram Proxy` | MTProto | Direct | Persistent Telegram Proxy access |

## Core Features

- Telegram bot for user onboarding, device selection, connection creation and revision management
- per-user device inventory with one active device used for new connection issuance
- Direct, Chain and Other connection categories with consistent Tracegate 2.2 naming
- two-revision connection model: active revision plus spare revision
- persistent Telegram Proxy access delivery through the bot
- admin controls for users, access revocation, blocks, announcements and operational feedback
- API control plane with durable PostgreSQL state
- dispatcher pipeline for delivering runtime changes to node agents
- optional Prometheus and Grafana integration
- Helm chart for production k3s deployment
- systemd deployment kit for plain Linux migration and lab environments

## User Model

Tracegate stores users, devices, connections and revisions separately.

- A user can have up to 5 devices.
- A device can have up to 4 connections.
- A connection can have up to 2 active revisions.
- New profiles are always attached to the currently active device.
- Existing profiles can be viewed, rotated, activated or removed from the `Connections` section of the bot.

## Components

### Control Plane

- `tracegate-api`: FastAPI service for users, devices, connections, revisions, admin flows and grants
- `tracegate-dispatcher`: background worker for runtime delivery and retry handling
- `tracegate-bot`: Telegram UX for users and admins
- PostgreSQL: durable state storage

### Managed Nodes

Node agents receive rendered runtime material from the control plane and apply changes without requiring users to understand the server topology.

Tracegate supports a primary Transit node and optional Entry nodes for chain profiles. The public repository keeps node templates, validation logic and deployment scaffolding; environment-specific runtime material belongs to deployment storage outside this repository.

## Bot UX

The main menu is intentionally small:

- `Help`: guideline and welcome screen
- `Connections`: create profiles, show active configs, rotate revisions, switch active revision, delete profiles
- `Devices`: add devices and choose the active one
- `Telegram Proxy`: show, rotate or revoke persistent Telegram Proxy access
- `Grafana`: request an observability login when enabled
- `Feedback`: contact project admins

Admins get an additional management section for access and moderation tasks.

## Repository Layout

- `src/tracegate`: application code
- `deploy/k3s/tracegate`: production Helm chart
- `deploy/systemd`: plain-host deployment kit
- `bundles`: public runtime bundle templates
- `alembic`: database migrations
- `tests`: coverage for API, bot and deployment behavior

## Local Development

Use Docker Compose for the control-plane development stack:

```bash
cp .env.example .env
docker compose up --build
docker compose exec api tracegate-init-db
pytest -q
```

Local development is intended for the control plane, bot flows, templates and validation logic. Production runtime configuration should be tested through the deployment chart and environment-specific values.

## Production Deployment

Tracegate 2.2 ships a single Helm chart:

```bash
helm template tracegate ./deploy/k3s/tracegate --namespace tracegate --create-namespace
helm upgrade --install tracegate ./deploy/k3s/tracegate \
  --namespace tracegate \
  --create-namespace \
  -f deploy/k3s/values-prod.yaml
```

Production values are intentionally environment-specific and are not part of the public README.

For plain-host migration and lab installs, start with [`deploy/systemd`](deploy/systemd).

## Container Image

The project publishes the main application image through GitHub Packages:

```text
ghcr.io/myheartraces/tracegate:2.2.0
```

Production deployments should pin either a version tag or an OCI digest.

## Observability

Tracegate can expose metrics for the API, bot, dispatcher and node agents. Grafana access can be issued through the bot when the deployment enables it.

## Validation

The test suite covers:

- API behavior
- bot navigation and text flows
- connection and revision rules
- client export generation
- Helm rendering
- deployment validation
- deployment helper behavior

Run locally:

```bash
python3 -m ruff check .
pytest -q
```

The k3s release gate is:

```bash
deploy/k3s/deploy-ready-check.sh
```

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).
