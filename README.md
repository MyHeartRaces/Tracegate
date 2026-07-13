<p align="center">
  <img src="docs/assets/tracegate-wordmark.svg" alt="TRACEGATE" width="720">
</p>

Tracegate is a managed privacy-gateway control plane. It coordinates user
access, device profiles, gateway runtime state and operational visibility for a
multi-role relay stack.

This repository is the public source tree. It contains application code,
tests, generic templates and safe documentation. Live deployment coordinates,
operator scripts, production overlays, decoy content, raw client exports and
secret material are intentionally outside this tree.

## Capabilities

Tracegate provides:

- a Telegram-first user flow for onboarding, device management and profile
  delivery;
- a FastAPI control plane backed by durable database state;
- a dispatcher that turns control-plane changes into gateway work items;
- a node agent that applies rendered runtime material and reports health;
- client export builders for supported proxy and tunnel profile families;
- revision tracking for activation, rotation and revocation;
- Grafana handoff flows for user and operator visibility;
- host-based systemd runtime units and deterministic bundle validation;
- tests for host runtime contracts, bot behavior, exports,
  revision logic and observability formatting.

## Repository Boundary

Public-safe material belongs here:

- source code and migrations;
- generic host runtime templates and placeholder values;
- deterministic tests and non-live fixtures;
- public bundle templates;
- high-level operator documentation.

Sensitive material does not belong here:

- real domains, public addresses, ports, node names or provider metadata;
- production values and rendered manifests;
- decrypted runtime secrets or plaintext disk encryption keys;
- decoy site assets and live bot copy;
- generated client imports, QR payloads or runtime state snapshots;
- production deployment automation.

The private operator repository is the single place for live deployment
material.

## Architecture

Tracegate separates control-plane decisions from gateway execution:

- the API owns users, devices, connections, revisions and admin actions;
- the bot exposes user and admin workflows;
- the dispatcher batches pending runtime changes;
- gateway agents reconcile role-specific desired state;
- renderers build runtime profiles and public client exports from structured
  connection data;
- validation tools check public bundle safety and private overlay shape without
  printing secret values.

New production deployments use protected Entry and Endpoint runtime surfaces.
The internal `transit` gateway role remains only as an Endpoint compatibility
alias while older installations migrate.

## Layout

- [src/tracegate](src/tracegate): application, agent, bot, dispatcher and
  service code.
- [deploy/host](deploy/host): production Compose, systemd, install, upgrade and
  rollback contract.
- [deploy/systemd](deploy/systemd): host service units for data-plane helpers.
- [bundles](bundles): generic runtime bundle templates.
- [alembic](alembic): database migrations.
- [tests](tests): automated coverage for behavior and generated artifacts.
- [docs](docs): public documentation that avoids live deployment coordinates.
- [docs/mtproto-entry-endpoint.md](docs/mtproto-entry-endpoint.md): shared Entry
  MTProto ingress with Endpoint-local MTG.
- [docs/tracegate-3-architecture.md](docs/tracegate-3-architecture.md):
  Tracegate 3 profiles, ports, backhaul and MTProto contract.
- [docs/entry-endpoint-migration.md](docs/entry-endpoint-migration.md):
  two-node migration contract and promotion gates.
- [docs/ingress-rotation.md](docs/ingress-rotation.md): revision-sticky
  hostname pool behavior and limits.
- [docs/postgres-backups.md](docs/postgres-backups.md): encrypted off-node
  database backups and scheduled restore verification.
- [docs/project-history-summary.md](docs/project-history-summary.md):
  public-safe architectural history.

## Local Development

Local development should use local-only configuration and ignored env files:

```bash
cp .env.example .env
python3 -m pip install -e '.[dev]' -c requirements.lock
python3 -m ruff check .
pytest -q
```

Docker Compose is available for local control-plane development. It is not a
production deployment path.

## Host Runtime

The supported deployment shape is a Linux host using systemd, Docker and host
networking. Public bundles are materialized with operator-provided private
state; the repository never contains live credentials or rendered production
configuration.

Run `make host-check` to validate the public Entry/Endpoint bundles, WGWS
WebSocket routing, ShadowTLS HAProxy handoff, Telemt loopback API and peer-sync
unit before packaging.

## Security Posture

Public examples use placeholders, loopback values or documentation-reserved
network ranges. Do not replace them with live coordinates in this repository.

Before making a file public, check whether it reveals a production endpoint,
route shape, credential, host policy, provider detail or generated user
artifact. If it does, keep it out of this repository.

## Documentation

- [docs/security-boundary.md](docs/security-boundary.md): public/private
  boundary rules.
- [docs/operator-workflow.md](docs/operator-workflow.md): safe high-level
  workflow for contributors and operators.
- [docs/release-checklist.md](docs/release-checklist.md): public release review
  checklist.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
