<p align="center">
  <img src="docs/assets/tracegate-wordmark.svg" alt="TRACEGATE" width="720">
</p>

Tracegate is a managed privacy-gateway control plane. It coordinates user
access, device profiles, gateway runtime state and operational visibility for a
multi-role relay stack.

This repository is the public source tree. It contains application code,
tests, generic templates and safe documentation. Live deployment coordinates,
operator scripts, production overlays, decoy content, client exports and
secret material are intentionally outside this tree.

## Capabilities

Tracegate provides:

- a Telegram-first user flow for onboarding, device management and per-device
  profile delivery with one-tap import;
- a FastAPI control plane backed by durable database state;
- a dispatcher that turns control-plane changes into gateway work items;
- node agents that apply rendered runtime material and report health;
- client export builders for the supported profile families;
- revision tracking for activation, re-issue, rotation and revocation, so
  issued connections keep working across releases and retired profile
  families are revoked explicitly;
- an engine artifact store that pins runtime images by digest and an update
  supervisor that activates new engine versions only after verification, with
  automatic rollback;
- native systemd host releases with health-gated deploy and rollback;
- Grafana-based visibility and operator alerting;
- tests for host runtime contracts, rendering, exports, migrations, bot
  behaviour and revision logic.

## Architecture

Tracegate separates control-plane decisions from gateway execution:

- the API owns users, devices, connections, revisions and admin actions;
- the bot exposes user and admin workflows;
- the dispatcher batches pending runtime changes;
- gateway agents reconcile role-specific desired state;
- renderers build runtime profiles and client exports from structured
  connection data;
- validation tools check public bundle safety and private overlay shape
  without printing secret values.

The concrete topology, transports and routing of a deployment are supplied by
operator-provided private state and are not described here.

## Layout

- [src/tracegate](src/tracegate): application, agent, bot, dispatcher and
  service code.
- [deploy/host](deploy/host): native host install, deploy and rollback
  contract.
- [deploy/systemd](deploy/systemd): systemd units for runtime helpers.
- [bundles](bundles): generic runtime bundle templates.
- [alembic](alembic): database migrations.
- [tests](tests): automated coverage for behaviour and generated artifacts.
- [docs](docs): public documentation that avoids live deployment coordinates.

## Local Development

Use local-only configuration and ignored env files:

```bash
cp .env.example .env
python3 -m pip install -e '.[dev]' -c requirements.lock
python3 -m ruff check .
pytest -q
```

PostgreSQL compatibility tests run when `TRACEGATE_TEST_POSTGRES_URL` points to
a disposable database. `make release-check` runs lint, tests, host checks and
the public-release privacy scan. Docker Compose is available for local
control-plane development only; it is not a deployment path.

## Repository Boundary

Public-safe material belongs here:

- source code and migrations;
- generic templates with placeholder values;
- deterministic tests and non-live fixtures;
- high-level documentation.

Sensitive material does not belong here:

- real domains, public addresses, ports, node names or provider metadata;
- production topology, route shape and per-node service placement;
- production values, private overlays and rendered manifests;
- runtime secrets, credentials and key material;
- decoy site assets and live bot copy;
- generated client imports, QR payloads or runtime state snapshots;
- production deployment automation.

Public examples use placeholders, loopback values or documentation-reserved
address ranges. Before making a file public, check whether it reveals a
production endpoint, route shape, credential, host policy, provider detail or
generated user artifact; if it does, keep it out. See
[docs/security-boundary.md](docs/security-boundary.md),
[docs/operator-workflow.md](docs/operator-workflow.md) and
[docs/release-checklist.md](docs/release-checklist.md).

## License

GPL-3.0-only. See [LICENSE](LICENSE).
