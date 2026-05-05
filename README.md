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
- a k3s-oriented Helm chart with public validation guards;
- tests for chart rendering, runtime contracts, bot behavior, exports,
  revision logic and observability formatting.

## Repository Boundary

Public-safe material belongs here:

- source code and migrations;
- generic Helm templates and placeholder values;
- deterministic tests and non-live fixtures;
- public bundle templates;
- high-level operator documentation.

Sensitive material does not belong here:

- real domains, public addresses, ports, node names or provider metadata;
- production values and rendered manifests;
- decrypted Kubernetes Secrets or plaintext disk encryption keys;
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
- validation tools check public chart safety and private overlay shape without
  printing secret values.

Entry and Transit roles are treated as protected runtime surfaces. Endpoint
support remains part of the model, but endpoint-specific live details stay out
of public documentation.

## Layout

- [src/tracegate](src/tracegate): application, agent, bot, dispatcher and
  service code.
- [deploy/k3s/tracegate](deploy/k3s/tracegate): public Helm chart and template
  guards.
- [bundles](bundles): generic runtime bundle templates.
- [alembic](alembic): database migrations.
- [tests](tests): automated coverage for behavior and generated artifacts.
- [docs](docs): public documentation that avoids live deployment coordinates.

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

## Helm Chart

The public chart is intended for rendering, validation and review. It includes
guards for external Secrets, private profile material, decoy content, gateway
traffic shaping and encrypted Entry/Transit runtime storage.

Use placeholder values for public review. Use operator-managed overlays for
real environments.

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
- [docs/node-encryption-runbook.md](docs/node-encryption-runbook.md): generic
  Entry/Transit encrypted runtime storage procedure.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
