<p align="center">
  <img src="docs/assets/tracegate-wordmark.svg" alt="TRACEGATE" width="720">
</p>

Tracegate 2.2 is a managed privacy-gateway control plane. It provides a
Telegram bot, FastAPI backend, node agent, runtime renderers, observability
helpers and a production Helm chart.

The public repository contains source code, tests, safe examples and deployment
scaffolding. Operator-private values, live hostnames, live addresses, decoy
sites, raw client exports and decrypted secret material are intentionally kept
outside this repository.

Release notes live in [CHANGELOG.md](CHANGELOG.md).

## What Tracegate Does

Tracegate issues and manages connection profiles through a Telegram-first user
flow:

- register a user in the bot;
- add a device and select the active device;
- create a connection profile for that device;
- receive an import link, QR code or client-specific export;
- rotate, activate or revoke revisions without manually editing server state.

The system supports several profile families for TCP, UDP, compatibility and
Telegram Proxy access. The public docs name profile families only at product
level; production endpoints and routing details belong to the private deployment
overlay.

## Current Public Surface

- Telegram bot onboarding, device inventory, connection issuance and support
  flows.
- Admin bot flows for access management, moderation, announcements and feedback.
- API control plane with durable PostgreSQL state.
- Dispatcher for retryable runtime delivery.
- Node agent for health checks, metrics and applying rendered runtime material.
- Runtime builders for the active Tracegate 2.2 profile families.
- Grafana OTP handoff, role-aware dashboards and bot-delivered admin alerts.
- Helm chart for k3s-style production deployments.
- Validation and test coverage for chart rendering, runtime contracts, bot text,
  exports, revision rules and observability behavior.

## Public vs Private Boundary

Public repository:

- application source code;
- public runtime templates with placeholders;
- tests and safe fixtures;
- safe example values;
- high-level operator documentation;
- CI and local development helpers.

Private deployment repository:

- real production values;
- encrypted Kubernetes Secrets;
- live TLS and profile material;
- decoy HTML/CSS/JS assets;
- raw client configuration artifacts;
- host policy, node inventory and operational runbooks that reveal deployment
  shape;
- generated state snapshots that are useful for operations but unsuitable for a
  public repo.

Do not move private deployment material into this repository. If a document or
example would reveal enough information to fingerprint the live deployment, keep
it in the private repository instead.

## Repository Layout

- [src/tracegate](src/tracegate): application code.
- [deploy/k3s/tracegate](deploy/k3s/tracegate): Helm chart and public templates.
- [bundles](bundles): public runtime bundle templates.
- [alembic](alembic): database migrations.
- [tests](tests): unit, integration-style and chart validation tests.
- [docs](docs): safe public documentation.

## Local Development

Use Docker Compose for the local control-plane stack:

```bash
cp .env.example .env
docker compose up --build
docker compose exec api tracegate-init-db
pytest -q
```

Local development is intended for control-plane behavior, bot flows, export
generation, chart rendering and validation logic. Production overlays should be
tested through ignored private values and encrypted secrets, not committed
examples.

## Deployment Model

Tracegate ships one Helm chart. The chart is public, but production inputs are
private:

```bash
helm template tracegate ./deploy/k3s/tracegate --namespace tracegate
helm upgrade --install tracegate ./deploy/k3s/tracegate \
  --namespace tracegate \
  -f /path/to/private-values.yaml
```

Use [deploy/k3s/README.md](deploy/k3s/README.md) for chart workflow and release
gates. Keep real overlays, decoy assets and operational host policy in the
private deployment repository.

## Observability

Grafana access is issued by the bot as a short-lived one-time link. User scope
shows per-user connection statistics and basic service health. Admin scope adds
operator dashboards, inventory views and alert routing.

Alert delivery is intentionally filtered so bot notifications stay focused on
material incidents and recoveries. Tuning values and live dashboard endpoints
belong to the private overlay.

## Validation

Run the standard local checks:

```bash
python3 -m ruff check .
pytest -q
```

Run the deployment release gate before promoting chart changes:

```bash
deploy/k3s/deploy-ready-check.sh
```

The strict production gate accepts ignored private values through environment
variables and should be run from the operator environment.

## Documentation

- [docs/operator-workflow.md](docs/operator-workflow.md): safe operational flow
  for public contributors.
- [docs/security-boundary.md](docs/security-boundary.md): what belongs in public
  Git and what stays private.
- [docs/release-checklist.md](docs/release-checklist.md): public release and
  verification checklist.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
