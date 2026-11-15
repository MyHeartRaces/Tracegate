<p align="center">
  <img src="docs/assets/tracegate-wordmark.svg" alt="TRACEGATE" width="720">
</p>

Tracegate is a managed privacy-gateway control plane for a small, invited user
group. It issues per-device connection profiles from a Telegram bot, runs a
two-node relay (Entry and Endpoint) on plain Linux hosts with systemd, and
keeps every issued connection working across releases.

This repository is the public source tree: application code, migrations,
tests, generic templates and safe documentation. Live coordinates, operator
scripts, production overlays, decoy content, client exports and secrets are
intentionally outside it.

## Capabilities

Profiles are created and re-issued from the bot, one subscription per device,
and import with one tap in common clients:

| Profile | Path | Notes |
| --- | --- | --- |
| **Chain** | VLESS + REALITY to Entry, then the Entry -> Endpoint backhaul | The main profile; traffic exits through Endpoint. |
| **Direct VLESS** | VLESS + REALITY (XTLS Vision) straight to Endpoint | New issuance uses a dedicated listener; older profiles keep theirs. |
| **Direct Hysteria 2** | QUIC straight to Endpoint | Salamander or Gecko obfuscation chosen at creation, verified TLS, server port hopping on by default. |
| **Telegram proxy** | Telemt FakeTLS behind Entry | Reachable only through Entry; no Telegram route is exposed on Endpoint. |

Re-issuing a VLESS or Hysteria profile silently moves it to the current
scheme; Hysteria keeps the obfuscation it was created with. Retired families
(WireGuard-over-WebSocket, client SS2022+ShadowTLS, VLESS WebSocket/gRPC, Chain
Hysteria) are revoked by migrations and refused by the API and the bot.

## Architecture

- **Entry** is the ingress node. HAProxy demultiplexes TLS by SNI to the Entry
  Xray REALITY inbounds and the Telegram route. Chain traffic leaves Entry over
  a ShadowTLS-based backhaul pool with a REALITY fallback leg. A host-wide
  traffic cap (outgoing shaping plus an incoming policer) keeps Entry inside its
  hosting allowance.
- **Endpoint** is the egress node with separate ingress and egress addresses.
  It runs the Direct listeners, the backhaul terminators, Telemt, and the
  control plane: FastAPI API, dispatcher, aiogram bot, PostgreSQL, Prometheus
  and Grafana.
- **Agents** on both nodes reconcile role-specific runtime state, expose
  health, and report metrics. The dispatcher turns control-plane changes into
  agent work items.
- **Engines** (Xray, Hysteria, ShadowTLS, Telemt, Prometheus, Grafana) run as
  containers pinned by digest in a local artifact store. Restarts never pull.
  A nightly update supervisor discovers new releases, lets each digest soak,
  checks its configuration, and activates it one unit at a time behind
  authenticated probes with automatic rollback; anything it cannot verify is
  queued for the operator.
- **Alerts** from Grafana reach the operator through the bot.

## Releases and deployment

Each tagged release builds a host-runtime package on GitHub Actions. A host
installs it side by side with the running release, migrates the database (with
a backup first), switches atomically, restarts the role's units and rolls back
by itself if health checks fail. See
[docs/operator-workflow.md](docs/operator-workflow.md) and
[docs/release-checklist.md](docs/release-checklist.md); release notes live in
[docs/releases](docs/releases) and [CHANGELOG.md](CHANGELOG.md).

## Layout

- [src/tracegate](src/tracegate): API, agent, bot, dispatcher, renderers,
  engine artifact store and update supervisor.
- [deploy/host](deploy/host): native host install, deploy, rollback, network
  queueing, Hysteria port hopping and the engine registry.
- [deploy/systemd](deploy/systemd): systemd units for engines, agents and
  timers.
- [bundles](bundles): generic Entry and Endpoint runtime templates.
- [alembic](alembic): database migrations.
- [tests](tests): behaviour, rendering, migration and host-runtime coverage.
- [docs](docs): public documentation without live deployment coordinates.

## Local development

Use local-only configuration and ignored env files:

```bash
cp .env.example .env
python3 -m pip install -e '.[dev]' -c requirements.lock
python3 -m ruff check .
pytest -q
```

PostgreSQL compatibility tests run when `TRACEGATE_TEST_POSTGRES_URL` points to
a disposable database. `make release-check` runs lint, tests, the host-runtime
contract checks and the public-release privacy scan. Docker Compose is
available for local control-plane work only; it is not a deployment path.

## Repository Boundary

Public-safe material belongs here: source code and migrations, generic
templates with placeholder values, deterministic tests and non-live fixtures,
and high-level documentation.

Sensitive material does not belong here:

- real domains, public addresses, ports, node names or provider metadata;
- production values, private overlays and rendered manifests;
- runtime secrets, credentials and key material;
- decoy site assets and live bot copy;
- generated client imports, QR payloads or runtime state snapshots;
- production deployment automation.

Public examples use placeholders, loopback values or documentation-reserved
address ranges. Before making a file public, check whether it reveals a
production endpoint, route shape, credential, host policy, provider detail or
generated user artifact; if it does, keep it out. See
[docs/security-boundary.md](docs/security-boundary.md).

## License

GPL-3.0-only. See [LICENSE](LICENSE).
