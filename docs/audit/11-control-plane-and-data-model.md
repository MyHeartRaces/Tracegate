# Control Plane & Data Model

The control plane owns identity and intent; the data plane executes it. This doc
covers the API, bot, dispatcher, agent, and the database model that ties them
together.

## 1. Components

### API (`src/tracegate/api`)
FastAPI app; routers under `api/routers`: `auth`, `users`, `devices`,
`connections`, `revisions`, `nodes`, `sni`, `client_configs`, `dispatch`,
`mtproto_access`, `admin`, `bot_messages`, `grafana`, `health`, `metrics`.
Auth via `security.py` (scoped bearer / `x-api-token`; bootstrap token). HTTP
observability middleware is installed on every app.

### Bot (`src/tracegate/bot`)
Telegram-first UI (aiogram-style): onboarding, device management, profile
delivery, admin tools. Authorisation is a role hierarchy
(`user` < `admin` < `superadmin`, `bot/access.py` + `services/user_roles.py`),
with per-user temporary/permanent bot blocks and a mandatory welcome gate. The
bot calls the API with `bot_api_token`. Polling or webhook mode
(`bot_webhook_secret_token` validates Telegram's header).

### Dispatcher (`src/tracegate/dispatcher`)
Polls the transactional **outbox**, batches pending work
(`dispatcher_batch_size`, `dispatcher_poll_seconds`), applies it to gateway agents
with a lock TTL and bounded attempts, and runs periodic ops checks (Telegram
alerts, outbox retention purge). mTLS to agents is supported
(`dispatcher_client_cert/key/ca`).

### Agent (`src/tracegate/agent`)
Per-role reconciler. Reads desired state, applies rendered runtime material
(`handlers.py`, `reconcile.py`), can add/remove Xray users live via the gRPC
HandlerService (`agent_xray_api_enabled`) for zero-restart issuance/revocation,
manages Hysteria clients, transit assignment, egress isolation, and reports
health (`/v1/health`, `/v1/live`). System interaction is in `agent/system.py`
(see F1/F2 in the findings).

### Services (`src/tracegate/services`)
Domain logic: `config_builder.py` / `xray_centric.py` / `materialized_bundles.py`
(runtime rendering), `ipam.py` (address leases), `revisions.py`, `connections.py`,
`connection_profiles.py`, `sni_catalog.py`, `mtproto*.py`, `pseudonym.py`,
`client_config_tokens.py`, `decoy_auth.py`, `runtime_contract.py`,
`runtime_preflight.py`, `grace.py`, `user_cleanup.py`, `outbox.py`.

## 2. Data model (`src/tracegate/models.py`)

| Entity | Table | Role |
|--------|-------|------|
| `User` | `tg_user` | Telegram user, role, bot-block state |
| `MTProtoAccessGrant` | `mtproto_access_grant` | Telegram-only MTProto access |
| `Device` | `device` | A phone/laptop/client (one profile per device discipline) |
| `Connection` | `connection` | A profile bound to a device |
| `ConnectionRevision` | `connection_revision` | Versioned config inside a connection (activation/rotation/revocation unit) |
| `IpamPool` / `IpamLease` | `ipam_pool` / `ipam_lease` | Address/SNI lease management |
| `NodeEndpoint` | `node_endpoint` | Gateway node/endpoint registry |
| `OutboxEvent` / `OutboxDelivery` | `outbox_event` / `outbox_delivery` | Transactional outbox + per-target delivery |
| `ApiToken` | `api_token` | Scoped, hashed API tokens |
| `GrafanaOtp` | `grafana_otp` | One-time Grafana handoff codes |
| `BotMessageRef` | `bot_message_ref` | Bot message bookkeeping (e.g. `/clear`) |

Migrations are in `alembic/`.

## 3. Core lifecycle: the revision model

The unit of change is the **revision**, not the connection. To get a new
`(Endpoint shard, SNI)` pair or update parameters, the user *re-issues a revision*
rather than creating duplicates. This keeps one profile per device, supports
clean rotation/drain, and is the basis of the zero-restart invariant: issuing or
revoking a revision is a live API/state operation, never a transport restart.

```
User ─► Device ─► Connection ─► ConnectionRevision (active | draining | revoked)
                                   │ writes OutboxEvent
                                   ▼
                            Dispatcher ─► Agent ─► Xray HandlerService (live add/remove)
```

## 4. Transactional outbox

State mutations enqueue `OutboxEvent`s in the same DB transaction; the dispatcher
delivers them to the right gateway target(s) (`OutboxDelivery`) with retries,
lock TTL, and a max-attempts ceiling. Retention is purged on a schedule
(`dispatcher_outbox_retention_*`). This decouples control-plane writes from
gateway availability and gives at-least-once delivery with idempotent apply.

## 5. IPAM & SNI leasing

`ipam.py` + the SNI catalog assign free `(shard IP, SNI)` pairs and prevent reuse
while a revision is active (`exclusive_sni_pairs`). For direct Reality, the user
does not choose a provider/SNI — the control plane picks from the configured
12–15-domain pool. This keeps service discovery (WHOIS/DNS) separate from the
active client listener set.

## 6. Grace & cleanup

`grace.py` and `user_cleanup.py` handle draining and pruning: draining is explicit
and does not silently assign new users; empty users (no devices/connections) can
be auto-pruned (`users_auto_prune_empty`). Revocation flows through the
control-plane APIs so individual grants can be pulled without disturbing others.
