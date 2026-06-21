# Architecture

System-level map of Tracegate: how control-plane decisions become gateway
runtime, the Entry/Endpoint topology, and the deployment phases. This is the
generic, public-safe view; live coordinates live only in the private operator
repository.

## 1. Two planes, one contract

Tracegate separates **control-plane decisions** from **gateway execution**:

```
Telegram bot ─┐
              ├─► FastAPI control plane ─► DB (users, devices, connections, revisions, outbox)
HTTP clients ─┘            │
                           ▼
                     Dispatcher (batches pending outbox work)
                           │  HTTP + agent_auth_token
                           ▼
                     Gateway agent (per role) ─► reconciles desired runtime state
                           │
                           ▼
        Xray / Hysteria2 / ShadowTLS / WireGuard / Telemt / HAProxy / nginx (in-pod)
```

- **API** (`src/tracegate/api`) owns users, devices, connections, revisions, SNI
  catalog, MTProto grants, and admin actions.
- **Bot** (`src/tracegate/bot`) is the Telegram-first user/admin UI.
- **Dispatcher** (`src/tracegate/dispatcher`) turns control-plane changes into
  batched gateway work via a transactional outbox.
- **Agent** (`src/tracegate/agent`) reconciles role-specific desired state onto
  the data-plane processes and reports health.
- **Services** (`src/tracegate/services`) hold the domain logic: config builders,
  IPAM, revisions, pseudonyms, SNI catalog, MTProto, runtime contracts.
- **Client export** (`src/tracegate/client_export`) renders user-facing profiles
  (links, JSON, bundles) for the supported clients and Tracegate-Router.

The binding rule (`runtime-contract`): *user and connection mutations use live
APIs or read-through state; reload hooks are base/topology only*. This is the
"zero-restart" invariant — issuing/revoking a user must not restart a transport.

## 2. Final topology (Tracegate 3, `entry-endpoint` mode)

```
Direct/Backup client ─► one of three Endpoint shard IPs ─► Endpoint pod ─► service/egress IP ─► Internet
Entry Chain client   ─► one Entry IP ─► Entry pod ─► XHTTP/REALITY or Hysteria2 backhaul ─► Endpoint ─► Internet
MTProto client       ─► Entry tcp/443 ─► Entry tunnel ─► Endpoint-local Telemt ─► Telegram
```

**Endpoint** has four addresses:

1. **Service / egress IP** — control surfaces and the *only* client internet
   egress identity. Client ports are rejected/dropped here.
2. **Three shard IPs** — direct Reality, Hysteria2, and Backup ingress. HAProxy
   binds TCP only to active/draining shard IPs.

**Entry** has one address, never provides client egress, and fails closed when
the Endpoint route is unavailable.

> Naming note: the internal Helm role `gateway.roles.transit` is the **Endpoint**
> compatibility name. There is no separate "Transit" server in new production;
> "transit" in templates/tests == Endpoint.

## 3. Pod-only data plane

Every Endpoint data-plane process runs in the single `gateway-transit` k3s pod as
sidecar containers: `agent`, `xray`, `hysteria`, `shadowtls-v3`, `wireguard` +
`wstunnel`, `telemt` (MTProto), `haproxy`, `nginx`. `gateway-state` uses a PVC;
decoy content uses a ConfigMap/PVC. HostPath is forbidden by
`architecture.podRuntimeOnly`. Host nftables and SNAT are **prerequisites, not
runtimes** — they are rendered by the host firewall scripts (see
[13-network-boundary-and-egress.md](13-network-boundary-and-egress.md)).

Sidecars chain over loopback: HAProxy terminates the public TCP/443 SNI demux and
forwards to in-pod backends (`127.0.0.1:<port>`); nginx is the TLS adapter for WS
/ gRPC / WireGuard-WS; Xray handles VLESS/Reality and SS-2022; a standalone
Hysteria2 owns UDP/443; ShadowTLS fronts SS-2022.

## 4. Deployment phases

- **`endpoint-first`** — only the Endpoint gateway is rendered; Direct and Backup
  profiles are validated; Telemt is staged but has no public frontend.
- **`entry-staged`** — Entry is brought up under validation gates.
- **`full`** — Entry gateway, Universal Entry backhauls, and MTProto client
  ingress are enabled after Endpoint acceptance.

The private `deploy.sh` enforces the gates: it refuses to roll out unless the
Endpoint ingress/egress firewalls (and, beyond `endpoint-first`, the Entry origin
firewall) are active.

## 5. Excluded / legacy surfaces

Audited for inertness, **not** part of the new-production contract: NaiveProxy,
Mieru, Zapret2 host-wide NFQUEUE, the `transitRouter` role, MasterDNS, host
data-plane binaries, and LUKS runtime markers. They remain behind disabled values
and `architecture.mode != entry-endpoint` guards. The chart's `secrets.yaml`
fails the render closed if these are combined with `entry-endpoint` mode in
unsupported ways.

## 6. Component → directory map

| Concern | Path |
|---------|------|
| Control-plane API | `src/tracegate/api` (routers in `api/routers`) |
| Telegram bot | `src/tracegate/bot` |
| Dispatcher | `src/tracegate/dispatcher` |
| Gateway agent | `src/tracegate/agent` |
| Domain services | `src/tracegate/services` |
| Client export | `src/tracegate/client_export` |
| Data model / DB | `src/tracegate/models.py`, `db.py`, `alembic/` |
| Settings | `src/tracegate/settings.py`, `constants.py` |
| SNI catalog | `src/tracegate/staticdata/sni_catalog.yaml` |
| Helm chart | `deploy/k3s/tracegate` |
| Host firewalls / preflight | `deploy/k3s/*.py` |
| Generic bundles | `bundles/` (reference templates, not the k3s render) |

See the per-subsystem docs:
[11-control-plane-and-data-model.md](11-control-plane-and-data-model.md),
[12-protocols-and-dpi.md](12-protocols-and-dpi.md),
[13-network-boundary-and-egress.md](13-network-boundary-and-egress.md),
[14-secrets-and-crypto.md](14-secrets-and-crypto.md),
[15-deployment-and-helm.md](15-deployment-and-helm.md),
[16-observability.md](16-observability.md),
[17-client-export-and-router.md](17-client-export-and-router.md).
