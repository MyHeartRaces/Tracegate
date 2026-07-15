# Changelog

## Unreleased

## v3.1.7 - 2026-07-15

- Replaced the obsolete cluster rollout contract with the actual native-systemd
  activation, health-gate and rollback invariants used by production.
- Made non-host agent runtime modes fail closed and removed the dead gateway
  readiness alert that queried metrics unavailable outside the retired cluster.

## v3.1.6 - 2026-07-15

- Treat the expected Docker SIGTERM exit status as successful in every
  container-backed systemd unit, preventing false service-failure events during
  native host deployments and controlled restarts.

## v3.1.5 - 2026-07-15

- Made native systemd the only supported production host runtime and removed
  the unused parallel Compose control plane.
- Added versioned application venv staging, atomic runtime activation, real
  symlink-based rollback, role health gates and tracked Entry/Endpoint units.
- Made the host archive self-contained with its application wheel, build
  identity and standard-library-only preflight checks.
- Added tag-driven immutable release publication and full release artifact
  inspection to CI.
- Restored the tracked Endpoint firewall contract for Hysteria Salamander on
  UDP/8444.

## v3.1.3 - 2026-07-14

- Replaced version-locked data-plane container references with rolling `latest`
  upstream images and mandatory pulls at service start for Xray, Hysteria,
  ShadowTLS, WSTunnel, Telemt, Prometheus and Grafana.
- Moved SS2022 termination into the managed Xray runtime so per-account clients
  are hot-added, revoked and exported through the existing Xray traffic metrics;
  the retired shared-password `ssserver` must no longer run beside Xray.
- Completed the host release installer with canonical systemd units, root-only
  ShadowTLS environment materialization and non-root Telemt runtime ownership.
- Corrected the Telemt metrics listener collision with Prometheus and packaged
  the Alembic migration tree and public runtime bundles in the wheel.
- Revoked and removed all previously issued Telegram Proxy grants before the
  production rollout; affected users must explicitly request fresh access.

## v3.1.2 - 2026-07-13

- Pinned the bundled Xray runtime binary by version and SHA-256 so branch and
  tag image builds cannot silently consume a different upstream release.

## v3.1.1 - 2026-07-13

- Retired the k3s/Helm deployment tree and replaced its release dependency with
  a host-runtime archive, host private preflight/reload commands and a
  deterministic `host-check` gate.
- Added the missing materialized Endpoint HAProxy route for the standalone
  ShadowTLS v3 listener while retaining WGWS HTTP/1.1 upgrade validation.

- Raised account capacity to four devices and capped each device at five
  connections while retaining the two-slot revision contract.
- Moved account-bound Telegram Proxy access into the Connections menu and kept
  block/revoke flows fail-closed for its per-user Telemt secret.
- Reorganized profile creation into Direct, Chain, Backup and Experimental,
  restoring SS2022+ShadowTLS v3 and WGWS without changing existing runtime
  profile identifiers or importer artifact filenames.
- Updated exported client labels to the `Tracegate-*` naming scheme; already
  issued configurations remain usable and adopt the new label on reissue.
- Added account-scoped Telemt traffic and per-peer WGWS metrics, corresponding
  Grafana panels, and fixed dashboard traffic presentation to decimal MB/MB/s.

## v3.1.0 - 2026-07-12

- Route newly issued Chain connections through Entry REALITY with an operator-selected camouflage SNI, while retaining existing WebSocket Chain revisions as a legacy compatibility profile.

- Replaced the native Telegram lane with pinned Telemt FakeTLS, real-site TLS
  masking, per-user hot-reloaded secrets and in-container health checks. Native
  Telegram still cannot use WebSocket transport; WSS remains a TUN/router lane.
- Added a Direct Hysteria2 Salamander option alongside Gecko on a dedicated
  UDP listener, including a bot selection menu and compatible client exports.
- Fixed Backup-Shadowsocks delivery in the Telegram bot: new revisions now include
  the generated `ss://` URI and QR code alongside the preferred sing-box JSON file.

### Transport Architecture

- Replaced VLESS/REALITY XHTTP with RAW/TCP + XTLS Vision.
- Replaced the Entry-to-Endpoint XHTTP pool with an SS2022/ShadowTLS v3 TCP
  primary and an independent Hysteria2/Gecko fallback.
- Migrated Direct Hysteria2 and internal Hysteria2 contracts from Salamander
  to Gecko, with minimum client/runtime version checks.
- Fixed the Entry ShadowTLS backhaul probes to check their loopback-only
  listener instead of the pod address.
- Hardened exclusive SNI pools to reject `max.ru` and sibling subdomains from
  the same root, and kept private catalog overrides explicit in production.
- Fixed Xray API hot-reload to preserve `xtls-rprx-vision` when adding
  VLESS/REALITY users, preventing live users from diverging from the persisted
  runtime configuration.
- Routed both VLESS gRPC and WebSocket backup profiles through the configured
  Cloudflare Endpoint hostname instead of exporting a direct origin-shard dial
  target that the origin firewall correctly rejects.
- Replaced the disabled Cloudflare Universal Entry profile with direct
  VLESS WebSocket+TLS Chain ingress on Entry; Entry traffic still uses the
  independent ShadowTLS/Hysteria2 backhaul pool and Endpoint-only egress.

## v3.0.0 - 2026-06-27

### Runtime and Deployment

- Aligned the public k3s chart with the current production runtime surface:
  Grafana OTP routing, observability manifests, WGWS/WireGuard peer sync,
  Shadowsocks-2022 + ShadowTLS handling and role-aware runtime reload hooks.
- Moved production-specific Grafana host routing and agent CORS origins behind
  private values instead of hardcoded live domains.

### Bot and Observability

- Refreshed the welcome/help flow, split application links from the main guide
  message and kept Grafana access behind bot-issued one-time links.
- Tuned Grafana alert delivery so non-critical signals do not create bot noise.

### Public Repository Hygiene

- Rewrote public documentation around a clear public/private boundary.
- Replaced live-domain and live-address test fixtures with reserved examples.
- Kept client configuration artifacts out of the public repository.

## v2.2.1 - 2026-04-28

### Runtime and Deployment

- Added the `gateway.entrySmall` k3s profile for 1 GB / 1 vCPU Entry nodes.
- Kept Entry-small on the full V1/V2/V3 production surface and rejected overlays that omit V3.
- Removed the legacy plain-host deployment kit, replacement workflow and old 2.1 architecture note from the public repository.
- Dropped the systemd bundle artifact from the image workflow.

### Validation

- Added render/preflight checks for Entry-small resource budgets, rollout mode, WGWS/lab-surface rejection and required V3.

## v0.6.1 - 2026-04-05

Changes included in this release were landed on 2026-04-05.

### Bot and Admin UX

- Added targeted admin access revocation by `telegram_id` without blocking the user account.
- Added optional user notification for targeted access revocation, with explicit `Да/Нет` choice in the admin bot flow.
- Blocked access revocation for `superadmin` targets in both bot and API flows.

### Packaging and Docs

- Bumped project version to `0.6.1`.
- Refreshed README release references for the `0.6.1` patch release.

## v0.6.0 - 2026-04-04

Changes included in this release were landed between 2026-03-05 and 2026-04-04.

### Gateway and Interconnect

- Hardened gateway startup and rollout behavior with startup probes for entry muxes and safer secret/config rollouts.
- Increased entry-mux capacity and fixed fallback routing, transit host derivation and self-heal for `VPS-E -> VPS-T`.
- Added dedicated `xray-b2` runtime on `VPS-E` for managed B2 REALITY inbounds and kept grouped REALITY routing local when needed.
- Added adaptive transit selector on `VPS-E` with health probing, hysteresis and metrics.
- Added `Hysteria` backplane, then upgraded it with pinned images, valid SAN handling and TCP encapsulation through `VPS-T entry-mux :443`.
- Added dedicated `WireGuard` backplane on `wgs2s` with explicit endpoint override support.
- Bundled Xray geodata into the app image and aligned host DNS behavior with the live `hostNetwork` topology.
- Stopped unnecessary Hysteria restarts on user churn and fixed reload behavior.

### Bot and Admin UX

- Added permanent bot blocks and clearer block/unblock notifications.
- Cleaned up admin copy and menu labels.
- Kept blocked users visible in admin tools while fixing active-user filtering.
- Added user feedback flow in the bot with relay to admins and targeted bans from the feedback message.
- Added admin registry views for all bot users, active users and blocked users.

### Ops and Observability

- Debounced noisy transient OPS alerts for metrics-server gaps, short node flaps and brief component health drops.
- Stabilized Grafana joins and availability alerts.
- Added gateway restart/startup protections that reduce false-positive rollout noise.

### Packaging and Docs

- Bumped project version to `0.6.0`.
- Updated chart/app versions and default image tags to `0.6`.
- Refreshed root and k3s README files to match the current gateway topology and interconnect options.
