# Changelog

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
