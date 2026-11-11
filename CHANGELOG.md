# Changelog

## v4.0.0 - 2026-11-12

- Engine units never pull at start: every engine unit starts the image
  recorded by immutable digest in the local artifact store
  (`/var/lib/tracegate/artifacts`), verified by a read-only pre-start check,
  so a restart can never change an engine version and an unreachable registry
  no longer keeps a service down.
- Added the tracked engine artifact registry `deploy/host/artifacts.json` and
  the `tracegate-artifacts` operator CLI (`components`, `status`, `capture`,
  `stage`, `promote`, `rollback`, `verify`); `stage` is the only command that
  contacts a registry.
- `tracegate-host-deploy deploy` now captures the running engine digests and
  verifies the store before changing any state, and both host scripts install
  the `tracegate-artifact-verify` helper.
- Reapply the `fq` queue discipline after the default-route interface becomes
  available, so BBR pacing does not silently remain on the boot-time
  `fq_codel` discipline after a live runtime deployment.
- Three-state Grafana alerting: missing metrics and failed rule queries no
  longer render as service failures. Rules that used `noDataState: Alerting`
  now report `NoData` and every rule uses `execErrState: Error`; the webhook
  renders these as "NO DATA" and "QUERY ERROR", and neither ever escalates as
  critical regardless of its severity label. The backhaul egress expressions
  no longer map absent probe metrics to "all Chain egress failed".
- New warning rule `tg-ops-backhaul-probe-nodata` ("NO DATA: backhaul egress
  probe metrics missing") reports which backhaul channel's egress probe
  metrics are absent. Rule changes take effect only after the operator
  re-runs the Grafana bootstrap on the host, which is a separate approved
  step.
- Removed two client transport families: WireGuard over WebSocket (WGWS) and
  the client Shadowsocks-2022 + ShadowTLS v3 profile. Neither can be issued;
  existing rows still load, display and can be revoked, and migration
  `c3a5e9d1f204` revokes the remaining ones. Their units
  (`tracegate-shadowtls`, `tracegate-wireguard`, `tracegate-wireguard-sync`,
  `tracegate-wstunnel-wireguard`) are stopped and removed by the next host
  deploy. The client `ss2022-in` inbound, its HAProxy route on TCP/443, the
  `/wgws` nginx path and the WireGuard forward/NAT rules are gone.
- The Entry-to-Endpoint backhaul, which also uses Shadowsocks-2022 inside
  ShadowTLS v3, is unchanged; a render-invariance test with a golden file
  taken before the removal guards it.
- A private profile handoff written by a pre-upgrade agent that still lists
  entries of the retired families now produces a warning instead of a
  validation error; the next agent reconcile rewrites it empty.
- Port model: Endpoint TCP/8443 is now a declared public listener. The
  Endpoint HAProxy frontend binds TCP/443 and TCP/8443 with identical SNI
  dispatch, the Endpoint firewall template accepts TCP/8443, and the Endpoint
  runtime contract, health checks, handoffs and preflight expect
  `listen tcp/8443`. UDP/8443 stays dropped on both roles; Entry keeps TCP/8443
  closed. The legacy MTProto fallback mode (`MTPROTO_PUBLIC_PORT=8443`) keeps its
  `listen tcp/8443 mtproto fallback` check.
- Direct VLESS/REALITY revisions are issued on `REALITY_DIRECT_PORT` (default
  8443), including re-issues of existing connections; the previous revision
  stays active in the second slot until the next re-issue. Chain stays on
  TCP/443 and the WebSocket/gRPC backups are unchanged.
- Telegram Proxy in the Entry tunnel mode is delivered only through Entry on
  TCP/443; the direct Endpoint backup route is no longer delivered. With
  `MTPROTO_DIRECT_BACKUP_HOST` set, Endpoint keeps routing the FakeTLS SNI on
  TCP/443 only (never TCP/8443), so backup links users saved earlier keep
  working. Entry never listens on TCP/8443 outside the legacy fallback mode.
  Secrets are unchanged.
- Hysteria2 port hopping for Direct revisions (`HYSTERIA_GECKO_HOP_PORTS`,
  `HYSTERIA_SALAMANDER_HOP_PORTS`, randomized hop interval between
  `HYSTERIA_HOP_MIN_INTERVAL_S` and `HYSTERIA_HOP_MAX_INTERVAL_S`). On by
  default: the Endpoint host deploy generates a private random range per obfs
  listener into the runtime environment when the keys are absent (an empty
  value disables hopping). The Endpoint firewall gains a
  `tracegate_hysteria_hop` nat table only when a range is configured; the
  Hysteria containers get no extra privileges. Exports use the official
  multi-port URI/YAML syntax and sing-box `server_ports` with `hop_interval`.
  New issues and re-issues carry the range; stored revisions are unchanged.
- Hysteria revisions verify the server certificate against the SNI
  (`HYSTERIA_TLS_VERIFY`, default true), including re-issues; verification is
  skipped only for an IP-literal server name or an explicit `tls_insecure`
  override. No certificate pinning and no ECH by default. The obfuscation
  chosen at creation (Gecko or Salamander) is kept on re-issue;
  `HYSTERIA_DEFAULT_OBFS` (default gecko) applies when none was chosen. Chain
  stays Gecko.
- Telegram Proxy link messages now ask the user to update Telegram to the
  latest version.

## v3.1.28 - 2026-07-26

- Restored the dedicated Entry-to-Endpoint Telegram Proxy path as the primary route.
- Added an opt-in direct Endpoint MTProto backup and dual-route bot delivery.

## v3.1.27 - 2026-07-26

- Detect actual Telemt uptime resets instead of treating every normal uptime
  increment as a runtime restart.

## v3.1.26 - 2026-07-26

- Keep the Telemt route-drop alert valid when Prometheus scrapes multiple
  counters with otherwise identical label sets.

## v3.1.25 - 2026-07-26

- Add interserver packet-loss, TCP retransmit, HAProxy backend/queue, full Chain
  egress latency, and Telemt MiddleProxy/restart alerts; expose HAProxy runtime
  health over a local Unix socket and bounded Entry/Endpoint peer probes.

- Keep Telegram Middle-End enabled for the dedicated Entry-to-Endpoint Telemt
  runtime so non-Premium and cross-DC media remains available, while retaining
  Telemt's direct-DC fallback.

## v3.1.24 - 2026-07-22

- Reject the retired `yandex.ru` and `www.yandex.ru` Reality fronts during
  materialization, including per-role destinations, server names, the isolated
  backhaul fallback, and multi-inbound groups. This turns stale private input
  into a failed render instead of silently restoring an obsolete production
  SNI.

## v3.1.23 - 2026-07-22

- Route the configured Grafana public hostname through the Endpoint web TLS
  backend alongside the normal WS/gRPC hostname, preventing unknown SNI from
  falling through to the Reality camouflage origin with HTTP 406.
- Install a certbot deploy hook that detects the active instantiated nginx role
  and reloads every service that consumes the renewed public certificate.

## v3.1.20 - 2026-07-22

- Disable nginx request-body size enforcement on the VLESS gRPC tunnel locations so long-lived streams cannot be rejected at the default 1 MiB limit.

## v3.1.19 - 2026-07-21

- Shorten the Grafana backhaul-monitor alert UID to satisfy Grafana's 40-character provisioning limit discovered during production bootstrap.

## v3.1.18 - 2026-07-21

- Export Xray Observatory full-egress health and latency for both ShadowTLS
  primary links and the isolated Reality fallback, with Grafana panels and
  alerts for primary degradation, fallback activation, and total Chain loss.
- Add bounded TLS 1.3 front discovery and Endpoint-first per-leg rotation with
  fresh-egress validation, independent slicing controls, and automatic host
  rollback. Endpoint IP rotation remains intentionally manual.
- Move every GitHub-hosted JavaScript action to its Node.js 24 generation while
  retaining `latest` container images for Xray, ShadowTLS, and Telemt.

## v3.1.17 - 2026-07-21

- Derive the Endpoint source allowed onto the Entry MTProto mask port from the
  explicit dedicated-link address. The production inventory uses a hostname
  for the general Endpoint plus distinct `.66` and `.85` service addresses.

## v3.1.16 - 2026-07-21

- Source-gate the Entry MTProto mask listener against the Endpoint's primary
  routing address rather than its optional secondary Hysteria bind address.
  This matters on the production Endpoint, where those addresses differ.

## v3.1.15 - 2026-07-21

- Preserve source-gated TCP access for both Chain link families and the
  dedicated MTProto/mask path even when a private firewall overlay replaces the
  public template.
- Feed Telemt's built-in exec-form healthcheck the live config at
  `/app/config.toml`; the previous shell-form override could never run because
  the image intentionally contains no `/bin/sh`.

## v3.1.14 - 2026-07-21

- Make SS2022 + ShadowTLS v3 the preferred Entry-to-Endpoint Chain transport,
  with the source-gated Reality leg used only when all ShadowTLS candidates are
  unavailable.
- Add independent, byte-preserving TCP stream-slicing sidecars for both
  ShadowTLS fronts; the fragmentation scope excludes MTProto and all unrelated
  host traffic.
- Finish the dedicated Entry-to-Endpoint Telemt link on source-gated TCP/9445,
  preserve PROXYv2 client attribution, keep the cover listener on TCP/10444,
  and align Telemt health/metrics with its Endpoint-owned runtime.
- Package both ShadowTLS legs and the isolated SS2022 backhaul terminator in the
  native host rollout so agent reconciliation no longer collapses the pool.

## v3.1.13 - 2026-07-17

- Added a dedicated Telemt-only Entry->Endpoint link so `entry-endpoint-tunnel`
  works as documented: Telemt runs on Endpoint and Entry is a plain TCP relay of
  the client's FakeTLS. Previously the render only emitted the Entry MTProto ACL
  for `entry-local-endpoint-egress`, so tunnel mode left Entry with no MTProto
  route at all, which is why Telemt had been hand-moved onto Entry.
- Added `MTPROTO_ENTRY_LINK_UPSTREAM` for that link's Endpoint target, so the
  Entry relay and the role-local Telemt listener no longer share one upstream.
  The Entry relay deliberately omits PROXY v2 (the Endpoint terminates the relay
  with its own HAProxy SNI demux and needs a raw ClientHello); the Endpoint still
  passes PROXY v2 into Telemt so real client addresses survive.

## v3.1.12 - 2026-07-16

- Fixed Chain (VLESS/REALITY on Entry) failing on Shadowrocket by retiring
  `yandex.ru` as the default REALITY camouflage dest. Major sites now negotiate
  post-quantum key exchange (X25519MLKEM768), which breaks REALITY for
  modern-fingerprint clients; the default is now an unpopular X25519-only TLS 1.3
  dest (`ibtcom.ru`). Operators still override per environment.
- Made the Entry->Endpoint backhaul a heterogeneous dual-transport pool:
  Shadowsocks-2022 (`2022-blake3-aes-256-gcm`) inside ShadowTLS v3 as the primary
  leg and VLESS/REALITY RAW/TCP as the independent fallback, so one transport
  signature or fault can no longer take the whole Chain (and MTProto tunnel)
  down. The SS2022 leg (`to-transit-ss` outbound, isolated `ss2022-backhaul-in`
  inbound, `tracegate-shadowtls-entry`/`-backhaul` units) is provisioned only
  when a backhaul key is present, so staging degrades cleanly to REALITY-only.
- Added an Xray `observatory` on Entry to health-probe both backhaul legs, and
  made `check_host_runtime` require both the REALITY and SS2022 backhaul
  transports so reconciliation can no longer silently collapse the pool.
- Made the REALITY fallback backhaul port configurable (`REALITY_BACKHAUL_PORT`,
  default 443) so it can move to a dedicated source-gated Endpoint port at
  cutover without agent reconciliation resetting it.

## v3.1.11 - 2026-07-15

- Export Hysteria Gecko profiles as official Hysteria YAML instead of an
  invalid sing-box attachment; Salamander keeps its compatible sing-box JSON.
- Stop Endpoint agents from publishing a false failed Telemt scrape for the
  Entry-only runtime.
- Make the verified RTC clock fallback declarative in native host deployment
  coordinates for providers that block NTP/UDP 123.

## v3.1.10 - 2026-07-15

- Standardized both Reality Chain legs on VLESS/REALITY RAW/TCP: client to
  Entry and Entry to Endpoint. Removed the retired split-HTTP transport from
  the Entry bundle and made agent reconciliation repair stale bundles before
  they reach Xray.
- Made the host contract fail when a packaged Reality leg is not RAW/TCP and
  reject malformed bracketed Reality SNI groups before rendering HAProxy.

## v3.1.9 - 2026-07-15

- Keep the primary Xray and fronting dependencies ahead of agent reconciliation
  while retaining Telemt and optional data planes in the final restart pass.

## v3.1.8 - 2026-07-15

- Run the host agent reconciliation before the deployer's final data-plane
  restart pass, preventing immediate double restarts and Telemt SIGKILL during
  startup.

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
