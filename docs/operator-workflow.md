# Host operator workflow

Tracegate production is managed through systemd on native hosts, the local
engine artifact store, and private role overlays. Engine units never pull at
start: each starts the image recorded by immutable digest in
`/var/lib/tracegate/artifacts`.

1. Build and validate the public release with `make release-check` and
   `scripts/build_release_artifacts.sh VERSION`.
2. Record the selected application image tags and the promoted engine digests
   in the private repository. `deploy/host/artifacts.json` defines which
   components exist and which upstream channel each follows.
3. Render/decrypt the reviewed private inventory into root-only files outside
   both repositories.
4. Verify checksums, install the host-runtime archive into a new release
   directory, then run `tracegate-host-deploy preflight`. Preflight prints
   `tracegate-artifacts status` for the role when a store already exists.
5. Run `tracegate-host-deploy deploy`. Before changing any state it captures
   the digests of the currently running engines (`tracegate-artifacts
   capture`) and aborts unless the store verifies for every role unit; it then
   requires a successful backup, applies migrations, replaces containers and
   waits for database-backed API readiness.
6. Validate role services and sustained client payload before proceeding to
   the next host.
7. To change an engine version: `tracegate-artifacts stage <component>`,
   probe the staged image, `tracegate-artifacts promote <component> <digest>`,
   restart one affected unit, probe, then continue; `tracegate-artifacts
   rollback <component>` restores the last-good digest.
8. On failure, use `tracegate-host-deploy rollback`; retain the failed logs,
   backup and release directory for review. The artifact store is never
   removed or retagged by a rollback.

Environment-specific inventory, DNS, firewall inputs, certificates, rendered
profiles, decoy content and credentials belong exclusively to
`tracegate-private` and production storage.

## Optional port features

These settings apply to new issuance and to re-issues; stored revisions keep
working as issued. Changing them changes the rendered firewall and listeners
on the next deploy or bundle reapply; that apply is a separate approved step,
never part of editing the environment.

- **Direct Reality port.** `REALITY_DIRECT_PORT` (default 8443) is the TCP port
  written into new and re-issued Direct VLESS/REALITY revisions. Endpoint
  always serves both TCP/443 and TCP/8443.
- **Telegram Proxy route.** In the Entry tunnel mode users receive only the
  Entry route on TCP/443. Keep `MTPROTO_DIRECT_BACKUP_HOST` set on Endpoint
  while legacy backup links must keep working: Endpoint then routes the
  FakeTLS SNI on TCP/443 only. Clearing it retires those links.
- **Hysteria2 port hopping.** On by default: when the Endpoint runtime
  environment has no `HYSTERIA_GECKO_HOP_PORTS` / `HYSTERIA_SALAMANDER_HOP_PORTS`
  keys, `tracegate-host-deploy` generates a random private 3000-port range for
  each and appends it before restarting services. Set a key to an empty value
  to disable hopping for that listener, or to `LO-HI` (within 1024-65535, at most 30000
  ports, not overlapping each other or UDP 443/4443/8443/8444), plus optionally
  `HYSTERIA_HOP_MIN_INTERVAL_S` (default 20, at least 5) and
  `HYSTERIA_HOP_MAX_INTERVAL_S` (default 60, greater than the minimum). Set
  them in the environment of the API (issuance) and of the bundle renderer.
  The renderer appends a `tracegate_hysteria_hop` nat table to the Endpoint
  `nftables.conf` after private overlays; when the Salamander listener binds
  a different address than Gecko, set `HYSTERIA_SALAMANDER_LISTEN_HOST_TRANSIT`.
  New and re-issued Direct revisions carry the range; existing revisions do
  not. Check on the host that nothing else listens on UDP inside the ranges.

## Reading alerts: failed, no data, query error

Every Grafana alert rule reports one of three distinct states:

- **Failed** — a probe or check ran and its result crossed the rule's
  threshold. Only failed alerts page the operator as critical.
- **No data** — the signal is missing: the probe never ran, the scrape is
  gone, or the metric is absent. No-data alerts are warnings and never page
  as critical; they mean monitoring cannot see the signal, not that the
  service failed. The dedicated warning rule "NO DATA: backhaul egress probe
  metrics missing" names the backhaul channel whose probe metrics are absent.
- **Query error** — Grafana could not evaluate the rule's query at all. Also
  a warning and never a confirmed failure.

Alert rules changed in this repository take effect in Grafana only after the
operator re-runs the Grafana bootstrap on the host; that re-run is a separate
approved step and is not part of a normal deploy.
