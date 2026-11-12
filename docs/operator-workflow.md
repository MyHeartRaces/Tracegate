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
   rollback <component>` restores the last-good digest. Routine upstream
   updates are handled by the engine update supervisor (see "Engine
   updates" below).
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
  Entry route on TCP/443, and Endpoint renders no MTProto route on any public
  port. `MTPROTO_DIRECT_BACKUP_HOST` no longer changes Endpoint routing.
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
  The Endpoint deploy also loads that table on the live host with
  `tracegate-hysteria-hop-apply` once the release is healthy: it checks the
  table with `nft -c`, replaces only `table inet tracegate_hysteria_hop`, and
  adds an include to the host's `nftables.conf` (checked, reverted on
  failure) so it survives a reboot. Run it by hand after changing a range.
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

## Engine updates

`tracegate-engine-update` (daily `tracegate-engine-update.timer`, one
`run` per host) keeps engine images current without ever trading away
working client connections. It is per host: each host decides only for the
engine units of its own role (`TRACEGATE_HOST_ROLE`).

How a new image moves through it:

1. **Discover** (no pull). For every component with an `update` block in
   `deploy/host/artifacts.json` it asks the upstream registry anonymously
   for the digest of the tracked tag. `{"track": "channel"}` follows the
   channel tag (for example `latest`); `{"track": "semver", "allow": "v2.*"}`
   follows the highest stable `MAJOR.MINOR.PATCH` tag inside that major and
   never crosses it. Multi-platform tags are recorded by their index digest
   (what `docker pull` reports in RepoDigests) and must contain linux/amd64.
2. **Soak.** A digest becomes eligible after it has stayed the newest one
   for `TRACEGATE_ENGINE_UPDATE_SOAK_DAYS` (default 3) since it was first
   seen. A digest that is replaced or withdrawn upstream is dropped and the
   soak starts again for its successor. A failed discovery run does not
   reset the soak.
3. **Stage** by digest through the artifact store (`stage` stays the only
   pull) and verify the pulled image reports that digest.
4. **Static check** with the candidate image against the live runtime
   config, read-only and without network: `xray run -test` for every Xray
   config the host's units mount, `promtool check config` for Prometheus.
   Other engines record "no static check". A failing check rejects the
   digest; a check that cannot run (missing config, docker error) is retried
   on the next run.
5. **Activate or queue.** Automatic activation needs all of: policy `auto`
   for this role, no hold, the soak passed, the static check passed and a
   complete authenticated probe set for the component on this role.
   Otherwise the candidate becomes `pending-approval` and the owner is
   notified. At most one component is activated per run.

Activation first runs the probe set against the current image (baseline;
a failing baseline queues the candidate and changes nothing), re-checks the
hold, promotes the digest, then restarts the component's units on this host
one at a time and runs the probe set after each restart. Any failure rolls
back to the previous digest (last-good is restored as it was), restarts the
units again, re-probes, rejects the candidate with its evidence and stops.
If the probes still fail after the rollback, the supervisor also turns the
hold on.

Probe sets (every sample of a window of at least 10 seconds must pass):

- every component: units active, running containers use the expected
  digest, agent health `overall_ok`;
- Endpoint Xray: a synthetic VLESS+REALITY client (the candidate image)
  using the internal Entry backhaul identity through the local TCP/443
  listener fetches a 204 endpoint repeatedly, and every backhaul channel in
  Prometheus reports success with a probe newer than the switch;
- Endpoint Hysteria: a synthetic Hysteria2 client (the candidate image)
  with the backhaul auth token fetches the same 204 endpoint through every
  Hysteria listener of the host; without the token the set is incomplete;
- ShadowTLS: every backhaul channel reports fresh success (Endpoint from
  Prometheus, Entry from its agent `/metrics`);
- Prometheus: `/-/ready`; Grafana: `/api/health` with database `ok`;
- Telemt, Entry Xray and Entry Hysteria have no authenticated probe yet and
  are never activated automatically.

Default policies (`policy` in the registry):

| Component | Endpoint | Entry |
| --- | --- | --- |
| xray | auto | notify |
| hysteria | auto (needs the backhaul token) | notify |
| shadowtls | auto | auto |
| telemt | notify | notify |
| prometheus | auto | - |
| grafana | auto | - |

These probes measure that issued connections of the probed paths keep
working on this host after the switch; they do not measure censorship
resistance of a new engine release.

Operator commands (run on the host, as root):

- `tracegate-engine-update status [--json]` shows candidates, their status
  (discovered, staged, checked, pending-approval, activated, rejected),
  soak time left, policy, the probe plan and the last evidence.
- `tracegate-engine-update approve COMPONENT DIGEST [--no-soak]` activates
  a known candidate through the same probe and rollback path, also when the
  policy is `notify` or a hold is on. `--no-soak` skips the remaining soak.
  A rejected digest is never activated.
- `tracegate-engine-update reject COMPONENT DIGEST` marks a digest as never
  to be staged or activated.
- `tracegate-engine-update hold on|off` freezes or releases all automatic
  activation on the host (discovery, staging and checks continue).
- `tracegate-engine-update discover` only records upstream digests.

State lives next to the artifact store: `updates.json` (mode 0600; every
candidate with first/last seen, status and evidence) and the `updates.hold`
file. Every action is appended to the artifact `journal.jsonl`. A digest
that was activated and later rolled back by hand is never re-activated
automatically.

Notifications need no extra credentials on Entry: each agent exports
`tracegate_engine_update_pending`, `tracegate_engine_update_rejected`,
`tracegate_engine_update_last_rejected_timestamp_seconds`,
`tracegate_engine_update_last_run_timestamp_seconds`,
`tracegate_engine_update_last_success_timestamp_seconds` and
`tracegate_engine_update_hold` from that state, and the warning rules
"engine update awaits approval", "engine update rejected" and "engine
update supervisor not succeeding" carry `notify=owner`, which the API alert
webhook forwards to the bot even at warning severity. As with every rule,
their no-data and query-error states stay silent.
