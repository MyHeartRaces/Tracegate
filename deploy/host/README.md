# Native host production runtime

Tracegate production runs directly on Linux hosts with systemd, host
PostgreSQL, Docker-backed data-plane services and host networking. There is no
parallel container orchestrator or Compose control plane.

Private inputs remain outside the public release:

- `/etc/tracegate/deploy.env` contains non-secret host deployment coordinates;
- `/etc/tracegate/tracegate.env` is the Endpoint runtime environment;
- `/etc/tracegate/tracegate-entry.env` is the Entry runtime environment;
- `/var/lib/tracegate/private` contains rendered private profiles and TLS data.

## Release lifecycle

1. Verify `SHA256SUMS` and extract `tracegate-host-runtime-VERSION.tar.gz`.
2. Run `tracegate-host-install VERSION`. It validates the archive, creates an
   immutable versioned venv from the bundled wheel, installs tracked systemd
   units and host helpers, and applies the QUIC sysctl profile. It does not
   switch the active release or restart traffic.
3. Render the correct role environment and run
   `tracegate-host-deploy preflight VERSION`.
4. Run `tracegate-host-deploy deploy VERSION`. Endpoint deployment takes a
   database backup and applies forward-compatible migrations before atomically
   switching `/opt/tracegate/current`, `/opt/tracegate/app` and
   `/opt/tracegate/venv`. Role services are restarted in dependency order and
   both API and agent readiness are required.
   On Endpoint, if the runtime environment has no `HYSTERIA_GECKO_HOP_PORTS`
   or `HYSTERIA_SALAMANDER_HOP_PORTS` key, the deploy appends a random private
   Hysteria port-hopping range for it first. Existing keys, including empty
   values that disable hopping, are never changed; the file stays private.
5. If readiness fails, the previous symlink targets and systemd files are
   restored automatically. `tracegate-host-deploy rollback` performs the same
   restoration explicitly. Database migrations are never downgraded.

The application wheel is versioned and immutable. Engine units never pull at
start: each one starts the image recorded by immutable digest in the local
artifact store (`/var/lib/tracegate/artifacts`, override with
`TRACEGATE_ARTIFACTS_DIR`). The store holds `active/<component>.env` and
`last-good/<component>.env` files with a single `TRACEGATE_IMAGE=<repo>@sha256:<digest>`
line, `candidates/<component>.json` lists of staged images and an append-only
`journal.jsonl` audit log. `deploy/host/artifacts.json` is the tracked registry
mapping components (xray, telemt, shadowtls, hysteria, prometheus,
grafana) to their upstream image and channel.

`tracegate-host-deploy deploy` runs `tracegate-artifacts capture --units ...`
and then `tracegate-artifacts verify --units ...` before it changes any state,
so a host that upgrades to this contract records the digests of the engines
that are already running (the first-upgrade capture) and the deploy aborts if
the store cannot satisfy a unit. If the running containers of one component
resolve to different digests (for example during a partial manual engine
update), `capture` refuses and lists each container with its digest; rerun it
as `tracegate-artifacts capture <component> --from-container NAME` to record
the digest of the container you choose. Choosing one means the sibling units
of that component move to that same digest at their next restart. Pulling is
explicit and operator-driven:

1. `tracegate-artifacts stage <component> [--tag TAG] [--digest sha256:...]`
   fetches a candidate (the only command that pulls; with `--digest` it pulls
   exactly that digest and verifies it) and records it.
2. Probe the staged engine through the real client path.
3. `tracegate-artifacts promote <component> <reference>` makes it active and
   prints the units to restart; restart them one at a time, probing after
   each. The previous active digest is kept as `last-good`.
4. `tracegate-artifacts rollback <component>` restores `last-good`;
   `tracegate-artifacts status` and `verify` report drift between running
   containers and the recorded digests.

Routine upstream engine updates run through `tracegate-engine-update`
(`tracegate-engine-update.service` and its daily timer): it discovers new
digests without pulling, lets them soak, stages them by digest through the
same store, checks them against the live config and activates one only where
policy is `auto` and a complete authenticated probe set passes after each
unit restart, rolling back otherwise; everything else waits for
`tracegate-engine-update approve`. `updates.json` and `updates.hold` live in
the artifact store directory. See "Engine updates" in
`docs/operator-workflow.md`.

A `tracegate-host-deploy rollback` re-installs the previous release's unit
files; the artifact store is left in place and local images are never removed
or retagged, so old units keep working after a rollback.

When a provider blocks outbound NTP/UDP 123, set
`TRACEGATE_ENABLE_RTC_CLOCK_SYNC=true` in that host's `deploy.env` only after
verifying that its UTC RTC is accurate. The deployer then validates `/dev/rtc0`
and keeps the tracked `tracegate-clock-sync-from-rtc.timer` enabled as part of
the role lifecycle.
