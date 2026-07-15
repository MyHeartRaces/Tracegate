---
name: tracegate-raw-chain-rollout
description: >
  Use this skill when Tracegate Chain is broken, an Entry bundle still contains
  XHTTP/splitHTTP, the Entry-to-Endpoint leg disappeared during host-runtime
  reconciliation, or a RAW Reality Chain change must be released safely. It
  covers source repair, private materialization, native-systemd rollout, base
  bundle delivery, and real active-revision egress verification without
  exposing client credentials.
license: MIT
metadata:
  author: openai
  version: "1.0"
---

# Tracegate RAW Reality Chain rollout

This is the proven order for restoring the two-leg Chain contract:
client -> Entry uses VLESS/Reality RAW, and Entry -> Endpoint also uses
VLESS/Reality RAW.

**Failure pattern:** issued clients are RAW but Entry still runs XHTTP, the
host contract strips `to-transit`, or bracketed SNI values make HAProxy route
away from the intended Reality shard.

**Verified by:** the public suite passed 739 tests plus host/deploy/privacy
checks, both production roles became healthy on the same release, and every
active slot-0 Chain revision completed an HTTP request with the Endpoint's
external egress rather than the Entry's.

## When to use this

- Chain imports exist but cannot pass traffic.
- Live Entry Xray differs from `bundles/base-entry/xray.json`.
- A host-runtime migration changed or removed the Entry backhaul.
- A release changes Reality transport, materialized SNI groups, or Entry
  routing and needs a production-safe validation sequence.

## Procedure

- [ ] 1. Establish the rollback point before editing or deploying.

  Check both roles' `/opt/tracegate/current`, API/agent readiness, failed
  systemd units, and the current live Entry config at
  `/var/lib/tracegate/agent-entry/base/xray/config.json`. Do not print client
  UUIDs, Reality keys, passwords, or materialized bundle payloads.

- [ ] 2. Enforce the contract in source, not only in the live file.

  The public bundle and reconciliation path must all agree:

  - `bundles/base-entry/xray.json`: `entry-in` and `to-transit` use
    `streamSettings.network = "raw"` with Reality security;
  - Entry traffic has a fail-closed default route to `to-transit` and no
    `direct` bypass for Entry inbounds;
  - `src/tracegate/services/runtime_contract.py`: the active Tracegate 3
    contract allows the Xray backhaul;
  - `src/tracegate/agent/reconcile.py`: stale persisted XHTTP/splitHTTP fields
    are converted to RAW before reaching live Xray;
  - `scripts/check_host_runtime.py`: rejects packaged XHTTP/splitHTTP, non-RAW
    Reality legs, missing backhaul, and Entry direct bypasses;
  - materialized SNI validation rejects bracketed hostnames rather than
    rendering invalid HAProxy ACLs.

- [ ] 3. Run the full local gate and publish an immutable patch release.

  ```sh
  make lint
  make test
  make host-check
  make privacy-check
  PYTHON=.venv/bin/python scripts/build_release_artifacts.sh VERSION
  ```

  Push `main`, require green CI including clean-room host install, then tag and
  verify the GitHub release assets. Secrets and decrypted host inputs belong
  only in the private repository or `/etc/tracegate`.

- [ ] 4. Stage the host archive on both roles without activating it.

  Run `deploy/host/tracegate-host-install VERSION` from the extracted archive,
  then run `tracegate-host-deploy preflight VERSION` on both Entry and
  Endpoint. Confirm the old release still owns `/opt/tracegate/current` during
  staging.

- [ ] 5. Render materialized bundles into a separate Endpoint directory.

  On Endpoint, source `/etc/tracegate/tracegate.env` and
  `/etc/tracegate/private/render.env`, override `BUNDLE_SOURCE_ROOT` to the
  staged release, and override `BUNDLE_MATERIALIZED_ROOT` to a versioned
  staging directory. Validate before activation:

  - no `xhttp` or `splithttp` text in rendered configs;
  - Entry inbound and `to-transit` are RAW;
  - no Entry direct bypass exists;
  - the default Entry rule targets `to-transit`;
  - HAProxy contains no `req.ssl_sni -i [` ACL.

  If rendering rejects `REALITY_MULTI_INBOUND_GROUPS`, normalize each `snis`
  value to a JSON list of plain hostnames in the existing protected env files,
  keep timestamped backups, and rerun the renderer. Mirror corrected plaintext
  snapshots back to SOPS-encrypted files in the private repository; never copy
  them into public files or command output.

- [ ] 6. Activate in the order that preserves compatibility.

  1. Deploy the new Entry release first so stale bundles are handled by the new
     reconciliation code.
  2. Replace `/opt/tracegate/materialized` with the already validated staged
     directory while retaining a timestamped backup.
  3. Deploy Endpoint/control; its native deployer performs backup, migration,
     atomic symlink switching, ordered restart, readiness, and rollback.
  4. Confirm both roles report the target version and zero failed units.

- [ ] 7. Explicitly enqueue the new Entry base bundle.

  Materializing files or restarting the agent does not deliver a new base
  bundle. POST `{"role":"ENTRY"}` to the local Endpoint API route
  `/dispatch/reapply-base` using `API_INTERNAL_TOKEN` loaded from
  `/etc/tracegate/tracegate.env`. Store the API response in a mode-0600
  temporary file and print only the event count; the response embeds the full
  materialized payload and can contain secrets.

  Poll the live Entry Xray file until it reports RAW for both legs, contains
  `to-transit`, has no Entry direct bypass, and contains no XHTTP. Also validate
  the live HAProxy ACL and service health.

- [ ] 8. Prove the path with real active slot-0 revisions.

  On Endpoint, query active `VLESS_REALITY` + `CHAIN` connections with active
  slot `0`, call `tracegate.client_export.config.export_client_config()` for
  each effective config, and write attachments only to a root-only temporary
  directory. Replace only the local SOCKS listener/auth in the test copy.

  Start one isolated `ghcr.io/xtls/xray-core:latest` client at a time with host
  networking and a read-only config mount. Through its authenticated SOCKS
  listener, require both:

  - a successful HTTPS response;
  - the observed external IP equals Endpoint's direct external IP and does not
    equal Entry's.

  Test every active Chain revision, remove the containers, and delete all
  temporary configs afterward.

## Gotchas

- `/opt/tracegate/materialized` is read by Endpoint/control, but Entry changes
  only after a dispatch event delivers `base-entry`.
- The live source of truth for verification is under
  `/var/lib/tracegate/agent-entry`, not merely the staged bundle.
- An Xray dummy gRPC `grpc-status: 12` can be healthy; do not treat it as a
  transport outage.
- Use `--user 0:0` for a test Xray container when its config is correctly mode
  0600, otherwise the container exits with `permission denied`.
- Never print `/dispatch/reapply-base` response bodies: they include complete
  bundle files, not just event metadata.
- Keep old active client revisions valid. This workflow changes server-side
  transport handling and does not require forced reissue when issued client
  links were already RAW.

## What didn't work

- Restarting `tracegate-agent-entry` alone did not fetch the new materialized
  base; the live config stayed XHTTP until `/dispatch/reapply-base` was queued.
- Treating `tracegate-host-install` as activation was wrong; it only stages the
  release and intentionally leaves traffic on the previous version.
- Rendering directly over the live materialized directory hid validation
  failures and could expose old agents to a partial change. A separate staging
  directory made validation and rollback deterministic.
- A first test Xray container exited immediately because a root-only config was
  mounted without `--user 0:0`; this was a test harness error, not a Chain
  failure.
