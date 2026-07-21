---
name: tracegate-durable-link-rollout
description: >
  Use this skill when Tracegate production Chain, Entry-to-Endpoint links,
  ShadowTLS fronts, Reality fallback, or the dedicated Telegram Proxy link must
  be audited, repaired, rotated, monitored, or released. Treat the verified
  production topology as the baseline even when the user does not mention DPI:
  two independent SS2022 + ShadowTLS v3 primary links with byte-preserving
  slicing, an isolated Reality fallback, and a separate Telemt/MTProto link.
license: MIT
metadata:
  author: openai
  version: "1.0"
---

# Tracegate durable isolated-link rollout

Use this order to preserve existing client compatibility while changing the
Entry-to-Endpoint data plane or its observability.

**Failure pattern:** RAW VLESS used as the primary interserver carrier is
quickly classified by DPI; a shared Chain/MTProto link couples failures; or a
healthy TCP/TLS handshake hides a channel that cannot complete Endpoint egress.
**Verified by:** the production topology survived primary-leg and dual-primary
failover tests, MTProto remained on its dedicated link, every active slot-0
Chain revision egressed through Endpoint, and the public release gate passed
757 tests plus host/deploy/privacy checks.

## When to use this

- Chain traffic fails, falls back unexpectedly, or exits from Entry.
- A ShadowTLS SNI or slicing profile must be discovered or rotated.
- Backhaul alerts, Xray Observatory metrics, or Grafana provisioning change.
- A host release or private snapshot must be converged with production.
- MTProto changes risk reusing a Chain carrier.

## Durable topology invariants

- Main A: Entry -> sliced TCP -> Endpoint TCP/9443 -> ShadowTLS v3 -> isolated
  SS2022 inbound.
- Main B: same protocol stack on independent local listeners and Endpoint
  TCP/9444. Its SNI and slicing controls must be independently changeable.
- Backup: VLESS/Reality RAW on source-gated Endpoint TCP/9446. It is fallback,
  not a primary candidate.
- Telegram Proxy: Entry HAProxy -> dedicated Endpoint Telemt TCP/9445 with its
  own mask return path. It must never use the Chain balancer.
- Xray's `latest`, ShadowTLS `latest`, and Telemt `latest` are intentional while
  upgrades preserve all existing connections. Do not pin them without a new
  user decision or a demonstrated compatibility break.

## Procedure

- [ ] 1. Snapshot live truth without exposing sensitive values.

  Record `/opt/tracegate/current` on both hosts, failed units, listener owners,
  container image names, Xray inbound/outbound tags, balancer selectors, and
  observatory status. Print environment key names only. Do not use repository
  architecture documents as the production baseline when the user forbids it.

- [ ] 2. Preserve the public/private boundary.

  Public source may contain topology, generic ports, metrics, validators, and
  placeholder domains. Passwords, UUIDs, private keys, selected production
  fronts, and host runtime snapshots belong only in SOPS-encrypted files in the
  private repository or root-only `/etc/tracegate` paths. Run the public privacy
  gate before every commit.

- [ ] 3. Validate all three Chain channels by full egress.

  Entry Xray must enable `ObservatoryService` and observe the prefix
  `to-transit`, which covers `to-transit-ss`, `to-transit-ss2`, and
  `to-transit`. Export each result separately from the Entry agent. Do not use
  outbound byte deltas to infer Reality fallback: Observatory probe traffic
  itself increments those counters.

  Alert when either primary is down, when both primaries are down and Reality
  is alive, and when all three are down. The Reality condition is the reliable
  early indicator that the balancer requires its `fallbackTag`.

- [ ] 4. Discover candidate fronts with a bounded search.

  Use the installed operator command; an adjacent CIDR scan is explicit and
  limited to 256 IPv4 addresses:

  ```sh
  tracegate-backhaul-fronts discover \
    --entry-ip ENTRY_IP \
    --scan-neighbors \
    --neighbor-cidr ENTRY_NEIGHBOR_CIDR \
    --candidate-file PRIVATE_SNI_CATALOG \
    --output CANDIDATES.json
  ```

  Accept only names that resolve, validate their certificate, negotiate TLS
  1.3, and return an HTTP response. Prefer longer common IP prefixes with Entry,
  then lower latency. Never commit the production candidate report publicly.

- [ ] 5. Rotate one ShadowTLS leg at a time.

  ```sh
  tracegate-backhaul-fronts rotate \
    --entry-ssh ENTRY_SSH \
    --endpoint-ssh ENDPOINT_SSH \
    --ssh-key SSH_KEY \
    --leg 1 \
    --sni CANDIDATE \
    --packets 1-1 \
    --length 1-4 \
    --interval-ms 1-2
  ```

  The command probes from both hosts, applies Endpoint server first, applies
  Entry client/slicer second, waits for an Observatory result newer than the
  transaction, and restores root-only host backups on failure. Rotate the
  other leg in a separate transaction. IP rotation stays manual.

- [ ] 6. Keep slicing byte-preserving.

  ShadowTLS v3 authenticates the original ClientHello record. Use Xray freedom
  stream fragmentation with per-leg `FRAGMENT1_*` / `FRAGMENT2_*` ranges.
  Never use `tlshello` record rewriting; it invalidates the ShadowTLS v3 HMAC.

- [ ] 7. Build, publish, and activate in the compatibility-preserving order.

  Run `make release-check`, build the host archive, and complete the clean-room
  install. Push `main`, require green CI/images, tag only after CI, and let the
  tag workflow create the immutable release.

  Stage and preflight both hosts. For a normal release, activate Entry first,
  render versioned private material on Endpoint, activate Endpoint, then
  explicitly dispatch `base-entry`. For an SNI-only rotation use the narrower
  Endpoint-first per-leg transaction in step 5.

- [ ] 8. Prove live convergence.

  Require zero failed units and healthy metrics for all expected channels.
  Re-run individual primary failures and dual-primary fallback. Verify Telemt
  TCP/9445 and its mask independently. Finally test every active slot-0 Chain
  revision through an isolated client: successful HTTPS and external IP equal
  to Endpoint, never Entry. Remove root-only test configs afterward.

- [ ] 9. Synchronize the private source after a successful live change.

  Capture only the intended runtime files, canonicalize duplicate dotenv keys
  with last-value-wins semantics, encrypt with SOPS, and verify encrypted
  metadata. Never print decrypted content. A future private render must
  reproduce the active SNI, ports, passwords, and per-leg slicing values.

## Gotchas

- Xray selectors are prefix matches: `to-transit-ss` deliberately covers both
  `to-transit-ss` and `to-transit-ss2`.
- A `generate_204` success is a full routed HTTP request, not a TCP handshake.
- Materializing a bundle does not deliver it to Entry; enqueue `reapply-base`.
- The dispatch response embeds full materialized files; keep it mode 0600 and
  print only counts.
- Grafana alert definitions are code-managed; rerun the internal bootstrap
  after release so new rules and panels are provisioned.
- Preserve all issued client revisions. Server-side backhaul work must not
  force replacement of working Salamander, Gecko, Reality, gRPC, WebSocket, or
  MTProto configurations.

## What didn't work

- RAW VLESS as the primary Entry-to-Endpoint carrier was classified and limited
  by DPI too quickly; keep it only as Reality fallback.
- Shared Chain and MTProto carriers coupled unrelated failure domains; Telemt
  needs its dedicated source-gated link.
- Counting Reality outbound bytes produced false fallback signals because
  health probes use the same outbound.
- TLS-record `tlshello` fragmentation broke ShadowTLS v3 authentication;
  byte-preserving TCP stream slicing passed.
