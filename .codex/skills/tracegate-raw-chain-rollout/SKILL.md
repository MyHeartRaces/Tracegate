---
name: tracegate-raw-chain-rollout
description: >
  Use this legacy skill only when diagnosing or removing an obsolete Tracegate
  RAW-Reality-primary deployment. Current production uses two SS2022 +
  ShadowTLS v3 primary links, isolated Reality fallback, and a separate Telemt
  link; for every current rollout load tracegate-durable-link-rollout instead.
license: MIT
metadata:
  author: openai
  version: "2.0"
---

# Tracegate RAW Reality Chain migration (legacy)

RAW Reality as the main Entry-to-Endpoint transport is retired. Read
`../tracegate-durable-link-rollout/SKILL.md` completely before taking any
current production action.

**Failure pattern:** a stale bundle or host reconciliation restores direct RAW
VLESS as the primary Chain carrier, making the interserver path easy for DPI to
classify and bypassing the two durable ShadowTLS primary legs.
**Verified by:** production moved to two independent SS2022 + ShadowTLS v3
primaries, retained RAW Reality only as fallback, isolated Telemt, and passed
active slot-0 Endpoint-egress plus controlled failover tests.

## Procedure

- [ ] 1. Inspect only for stale RAW-primary artifacts. Do not change production
  from this skill.
- [ ] 2. Confirm `to-transit-ss` and `to-transit-ss2` are the balancer selector
  candidates and `to-transit` is only `fallbackTag`.
- [ ] 3. Confirm the dedicated Telemt listener does not traverse that balancer.
- [ ] 4. Switch to `tracegate-durable-link-rollout` for source repair, private
  materialization, release, deployment, SNI rotation, monitoring, and live
  verification.

## Gotchas

- Public client Reality ingress may remain RAW; the retired part is RAW as the
  primary Entry-to-Endpoint carrier.
- Do not delete the Reality leg. It remains the isolated fallback on the
  dedicated source-gated listener.

## What didn't work

- Restoring the old RAW-primary procedure repaired connectivity briefly but
  reintroduced the DPI failure mode. Migrate forward to the durable topology.
