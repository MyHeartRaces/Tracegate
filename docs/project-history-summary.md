# Tracegate Project History Summary

This public-safe summary consolidates architectural decisions recovered from
prior project discussions and repository history.

## Evolution

- Early systemd and Xray-centric layouts demonstrated that dynamic backplanes
  and many interchangeable paths increased operational ambiguity.
- Tracegate 2.1 returned deployment ownership to one k3s/Helm package and kept
  live decoys and credentials private.
- Tracegate 2.2 added user-facing Direct/Chain variants, Hysteria, NaiveProxy,
  WireGuard-over-WebSocket and MTProto experiments.
- Repeated provider failures and payload-level Chain failures showed that a
  third Transit node was not a reliable security or availability boundary.
- The stable MTProto direction became MTG on Entry with a dedicated,
  fail-closed encrypted egress path through Endpoint.

## Current Decisions

- New production topology is Entry plus Endpoint only.
- Endpoint remains the stable egress boundary.
- Entry is replaceable and may expose a revision-sticky ingress pool.
- The old internal `transit` workload name is compatibility debt, not a node.
- Public Git contains code, generic contracts and validators. Private Git owns
  live coordinates, encrypted secrets, decoys and promotion automation.
- A release probe must authenticate and move sustained payload. Port-open and
  TLS-handshake-only checks are insufficient.
- Transport changes are promoted by canary revision with overlap and rollback,
  not by replacing active profiles in place.
- No transport is described as permanently DPI-proof.
