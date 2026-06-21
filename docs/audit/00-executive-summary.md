# Tracegate — Audit, Documentation & Hardening: Executive Summary

Full audit of the Tracegate project across both repositories (public `Tracegate`
and private `tracegate-private`): a complete read-through of the control plane,
agent, dispatcher, services, client export, Helm chart, protocol bundles, host
firewall renderers, and operator tooling; documentation of every implemented
solution; and a test-gated set of hardening fixes — weighted toward the project's
stated goal of maximum obfuscation / DPI resistance in a hard-moderated,
TLS-only-on-443 environment.

## What Tracegate is

A k3s-managed, multi-protocol privacy gateway with a Telegram-first control plane.
Control-plane intent (users, devices, connections, revisions) is turned into
gateway runtime by a dispatcher + per-role agent, which drive an in-pod data plane
of Xray (VLESS/Reality, Shadowsocks-2022), Hysteria2, ShadowTLS, WireGuard +
WSTunnel, and Telemt (MTProto), all multiplexed onto TCP/443 behind a HAProxy SNI
demux, plus Hysteria2 on UDP/443. Topology is Entry → Endpoint with a single
egress identity and a fail-closed Entry.

Supported transports: **VLESS+Reality (XHTTP)**, **Hysteria2 (+Salamander)**,
**VLESS-WS / VLESS-gRPC**, **Shadowsocks-2022 + ShadowTLS v3**,
**WireGuard-over-WebSocket**, **MTProto (FakeTLS)**.

## Methodology

Direct read-through of both repositories (no automated scanners as the basis;
findings are from logic, configuration, protocol-correctness, and hardening
analysis), plus `ruff`, the full `pytest` suite, real `helm template` chart
rendering, the host-firewall renderers, and `git ls-files` secret-tracking
checks. Baseline at start: `ruff` clean, **827 passed / 1 skipped**.

## Overall posture

**Solid.** The architecture's hard separations are real and enforced in code, not
just asserted: pod-only data plane, egress-identity isolation (DNAT/SNAT to a
single IP), fail-closed Entry and deploy, Cloudflare-only origin firewall, SNI-demux
collision guards that fail the render closed, SOPS/age secrets with only encrypted
manifests tracked, scoped API tokens, and pseudonymous observability. **No High-
severity findings.** Issues concentrate in defence-in-depth, camouflage-front
hygiene, and consistency.

## Top findings (full register: [90-findings-register.md](90-findings-register.md))

| ID | Sev | Summary | Status |
|----|-----|---------|--------|
| F8 | Medium | Default ShadowTLS/Reality camouflage fronts drifted onto catalog-disabled / forbidden SNIs (incl. `splitter.wb.ru`, which the same file forbids) | Fixed (transit front + regression guard); residual documented |
| F1 | Medium | Bootstrap & agent tokens compared with non-constant-time `==`/`!=` | Fixed (`hmac.compare_digest`) |
| F7 | Medium | Gateway pods run as root with no seccomp profile | Fixed (pod `seccompProfile: RuntimeDefault`); residual documented |
| F5 | Low-Med | UDP-over-TCP tunnel disables TLS verification silently | Fixed (loud warning) |
| F2, F3, F4, F6, F9, F10 | Low/Info | Hygiene, consistency, decoy hardening, docs | Fixed or documented |

## What changed (test-gated)

8 files in the public repo + 1 in the private repo. After remediation: `ruff`
clean, **828 passed / 1 skipped** (a regression-guard test was added for the
camouflage-front class). Every change, with rationale/verification/rollback, is in
[92-remediation-changelog.md](92-remediation-changelog.md).

## Top recommendations (operator-owned)

1. Validate and override the remaining catalog-disabled camouflage fronts (entry
   ShadowTLS, MTProto-egress ShadowTLS, transit Reality `dest`) from the target
   network — SNI reachability is a measured property (F8 residual).
2. Pilot `allowPrivilegeEscalation: false` / non-root for the `agent` sidecar on a
   staging node (F7 residual).
3. Add an offline break-glass age recipient (F10); serve the decoy frame with a
   CSP (F6).

## Document set

| Doc | Topic |
|-----|-------|
| [10-architecture.md](10-architecture.md) | Topology, planes, pod-only data plane, phases |
| [11-control-plane-and-data-model.md](11-control-plane-and-data-model.md) | API/bot/dispatcher/agent, DB model, revisions, outbox |
| [12-protocols-and-dpi.md](12-protocols-and-dpi.md) | Per-protocol deep dive + DPI/SNI strategy (priority) |
| [13-network-boundary-and-egress.md](13-network-boundary-and-egress.md) | Firewalls, egress identity, fail-closed (priority) |
| [14-secrets-and-crypto.md](14-secrets-and-crypto.md) | SOPS/age, tokens, HMAC, pseudonyms |
| [15-deployment-and-helm.md](15-deployment-and-helm.md) | Chart, guards, seeding, validation |
| [16-observability.md](16-observability.md) | Metrics, health, Grafana handoff |
| [17-client-export-and-router.md](17-client-export-and-router.md) | Export formats, Tracegate-Router compat |
| [90-findings-register.md](90-findings-register.md) | Severity-ranked findings |
| [91-security-hardening-report.md](91-security-hardening-report.md) | Threat model, attack surface, hardening |
| [92-remediation-changelog.md](92-remediation-changelog.md) | Applied changes |

Operator/secret-sensitive ops audit lives in the private repo under
`docs/audit/` (deploy package + secrets handling).

> Scope note: this audit set is public-safe — it uses placeholders and never adds
> live domains, addresses, or credentials to the public tree, per the project's
> own repository boundary rules.
