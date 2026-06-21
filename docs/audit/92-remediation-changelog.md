# Remediation Changelog

Every change applied during the audit, with rationale, verification, and
rollback. All changes are test-gated: `ruff check .` clean and
`pytest -q` green (**828 passed / 1 skipped**, one regression-guard test added).
Chart changes were additionally validated through real `helm template`
(helm v4.x) via the existing `tests/test_k3s_chart.py` suite.

Cross-references: [90-findings-register.md](90-findings-register.md).

## Changed files

Public repository (`Tracegate`):

| File | Finding | Change |
|------|---------|--------|
| `src/tracegate/security.py` | F1 | Constant-time token comparison helper + 3 call sites |
| `src/tracegate/udp_tcp_tunnel.py` | F5 | Warning when TLS verification is bypassed |
| `bundles/base-entry/xray.json` | F3 | Add `hy2-in` to RU split-tunnel rules |
| `bundles/base-entry/nftables.conf` | F4 | Correct misleading port comment |
| `bundles/base-transit/nftables.conf` | F4 | Correct misleading port comment |
| `deploy/k3s/tracegate/values.yaml` | F7, F8 | `gateway.seccompProfileType`; repoint forbidden ShadowTLS front |
| `deploy/k3s/tracegate/templates/gateways.yaml` | F7 | Pod-level `seccompProfile` block |
| `tests/test_sni_catalog_integrity.py` | F8 | Regression-guard test |

Private repository (`tracegate-private`):

| File | Finding | Change |
|------|---------|--------|
| `deploy-ready/tracegate-3-new-prod/deploy.sh` | F9 | Require `TRACEGATE_PUBLIC_REPO`; drop hardcoded path |

> Note: `src/tracegate/settings.py` and `tests/test_settings_compat.py` were
> touched during F8 exploration and then reverted to their original values (the
> `serverNameEntry` change was rolled back as out-of-scope for the applied fix);
> they carry no net change.

---

## F1 — Constant-time token comparison

**File.** `src/tracegate/security.py`.

**Change.** Added `import hmac` and a helper:

```python
def _tokens_match(provided: str | None, expected: str | None) -> bool:
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided, expected)
```

Replaced `token == settings.api_internal_token` (bootstrap accept),
`token != settings.api_internal_token` (`require_bootstrap_token`), and
`token != expected` (`require_agent_token`) with `_tokens_match(...)` calls.

**Behaviour.** Identical (same 401 responses, same accept conditions); only the
comparison is now timing-safe and `None`/empty-safe.

**Verify.** `pytest tests/test_entry_ingress.py tests/test_entry_ingress_pairs.py -q`
(token-auth paths) and full suite green.

**Rollback.** Revert the helper and the three call sites to `==`/`!=`.

## F3 — Entry bundle RU split-tunnel consistency

**File.** `bundles/base-entry/xray.json`.

**Change.** Added `"hy2-in"` to the `inboundTag` list of both RU split-tunnel
routing rules (the `geosite`/domain rule and the `geoip:ru` rule), so Hysteria2
matches the same direct-RU behaviour as the other user inbounds.

**Behaviour.** Generic reference template only (not the rendered k3s data plane);
JSON still parses. **Verify.** `python3 -c "import json;json.load(open('bundles/base-entry/xray.json'))"`.

**Rollback.** Remove `"hy2-in"` from the two rules.

## F4 — nftables comment correction

**Files.** `bundles/base-entry/nftables.conf`, `bundles/base-transit/nftables.conf`.

**Change.** Replaced the comment "Hysteria2 owns UDP/4443; 8443 stays closed."
with: "Hysteria2 owns public UDP/443; UDP/4443 is the Entry<->Endpoint
interconnect backhaul. TCP/4443 and TCP+UDP/8443 stay closed." No rule change.

**Rollback.** Restore the prior comment line.

## F5 — Warn on TLS verification bypass

**File.** `src/tracegate/udp_tcp_tunnel.py` (`_build_client_tls_context`).

**Change.** Emit `logging.getLogger(__name__).warning(...)` when
`tls_insecure_skip_verify` is active, before disabling verification. No control-
flow change; `logging` was already imported.

**Verify.** Full suite green; `ruff` clean.

**Rollback.** Remove the warning call.

## F7 — Pod-level seccomp profile

**Files.** `deploy/k3s/tracegate/templates/gateways.yaml`, `deploy/k3s/tracegate/values.yaml`.

**Change.** Added an overridable value `gateway.seccompProfileType: RuntimeDefault`
and, in the gateway pod `spec`, an optional block:

```yaml
{{- if $.Values.gateway.seccompProfileType }}
      securityContext:
        seccompProfile:
          type: {{ $.Values.gateway.seccompProfileType }}
{{- end }}
```

**Behaviour.** Adds a pod-level seccomp profile to every gateway data-plane
container. `RuntimeDefault` permits the `NET_ADMIN`/`NET_RAW` networking the data
plane needs. Set `gateway.seccompProfileType: ""` to omit, or `Unconfined` for
short-lived debugging.

**Verify.** `tests/test_k3s_chart.py` renders the chart via `helm template`
(green). Optional manual check: `helm template tracegate deploy/k3s/tracegate -f
deploy/k3s/values-endpoint-first.example.yaml | grep -A2 seccompProfile`.

**Rollback.** Remove the template block and the value.

## F8 — Repoint forbidden ShadowTLS front + regression guard

**Files.** `deploy/k3s/tracegate/values.yaml`,
`tests/test_sni_catalog_integrity.py`.

**Change.**
1. `shadowsocks2022.shadowtls.serverNameTransit`: `splitter.wb.ru` →
   `api.reviews.2gis.com`. The original was listed in the same file's
   `mtproto.stealth.forbiddenTlsDomains` and is catalog-disabled; the replacement
   is the sibling off-pool 2gis API domain — not forbidden, and (being catalog-
   disabled) it does not collide with the active Reality serverNames pool, so it
   passes the chart's SNI-demux collision guard. Added an explanatory comment in
   `values.yaml` documenting the distinctness + non-forbidden constraints.
2. New test `test_chart_shadowtls_server_names_avoid_forbidden_faketls_domains`
   asserts the chart's ShadowTLS fronts are never a forbidden FakeTLS domain and
   that Entry/Endpoint fronts differ.

**Why not more.** `serverNameEntry`, `mtproto.egress.shadowtls.serverName`, and
the transit `reality.dest` also default to catalog-disabled domains, but
replacing them requires a reachable off-pool domain validated from the target
network (the project's "SNI is a measured property" rule) and must avoid the
collision guard. These are left as operator recommendations (see F8 residual).

**Verify.** `pytest tests/test_sni_catalog_integrity.py tests/test_k3s_chart.py -q`
(green; the chart renders through `helm template`).

**Rollback.** Restore `serverNameTransit: splitter.wb.ru` and delete the test.

## F9 — Remove hardcoded developer path from private deploy wrapper

**File.** `tracegate-private` `deploy-ready/tracegate-3-new-prod/deploy.sh`.

**Change.** `PUBLIC_REPO` no longer defaults to a local absolute path;
`TRACEGATE_PUBLIC_REPO` is now required and validated (`deploy/k3s` must exist),
mirroring the existing required-env check for `TRACEGATE_K3S_PROD_VALUES`.

**Verify.** `bash -n deploy-ready/tracegate-3-new-prod/deploy.sh` (syntax);
running without `TRACEGATE_PUBLIC_REPO` now exits 2 with a clear message.

**Rollback.** Restore the default and drop the two guard clauses.

---

## Documented, not code-changed

| Finding | Reason |
|---------|--------|
| F2 (`shell=True`) | Inputs are operator-trusted reload hooks / fixed `nft` paths; shell is required for the hooks. |
| F6 (decoy regex sanitisation) | Decoy-only camouflage; outbound fetch already host-restricted. Recommend CSP + sandboxed iframe. |
| F7 residual (`runAsNonRoot`, `allowPrivilegeEscalation: false`) | Needs per-sidecar runtime validation on a staging node. |
| F8 residual (entry / egress / reality-dest fronts) | SNI reachability is a measured property; operator must validate from the target network. |
| F10 (single age recipient) | Key-custody recommendation; add offline break-glass recipient. |
