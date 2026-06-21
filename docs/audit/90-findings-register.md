# Findings Register

Severity-ranked register from the full project audit (control plane, agent,
dispatcher, services, client export, Helm chart, protocol bundles, host firewall
renderers, and the private operator repository). Severities are relative to the
project's own threat model (maximum obfuscation / DPI resistance in a hard-
moderated, TLS-only-on-443 environment), not to a generic internet service.

Baseline at audit start: `ruff` clean, **827 passed / 1 skipped**. After
remediation: `ruff` clean, **828 passed / 1 skipped** (one regression-guard test
added). Every applied fix is recorded in
[92-remediation-changelog.md](92-remediation-changelog.md).

## Severity scale

| Level | Meaning |
|-------|---------|
| High | Direct compromise of confidentiality/availability or de-anonymisation of users under the stated threat model. |
| Medium | Defence-in-depth gap, stealth-correctness defect, or latent break that degrades resistance or breaks a profile under realistic conditions. |
| Low | Consistency / hygiene / documentation defect with limited blast radius. |
| Info | Observation worth recording; no defect. |

No **High** findings were identified. The architecture's hard separations
(pod-only data plane, egress-identity isolation, fail-closed Entry, SNI-demux
collision guards, SOPS/age secrets) are sound; findings concentrate in
defence-in-depth, stealth-front hygiene, and consistency.

## Register

| ID | Sev | Area | Location | Status |
|----|-----|------|----------|--------|
| F1 | Medium | Crypto / timing | `src/tracegate/security.py` (bootstrap + agent token checks) | Fixed |
| F2 | Low | Command execution | `src/tracegate/agent/system.py:35` (`run_command`, `shell=True`) | Accepted (documented) |
| F3 | Low | Stealth / routing | `bundles/base-entry/xray.json` (RU split omitted `hy2-in`) | Fixed |
| F4 | Low | Docs / config drift | `bundles/base-entry/nftables.conf`, `bundles/base-transit/nftables.conf` | Fixed |
| F5 | Low-Med | TLS verification | `src/tracegate/udp_tcp_tunnel.py` (`tls_insecure_skip_verify`) | Fixed (loud warning) |
| F6 | Low | Decoy hardening | `src/tracegate/services/decoy_auth.py` (regex HTML sanitisation, no CSP) | Documented |
| F7 | Medium | Pod security | `deploy/k3s/tracegate/templates/gateways.yaml` (root, no seccomp) | Partially fixed + residual documented |
| F8 | Medium | Stealth / SNI hygiene | `deploy/k3s/tracegate/values.yaml`, `src/tracegate/settings.py` (ShadowTLS / Reality fronts) | Fixed (transit) + documented |
| F9 | Low | Hygiene | `tracegate-private` `deploy-ready/tracegate-3-new-prod/deploy.sh` | Fixed |
| F10 | Info | Secret recovery | `tracegate-private` `.sops.yaml` (single age recipient) | Documented |

---

## F1 — Non-constant-time comparison of bootstrap and agent tokens (Medium)

**Where.** `src/tracegate/security.py`: `require_internal_api_token` compared the
bootstrap token with `token == settings.api_internal_token`;
`require_bootstrap_token` and `require_agent_token` used `token != ...`.

**Issue.** Python `==`/`!=` on `str` short-circuits at the first differing byte,
leaking timing about how many leading bytes matched. The bootstrap token and the
agent token are long-lived shared secrets that gate the entire control-plane and
the gateway-agent control channel. The rest of the codebase already compares
secrets in constant time (`decoy_auth.py`, `api/routers/grafana.py`,
`agent/main.py` backhaul token), so this was both a weakness and an
inconsistency. Database-issued API tokens were already compared by SHA-256 hash
in SQL and are not affected.

**Risk.** A network-adjacent attacker who can measure response timing could, in
principle, recover the shared secret byte-by-byte. Lower in practice behind
k3s/SNI fronting, but it is a textbook side channel on the highest-value secret.

**Fix.** Added a `_tokens_match()` helper using `hmac.compare_digest` (None/empty
safe) and routed all three comparisons through it. Behaviour (the 401 paths) is
unchanged. See changelog F1.

## F2 — Agent `run_command` executes via `shell=True` (Low, accepted)

**Where.** `src/tracegate/agent/system.py:35`.

**Issue.** Reload hooks run through `subprocess.run(cmd, shell=True)`. The only
input filter rejects multi-line commands.

**Analysis.** All callers pass either (a) operator-defined reload commands from
Helm values (`AGENT_RELOAD_*_CMD`, e.g. `sh -lc '(flock 9; …) 9>…'`), which
*require* a shell, or (b) fixed internal strings (`nft -c -f <path>` /
`nft -f <path>`) where the path is a constant runtime location. No
user/database-derived data reaches `run_command`. The reload hooks are part of
the trusted deployment contract (set by the operator in `values.yaml`), so this
is not an injection sink for untrusted input.

**Disposition.** Accepted by design and documented. The shell is intentional for
reload hooks; the multi-line guard prevents trivial chaining. Recommendation
(non-blocking): keep reload commands sourced exclusively from Helm values and
never interpolate runtime/user data into them.

## F3 — Generic Entry bundle RU split-tunnel omitted the Hysteria2 inbound (Low)

**Where.** `bundles/base-entry/xray.json` routing rules.

**Issue.** The RU "direct" split-tunnel rules (`geosite:category-ru` / `geoip:ru`
→ `direct`) listed `entry-in`, `vless-ws-in`, `vless-grpc-in` but not `hy2-in`,
so Hysteria2 users' Russian-domestic traffic was backhauled instead of taking
the direct path that every other inbound used.

**Scope.** `bundles/` are generic reference templates; the **authoritative** k3s
data plane is rendered by `deploy/k3s/tracegate/templates/configmaps.yaml`, which
handles routing per `architecture.mode` and is unaffected. This was an internal
inconsistency in the example template only.

**Fix.** Added `hy2-in` to both RU split-tunnel rules so the template is
internally consistent. See changelog F3.

## F4 — Misleading "Hysteria2 owns UDP/4443" comment in nft bundles (Low)

**Where.** `bundles/base-entry/nftables.conf`, `bundles/base-transit/nftables.conf`.

**Issue.** The comment read "Hysteria2 owns UDP/4443; 8443 stays closed." Per
`src/tracegate/constants.py`, Hysteria2's public surface is **UDP/443**
(`TRACEGATE_PUBLIC_UDP_PORT = 443`); **UDP/4443** is the Entry↔Endpoint
interconnect backhaul (`TRACEGATE_INTERCONNECT_UDP_PORT = 4443`). The rules
themselves were correct; only the comment was wrong, which is dangerous in a
firewall file an operator reads while reasoning about exposure.

**Fix.** Corrected both comments to state Hysteria2 = public UDP/443, UDP/4443 =
interconnect backhaul, TCP/4443 + 8443 closed. See changelog F4.

## F5 — UDP-over-TCP tunnel disables TLS verification silently (Low-Medium)

**Where.** `src/tracegate/udp_tcp_tunnel.py` (`_build_client_tls_context`),
exposed via `--tls-insecure-skip-verify` in `src/tracegate/cli/udp_tcp_tunnel.py`.

**Issue.** When `tls_insecure_skip_verify=True`, the client sets
`check_hostname=False` and `verify_mode=CERT_NONE`, accepting any certificate.
It defaults to `False` and is opt-in, and the constructor refuses to build a
context with no verification material unless this flag is explicitly set — but it
produced no warning, so an operator could leave an insecure tunnel running
unknowingly.

**Fix.** Emit a loud `logging.warning` whenever the bypass is active, pointing to
`tls_server_name` + `tls_ca_file` (pinned CA) for production. Behaviour
unchanged. See changelog F5.

## F6 — Decoy GitHub mirror: regex HTML sanitisation, frame without CSP (Low)

**Where.** `src/tracegate/services/decoy_auth.py`
(`sanitize_github_repo_html`, `load_github_repo_frame_html`).

**Issue.** Decoy content fetched from `api.github.com` is sanitised by stripping
`<script>` / CSP / `X-Frame-Options` with regular expressions, then framed
without a Content-Security-Policy. Regex-based HTML sanitisation is inherently
fragile.

**Mitigating factors.** The outbound fetch is constrained to `github.com` repos
by `_github_repo_parts` (scheme + netloc allow-list, owner/repo regex); the
content is decoy camouflage, not a trust boundary; failures fall back to a static
template. Blast radius is small.

**Disposition.** Documented. Recommendation (non-blocking): serve the decoy frame
with a restrictive `Content-Security-Policy` response header and treat the GitHub
HTML as untrusted (sandboxed `iframe` / escaped rendering) rather than regex
stripping.

## F7 — Gateway data-plane pods run as root with no seccomp profile (Medium)

**Where.** `deploy/k3s/tracegate/templates/gateways.yaml`.

**Issue.** Gateway containers set `securityContext.runAsUser: 0` and add
`NET_ADMIN` / `NET_RAW` capabilities, but the pod had **no** `seccompProfile`,
**no** `allowPrivilegeEscalation: false`, and **no** `runAsNonRoot`. The
capability-scoped approach (vs `privileged: true`) is good, but the default
(unconfined) seccomp profile leaves the full syscall surface available to a
root-running, host-networked pod.

**Fix (applied).** Added an overridable pod-level
`securityContext.seccompProfile.type: RuntimeDefault`
(`gateway.seccompProfileType`, default `RuntimeDefault`). `RuntimeDefault`
constrains the syscall surface while still permitting the `NET_ADMIN`/`NET_RAW`
networking the data plane needs (nft, tc, WireGuard). Validated by `helm
template`. See changelog F7.

**Residual (recommended, not auto-applied — needs runtime validation).**
- Set `allowPrivilegeEscalation: false` on containers that do not need to gain
  privileges beyond their declared capabilities.
- Run the `agent` container (a Python control process) as non-root.
- Consider `readOnlyRootFilesystem: true` with explicit writable mounts for the
  stateless sidecars.
These touch a multi-sidecar data plane that performs privileged networking;
apply with per-sidecar runtime testing on a staging node.

## F8 — ShadowTLS / Reality camouflage fronts default to forbidden or dead SNIs (Medium)

**Where.** `deploy/k3s/tracegate/values.yaml` (`shadowsocks2022.shadowtls`,
`mtproto.egress.shadowtls`, transit `reality.dest`), `src/tracegate/settings.py`
(`shadowtls_server_name_*`), cross-checked against
`src/tracegate/staticdata/sni_catalog.yaml`.

**Issue.** Several default camouflage fronts pointed at SNIs the project's own
catalog marks `enabled: false`, and one was explicitly forbidden:

- `shadowsocks2022.shadowtls.serverNameTransit: splitter.wb.ru` — catalog
  `enabled: false`, **and** listed in the *same file's*
  `mtproto.stealth.forbiddenTlsDomains`, **and** called out in
  `docs/release-checklist.md` as a domain that must be "absent from active SNI
  fields." This is an objective self-contradiction.
- `shadowsocks2022.shadowtls.serverNameEntry: api.photo.2gis.com` — catalog
  `enabled: false` ("TLS handshake timed out from production").
- `mtproto.egress.shadowtls.serverName: styles.api.2gis.com` — catalog
  `enabled: false`.
- transit `reality.dest: public-api.reviews.2gis.com` — catalog `enabled: false`.

A camouflage front whose TLS endpoint is dead or DPI-flagged weakens stealth: an
active prober that knows the domain is atypical/unreachable for that IP can flag
the host. The chart's **SNI-demux collision guard** (`secrets.yaml`) further
requires the ShadowTLS `serverName` to be **distinct** from the active Reality
serverNames pool — which is why these fronts are deliberately drawn from
*outside* the enabled Reality lease pool. That design constraint is correct; the
defect is that the chosen off-pool domains include a *forbidden* one and several
operationally dead ones.

**Fix (applied).** Repointed `serverNameTransit` from the forbidden
`splitter.wb.ru` to the sibling off-pool domain `api.reviews.2gis.com` (not
forbidden, not in the active Reality pool, preserves the demux-collision-avoidance
design). Added a regression-guard test
(`tests/test_sni_catalog_integrity.py::test_chart_shadowtls_server_names_avoid_forbidden_faketls_domains`)
asserting the chart's ShadowTLS fronts are never a forbidden FakeTLS domain and
are distinct. See changelog F8.

**Residual (recommended — measured property, operator action).** `serverNameEntry`
(`api.photo.2gis.com`), `mtproto.egress.shadowtls.serverName`
(`styles.api.2gis.com`), and the transit `reality.dest`
(`public-api.reviews.2gis.com`) remain on catalog-disabled domains. The project's
own DPI methodology treats SNI reachability as a *measured property* validated
from the target network, so these must not be blindly reassigned in the public
repo. Recommendation: the operator designates reachable, TLS 1.3-verified domains
that sit **outside** the Reality lease pool, validates them from the target
carrier, and overrides these defaults in the private overlay.

## F9 — Private deploy wrapper hardcodes a developer-specific path (Low)

**Where.** `tracegate-private` `deploy-ready/tracegate-3-new-prod/deploy.sh`.

**Issue.** `PUBLIC_REPO` defaulted to `/Users/sgk/PycharmProjects/Tracegate`, a
single developer's local path baked into a production deploy package.

**Fix.** Removed the default; `TRACEGATE_PUBLIC_REPO` is now required and
validated to look like a Tracegate checkout (`deploy/k3s` present), matching the
existing required-env pattern for `TRACEGATE_K3S_PROD_VALUES`. See changelog F9.

## F10 — Single age recipient for all SOPS-encrypted secrets (Info)

**Where.** `tracegate-private` `.sops.yaml`.

**Issue.** All SOPS creation rules encrypt to one age recipient. If that single
age identity is lost, every committed secret becomes unrecoverable; if it is
compromised, everything is exposed. The `encrypted_regex` correctly limits
encryption to `data`/`stringData`, and the recipient public key is safe to
commit — the concern is purely key custody/recovery.

**Disposition.** Documented. Recommendation: keep an offline backup of the age
identity (already stated in `docs/project/security-and-secrets.md`) and consider
adding a second (offline break-glass) recipient so secret recovery does not
depend on a single key.

---

## Positive findings (defences confirmed working)

These were verified during the audit and are called out so they are preserved
through future change:

- **Egress-identity isolation** is enforced in depth: `endpoint-egress-firewall.py`
  DNAT/SNATs shard traffic to the single service IP; `endpoint-ingress-firewall.py`
  rejects client ports on the service/disabled IPs (`tcp reset`) and only accepts
  UDP that arrived via DNAT (`ct status dnat`).
- **Universal Entry origin firewall** restricts `:443` to Cloudflare CIDRs,
  validated as public + global IPv4 (`universal-entry-origin-firewall.py`).
- **SNI-demux collision guards** in `secrets.yaml` fail the render closed when a
  ShadowTLS / chain-bridge / vless-encryption SNI collides with a Reality SNI.
- **Constant-time secret comparison** is now used consistently (post-F1).
- **Fail-closed deploy**: the private `deploy.sh` refuses to roll out unless the
  Endpoint ingress/egress firewalls are active.
- **Secrets**: real keys/certs/kubeconfigs are git-ignored; only SOPS-encrypted
  manifests and `.example` files are tracked (verified via `git ls-files`).
- **Hysteria2 auth** uses the HTTP auth backend with `insecure: false`, Salamander
  obfs is mandatory, and masquerade serves the decoy directory.
