# Security & Hardening Report

Stealth-weighted security assessment of Tracegate against its stated threat
model. Read alongside [90-findings-register.md](90-findings-register.md) (issues)
and [92-remediation-changelog.md](92-remediation-changelog.md) (applied fixes).

## 1. Threat model

Tracegate is an anti-censorship privacy gateway whose explicit goal is
**maximum obfuscation / stealth and DPI resistance in a hard-moderated,
TLS-only-on-443 ("Siberian lockdown") environment**, while remaining compatible
with the Tracegate-Router client. The realistic adversary is a national/regional
network operator with:

- **Passive DPI** — TLS ClientHello fingerprinting, SNI inspection, flow timing,
  packet-size/entropy heuristics, ASN/IP reputation.
- **Active probing** — connecting to a suspected proxy IP/port to elicit a
  tell-tale response; replaying captured handshakes.
- **Stateful flow manipulation** — allowing a handshake then freezing a TCP flow;
  throttling UDP; resetting connections matching a signature.
- **Allow-listing pressure** — only TLS on 443 reliably traverses; UDP is
  unreliable; non-443 ports are blocked.
- **Provider-level visibility** — WHOIS/DNS/ASN ownership and routing
  relationships are observable (this is acknowledged as separation, not
  anonymity).

The adversary is **not** assumed to have host compromise, k3s API access, the
SOPS/age identity, or the private operator repository. Disk-at-rest exposure on
the nodes is explicitly accepted by the project (LUKS was intentionally dropped),
so confidentiality rests on "don't commit/print secrets," not on node disk
encryption.

Primary assets: user identity/anonymity, the set of working transports, the
camouflage fronts (SNIs/decoy), and the control-plane secrets.

## 2. Attack surface

| Surface | Exposure | Primary control |
|---------|----------|-----------------|
| Public TCP/443 (Entry & Endpoint shards) | Internet | HAProxy SNI demux → Reality / ShadowTLS / WS / gRPC / MTProto backends; per-source conn + rate limits |
| Public UDP/443 (Hysteria2) | Internet | TLS + Salamander obfs + HTTP auth + masquerade decoy |
| UDP/4443 (Entry↔Endpoint interconnect) | Endpoint↔Entry | Salamander + private auth + anti-replay/amplification + source validation |
| Service IP (egress + control) | Internet (control), egress identity | Ingress firewall rejects client ports; egress firewall SNAT identity |
| Universal Entry origin `:443` | Cloudflare only | Origin firewall: allow Cloudflare CIDRs, `tcp reset` else |
| Control-plane API (`:8080`) | Cluster / behind nginx | Scoped bearer/`x-api-token`; bootstrap token |
| Agent control channel (`:8070`) | Inter-node | `agent_auth_token`; host nftables |
| Public `/client-config/<token>` | Internet (via nginx) | HMAC-signed, expiring token |
| Telegram bot | Telegram | Role hierarchy; per-user bot blocks; welcome gate |
| Decoy / Grafana handoff | Internet (via nginx) | HMAC session cookie; rate limits; decoy auth |
| Secrets at rest (repo) | Git | SOPS/age; `.gitignore`; `.example` placeholders |

## 3. Defence-in-depth review (by layer)

### 3.1 Transport obfuscation (the stealth core)

- **Everything is multiplexed on TCP/443** and demuxed by TLS SNI in HAProxy
  (`configmaps.yaml`), so the public fingerprint is "one TLS service on 443."
  This is the correct shape for a TLS-only environment.
- **VLESS + Reality over XHTTP** is the primary direct profile: no certificate of
  its own — it borrows a real upstream's TLS via the Reality `dest`/`serverNames`
  handshake, defeating SNI/cert inspection when the front is a real, reachable
  site. Correctness therefore depends entirely on the **front SNI being a real,
  reachable, low-profile domain** — see F8 and §4.
- **Hysteria2 (UDP/443)** adds **Salamander** obfuscation (mandatory),
  HTTP-backend auth (`insecure: false`), QUIC with BBR, and **file masquerade**
  to the decoy directory so an HTTP/3 probe sees a plausible site. UDP is treated
  as a *measured* secondary, never assumed available — matching the DPI notes.
- **Shadowsocks-2022 + ShadowTLS v3** wraps SS-2022 (`2022-blake3-aes-128-gcm`,
  an AEAD construction with replay protection) behind a ShadowTLS v3 handshake so
  the outer flow looks like TLS to a real `serverName`. The ShadowTLS front must
  be **distinct from the Reality SNI pool** (enforced by the collision guard) and
  reachable (F8).
- **WireGuard-over-WebSocket** tunnels WG inside a WS/TLS upgrade behind nginx so
  it presents as ordinary WebSocket traffic, addressing WG's otherwise-trivial
  UDP fingerprint.
- **MTProto (Telemt FakeTLS)** is isolated from the VPN profiles, uses a
  whitelisted FakeTLS SNI (`ctlog2024.mail.ru`) with an enforced
  `forbiddenTlsDomains` deny-list, and `unknown_sni_action = "mask"`.
- **DPI methodology is sound and self-aware**: health checks transfer sustained
  authenticated payload (to detect post-handshake freezing); new-TLS-session
  concurrency is capped per source; multiple independent ingress IPs/providers
  are kept; SNI availability is treated as a *measured property*, not a config
  assumption (`docs/dpi-research-notes.md`). The audit's main stealth finding
  (F8) is precisely a case where a default drifted away from that methodology.

### 3.2 Network boundary & egress identity

- **Egress-identity isolation** is enforced in the host nftables renderers, not
  just asserted: shard traffic is DNAT/SNATed to a single service/egress IP
  (`endpoint-egress-firewall.py`), client ports are `tcp reset` / dropped on the
  service and disabled IPs, and inbound UDP is only accepted when it arrived via
  DNAT (`ct status dnat`, `endpoint-ingress-firewall.py`). This makes the client
  ingress identities disjoint from the single egress identity.
- **Fail-closed** is pervasive: Entry must fail closed when the Endpoint route is
  down; the private `deploy.sh` refuses to roll out unless the firewalls are
  active; Universal Entry origin `:443` is restricted to Cloudflare CIDRs
  (validated public + global).
- **Pod-only data plane** (`architecture.podRuntimeOnly`) keeps every runtime in
  the gateway pod; host nftables/SNAT are prerequisites, not runtimes.

### 3.3 Control plane & authn/authz

- **Scoped API tokens** (`security.py`): DB-issued tokens carry scopes (`:read` /
  `:write` / `:rw` / `all`) compared by SHA-256 hash in SQL; a bootstrap token
  grants `all`. Post-F1 all shared-secret comparisons are constant-time.
- **Agent channel** is gated by `agent_auth_token`; the backhaul token already
  used `secrets.compare_digest`.
- **Public client-config** path is HMAC-signed and expiring (token in URL — see
  residual risk §5).
- **Bot** uses an explicit role hierarchy (`user` < `admin` < `superadmin`) with
  `can_manage_user`, per-user temporary/permanent blocks, and a welcome gate.
- **Pseudonymity**: alias tokens are HMAC-derived from a private pseudonym secret
  and never expose raw connection/Telegram IDs.

### 3.4 Secrets

- SOPS/age with `encrypted_regex` limited to `data`/`stringData`; only encrypted
  manifests and `.example` files are tracked (verified). Secrets are injected into
  runtime configs by an init container via `sed` placeholder replacement from a
  mounted Secret, with the private-profile preflight refusing placeholder values.

### 3.5 Kubernetes posture

- Capability-scoped (`NET_ADMIN`/`NET_RAW`) rather than `privileged: true` — good.
- Post-F7 a pod-level `seccompProfile: RuntimeDefault` is applied. Residual:
  containers still run as root with privilege escalation allowed (§5).

## 4. Stealth-correctness analysis (priority focus)

The single most consequential stealth defect class is **camouflage-front drift**:
Reality `dest`/`serverNames`, ShadowTLS `serverName`, and MTProto FakeTLS SNI must
all be **real, reachable, low-profile domains that are not DPI-flagged**, because
the entire indistinguishability argument rests on the outer handshake looking
like a genuine visit to that domain.

The project models this well — a curated SNI catalog
(`staticdata/sni_catalog.yaml`) tracks per-domain `enabled` state with operational
notes ("TLS 1.3 verified from production Endpoint" vs "handshake timed out from
production"), and chart guards prevent SNI-demux collisions. The defect (F8) is
that several **default** fronts drifted onto catalog-`disabled` domains, and one
(`splitter.wb.ru`) onto an explicitly *forbidden* one — i.e., the defaults stopped
honouring the catalog the project maintains for exactly this purpose. The applied
fix removes the forbidden default and adds a regression guard; the residual
recommendation is to repoint the remaining disabled fronts to measured, reachable,
off-pool domains.

Key invariants to preserve (now partly guarded by tests):

1. A camouflage front must be **reachable + TLS 1.3-valid** from the target
   network (measured, not assumed).
2. A ShadowTLS / chain front must be **distinct** from the active Reality SNI pool
   (collision guard).
3. No active SNI field may use a **forbidden** domain (`yandex.ru`,
   `splitter.wb.ru`) — now test-guarded for ShadowTLS.
4. Raw proxy records stay **DNS-only**; proxied origins are firewalled to the
   provider's source ranges.

## 5. Residual risk (accepted or operator-owned)

- **Pods run as root with `allowPrivilegeEscalation` default** (F7 residual). A
  container breakout from a root, host-networked pod reaches the node. Mitigated
  by `RuntimeDefault` seccomp and capability scoping; further hardening needs
  staging validation.
- **Disabled camouflage fronts remain as defaults** for entry ShadowTLS, MTProto
  egress ShadowTLS, and the transit Reality `dest` (F8 residual) — operator must
  validate + override from the target network.
- **Client-config token in URL** can leak via proxy logs / referrers; it is
  HMAC-signed and expiring, but treat the link as a short-lived bearer.
- **Disk-at-rest exposure** is an accepted architectural decision (no LUKS).
- **Single age recipient** (F10) — add an offline break-glass recipient.
- **Decoy frame lacks CSP** (F6) — low blast radius; recommend CSP + sandboxing.
- **Provider-level correlation** (WHOIS/DNS/ASN) is acknowledged separation, not
  anonymity.

## 6. Prioritised recommendations

1. **(Operator, stealth)** Validate and override the remaining ShadowTLS / Reality
   default fronts (F8 residual) to reachable, off-pool, non-forbidden domains;
   re-run the clean-network payload probes the DPI notes prescribe.
2. **(Chart, medium)** Pilot `allowPrivilegeEscalation: false` and non-root for
   the `agent` sidecar on a staging node (F7 residual).
3. **(App, low)** Serve the decoy frame with a restrictive CSP and sandbox the
   GitHub mirror iframe (F6).
4. **(Ops, low)** Add an offline break-glass age recipient (F10).
5. **(Process)** Extend the new SNI-front regression guard to cover MTProto-egress
   ShadowTLS and the Reality `dest` once the operator selects validated targets,
   so the catalog stays the single source of truth.

## 7. Verification performed

- `ruff check .` — clean.
- `pytest -q` — 828 passed / 1 skipped (incl. the new regression guard and the
  `helm template`-backed chart suite).
- Host firewall renderers re-run against the example values (see task 9 in the
  audit run / [15-deployment-and-helm.md](15-deployment-and-helm.md)).
- `git ls-files` confirmed no plaintext secret/cert/kubeconfig is tracked in
  either repository.
