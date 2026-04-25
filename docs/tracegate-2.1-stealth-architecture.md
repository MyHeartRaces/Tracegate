# Tracegate 2.1 stealth architecture

Status: design proposal

Date: 2026-04-24

Scope: production replacement for the current Tracegate 2 runtime while keeping the product name `Tracegate 2`.

## Goal

Tracegate 2.1 returns to one managed `k3s` + Helm runtime, keeps the current decoy surfaces intact, keeps persistent Telegram `MTProto` access in core, and adds a layered transport set that can survive DPI pressure without making Entry or Transit unstable.

The main correction versus the first k3s Tracegate and the current systemd Tracegate 2 is that user churn and private camouflage changes must not restart data-plane processes. Helm owns the static topology; live APIs and narrow reload hooks own runtime state.

## Non-negotiable invariants

- No data-plane restart for ordinary user issue, revoke, rotate or resend.
- Exception: `MTProto` may trade per-session stability for stronger obfuscation, but only inside its isolated gateway/fronting path. MTProto restarts or secret rotations must not restart `edge-mux`, `xray`, `sing-box`, WireGuard, WSTunnel, or host networking.
- No broad host-wide packet manipulation. Private camouflage must be scoped to Tracegate public `443` surfaces and the Entry-to-Transit tunnel only.
- Decoy sites stay as they are now. Tracegate 2.1 may mount or reference the existing decoy trees, but must not regenerate or redesign them.
- `Entry` is a chain ingress, not a heavy egress node. Transit remains the primary egress and observability point.
- Every optional obfuscation layer must fail open to the previous stable transport or fail closed per connection, but must never flush host networking, reset interfaces, or drop unrelated connections.
- Private encryption and shaping profiles are host-local/private artifacts. The public repository may define schemas and handoff paths, but not real Mieru credentials, zapret2 packet policies, classifiers, fingerprints, timing profiles or target host lists.
- Helm upgrades may change static manifests, but production rollouts must not rely on pod restarts to apply user state.

## Runtime shape

Tracegate 2.1 should use one Helm chart again:

- `control-plane`: API, dispatcher, bot, PostgreSQL or external DB, optional Prometheus and Grafana.
- `gateway-transit`: one host-network pod pinned to the Transit node.
- `gateway-entry`: one host-network pod pinned to the Entry node.
- `private-runtime`: hostPath handoff directories under `/etc/tracegate/private` and `/var/lib/tracegate/private`, matching the current Tracegate 2 boundary.

Gateway pods keep the old useful k3s pattern: sidecars share a pod network namespace so local handoffs are `127.0.0.1` only. The chart must not put per-user material into pod template checksums, because that caused the old Kubernetes path to treat user changes as rollout events.

Data-plane sidecars:

- `edge-mux`: owns public `TCP/443`, does SNI/ALPN/path demux and static decoy routing.
- `udp-edge`: owns public `UDP/443` for Hysteria2 or TUIC lab profiles.
- `xray`: kept only where existing V1/V2 compatibility requires it, with users synced through gRPC API.
- `sing-box`: owns Shadowsocks-2022, ShadowTLS V3, TUIC lab profiles and the chain-proxy relay fabric.
- `mtproto-gateway`: core Transit-side Telegram Proxy runtime, fronted on a dedicated domain and isolated from the main profile runtimes.
- `wireguard`: kernel WireGuard or sing-box WireGuard endpoint, updated with `wg set` / `wg syncconf` or a managed API, not pod restart.
- `wstunnel`: stable WebSocket/TLS carrier for V7 WireGuard and optional private backplane.
- `link-crypto`: private Mieru-based encrypted link envelope for Entry-to-Transit and optional Router-to-Entry/Transit paths.
- `zapret2-wrapper`: private helper with narrow metadata handoff only.
- `agent`: reconciles runtime contracts, dispatches live user sync and runs preflight checks.

The agent publishes V5/V6/V7 runtime intent for private adapters as
`<private-runtime-root>/profiles/<entry|transit>/desired-state.json` plus a matching
`desired-state.env`. This handoff is generated from per-user artifacts, is mode `0600`,
contains secret material, and must be consumed from private runtime storage only. The
agent also publishes the Entry-Transit and optional Router link encryption intent as
`<private-runtime-root>/link-crypto/<entry|transit>/desired-state.{json,env}`. That second
handoff contains no secrets; it only points at private Mieru and zapret2 files. The public
repo owns the schemas and tests; real `sing-box`, ShadowTLS, WSTunnel, WireGuard, Mieru
and zapret2 profiles remain outside Git.

## Public profile map

| Profile | Public ingress | Runtime owner | Mode | Notes |
| --- | --- | --- | --- | --- |
| `V1` | Transit `TCP/443` | edge-mux + gRPC/WS carrier + Xray or sing-box adapter | direct | New default TCP compatibility surface. Prefer HTTP/2 gRPC carrier; keep legacy WS+TLS fallback only for clients that cannot speak gRPC. |
| `V2` | Entry `TCP/443` | edge-mux + chain-proxy | chain | Keep current user-facing role, but Entry-to-Transit must move out of Xray. |
| `V3` | Transit `UDP/443` | Hysteria2 standalone or sing-box | direct | Keep Hysteria2 for now. Do not replace with TUIC in the first 2.1 production cut. |
| `V4` | Entry `UDP/443` | Hysteria2 standalone or sing-box + chain-proxy | chain | Keep as backup/UDP profile. Its backhaul must use the same chain relay contract as V2/V6. |
| `V5` | Transit `TCP/443` | sing-box ShadowTLS V3 + Shadowsocks-2022 | direct | New direct SS2022 profile. |
| `V6` | Entry `TCP/443` | sing-box ShadowTLS V3 + Shadowsocks-2022 + chain-proxy | chain | New chained SS2022 profile. |
| `V7` | Transit `TCP/443` WSS | wstunnel + WireGuard | direct L3 | WireGuard returns, but only through WebSocket/TLS. Optional Entry-fronted V7 is lab-only until latency and reconnect behavior are proven. |
| `V8` | Transit `TCP/443` or dedicated domain | Mieru or RESTLS lab | direct option | Optional direct Transit obfuscation layer, not a default production profile. |
| `V9` | Transit/Entry `UDP/443` | TUIC v5 lab | direct or chain lab | Evaluation profile only. |
| `MTProto` | Transit `TCP/443` dedicated domain | fronting + MTProxy-compatible gateway + zapret2 extra profile | direct | Core Telegram Proxy surface. Maximum obfuscation is preferred over long-lived connection stability. |

## Client profile naming

Client-facing names should use one stable pattern:

`V<number>-<Type>-<Transport>-<Chain|Direct>`

Examples:

- `V1-VLESS-gRPC-TLS-Direct`
- `V1-VLESS-Reality-Direct`
- `V1-VLESS-WS-TLS-Direct`
- `V2-VLESS-Reality-Chain`
- `V3-Hysteria2-QUIC-Direct`
- `V4-Hysteria2-QUIC-Chain`
- `V5-Shadowsocks2022-ShadowTLS-Direct`
- `V6-Shadowsocks2022-ShadowTLS-Chain`
- `V7-WireGuard-WSTunnel-Direct`
- `MTProto-FakeTLS-Direct`

Keep old labels as compatibility aliases in database rows, exports and bot copy while migrating. New client exports and newly issued bot labels should use the normalized names.

## Local SOCKS5 authentication

Tracegate 2.1 requires SOCKS5 username/password on every local proxy adapter, including loopback-only listeners.
Generated client attachments bind local adapters only to loopback and use a stable per-connection high port by default,
not a common port such as `1080`.

Scope:

- VLESS client attachments: local Xray SOCKS inbound must require username/password credentials for `V1-VLESS-Reality-Direct`, `V1-VLESS-gRPC-TLS-Direct`, `V1-VLESS-WS-TLS-Direct` and `V2-VLESS-Reality-Chain`.
- Any Xray-based local SOCKS inbound shipped by Tracegate, including compatibility/debug attachments, must follow the same `localProxy.auth` contract.
- Hysteria client attachments: local SOCKS adapter must require credentials; generated Tracegate profiles keep `client_mode=socks` and reject HTTP/TUN client-mode overrides.
- Shadowsocks/ShadowTLS client attachments: local sing-box mixed/SOCKS inbound must require credentials.
- Mieru router/local adapters: local SOCKS ingress must require credentials, including loopback listeners.
- WireGuard/WSTunnel is L3, not SOCKS-native. If Tracegate ships a local SOCKS-to-WireGuard adapter, that adapter must require credentials.

Configuration model:

- `localProxy.auth.mode=username_password`
- generated credentials are per connection/device and emitted only in the client artifact/bot delivery.
- operator/user-supplied username/password may be set per connection through `local_socks_username` and `local_socks_password`; they are accepted only as a non-empty pair and never disable auth.
- operator-supplied username/password may exist only in private values, the database-backed override surface or user delivery artifacts, never committed to Git.
- `ConnectionRead` responses redact sensitive override values; revision generation still reads the stored unredacted value server-side.
- local listeners must stay on `127.0.0.1`/`::1`/`localhost`; non-loopback listeners are rejected.
- default generated local ports are stable high ports in `20000..59999`; common ports such as `1080` require an explicit override.

Recommended default:

- managed desktop/router artifacts: generated `username_password` credentials plus a non-standard high local port;
- legacy one-click URI exports: still deliver an authenticated Xray/sing-box/Hysteria attachment when a local proxy is expected;
- LAN/listen-anywhere adapters: not allowed for generated client artifacts; private router runners must combine any exception with firewall allowlists.

Local SOCKS auth protects the client host or router from other local/LAN processes abusing the proxy. It is not a replacement for VLESS/Hysteria/Shadowsocks/WireGuard server-side authentication.

## Xray API surface

Tracegate 2.1 must not ship client artifacts with Xray API access. Client-side `HandlerService`, `StatsService` or `ReflectionService` blocks are invalid profile material.

Server-side Xray API remains allowed only for the agent live-sync path:

- the API inbound must be tagged `api`, use `dokodemo-door`, and listen explicitly on loopback;
- the allowed service set is `HandlerService` and `StatsService`;
- `ReflectionService` and unknown API services are rejected by runtime preflight;
- an API services block without a matching loopback API inbound is invalid;
- the API listener is never part of client exports, decoy routing or public fronting.

## V1: WebSocket+TLS in a gRPC-shaped wrapper

The primary V1 profile remains `V1-VLESS-Reality-Direct`.

The V1 compatibility surface should stop being plain "WS path on TLS" as the main option. The recommended 2.1 compatibility shape is:

`client -> TLS h2 -> gRPC carrier -> local VLESS/WS or mixed adapter -> direct egress`

Operational rules:

- Use a real certificate and normal HTTP/2 ALPN on Transit.
- Keep the legacy `/ws` path available behind edge-mux during migration, but do not make it the only V1 implementation.
- Do not stack WebSocket inside gRPC unless a client cannot speak native gRPC. Prefer native gRPC transport where the client supports it.
- Per-user state remains in the inner runtime and is updated through live API, not by changing edge-mux or Kubernetes secrets.

## V5/V6: Shadowsocks-2022 + ShadowTLS V3

Use `sing-box` for the first production implementation because it already has Shadowsocks, ShadowTLS, TUIC and Hysteria2 primitives in one runtime surface.

Recommended shape:

- Outer layer: ShadowTLS V3 on `TCP/443`, with per-node or per-profile outer users kept mostly static.
- Inner layer: Shadowsocks-2022 with per-user credentials.
- Direct `V5`: Transit ShadowTLS -> local Shadowsocks -> direct egress.
- Chain `V6`: Entry ShadowTLS -> local Shadowsocks -> local chain-proxy -> Entry-to-Transit tunnel -> Transit egress.

Important stability choice: do not create or remove a ShadowTLS V3 outer user for every customer operation unless we have a verified live-management path. Keep ShadowTLS credentials coarse and rotate them as structural maintenance. Put per-user lifecycle in Shadowsocks-2022, where managed-user support can be isolated and tested.

The private V5/V6 handoff must therefore carry ShadowTLS as a static outer reference, not as
per-user credential material. Each row points at the role's private ShadowTLS config file,
declares `credentialScope=node-static`, `manageUsers=false` and
`restartOnUserChange=false`; per-user add/revoke/rotate changes only the Shadowsocks-2022
inner user set.

Use `2022-blake3-aes-256-gcm` by default on x86 hosts with AES acceleration. Keep `2022-blake3-chacha20-poly1305` as the low-power fallback.

The control plane emits per-role desired state for V5/V6 under the private profile handoff.
Transit receives V5 direct users and V6 transit terminator entries; Entry receives only V6
entry relay entries. Reload hooks must reconfigure the private adapter in place and must
not restart the public gateway pod.

## V7: WireGuard over WebSocket/TLS

V7 returns as WireGuard over WSTunnel:

`client WireGuard -> local UDP endpoint -> wstunnel WSS -> Transit wstunnel -> local WireGuard`

Server-side rules:

- WSTunnel is exposed through `TCP/443` behind edge-mux or directly on a dedicated SNI.
- The WSTunnel server must restrict forwarding to the local WireGuard UDP endpoint only.
- WSTunnel client targets must stay in the form `wss://host:443/path`; the path in desired state must match the URL path, and local UDP listeners must stay loopback-only.
- WireGuard peer changes use live `wg` operations, not container restart.
- Use `PersistentKeepalive = 20` or `25` only where NAT requires it.
- Start with MTU `1280-1320`; generated overrides are bounded to the conservative `1200..1420` range, and keepalive overrides are bounded to `0..60`.
- Client profiles must route the WSTunnel server IP outside the WireGuard default route to prevent self-looping.

V7 desired state must include the client public key, optional preshared key, server-side
peer AllowedIPs, WSTunnel path, local UDP endpoint and a live sync contract. Server-side
peer AllowedIPs must be the client's tunnel host routes (`/32` or `/128`), never the
client's default-route intent such as `0.0.0.0/0` or `::/0`. The production sync contract
is `strategy=wg-set`, `applyMode=live-peer-sync`, `removeStalePeers=true`,
`restartWireGuard=false` and `restartWSTunnel=false`. If the client public key is missing,
the private adapter must reject only that peer entry, not restart the WireGuard interface
or WSTunnel listener.

Do not make Entry-fronted V7 the default. It adds another TCP/WSS hop and can amplify TCP-over-TCP behavior. Keep it as a fallback only when direct Transit is degraded and the user explicitly needs an L3 tunnel.

## Entry-to-Transit tunnel

The 2.1 default should be a `Stealth Transit Bridge` implemented outside Xray.

Recommended production default:

`Entry local chain-proxy -> ShadowTLS V3 -> Shadowsocks-2022 relay -> Transit local egress`

Why this should be the default:

- It is outside Xray and can serve V2, V4 and V6 through one local proxy contract.
- It avoids privileged kernel networking on Entry.
- It keeps Entry CPU low compared with multi-backplane probing.
- It looks like one stable `TCP/443` service instead of multiple changing paths.
- It can be managed in the same sing-box runtime as V5/V6.

Backplane tiers:

- Tier 1: ShadowTLS V3 + Shadowsocks-2022 relay on `TCP/443`, default for V2/V6 and TCP-heavy V4.
- Tier 2: private WireGuard-over-WSTunnel L3 overlay, only where a true IP route is required.
- Tier 3: Hysteria2 or TUIC QUIC backplane, lab-only for UDP-heavy workloads when `UDP/443` is known to survive.

Avoid reintroducing the old adaptive selector as a default. If selector logic returns, it must be sticky, per-flow, slow to switch, and disabled from probing multiple expensive backplanes on small Entry nodes.

Direct Entry-to-Transit TLS fallback is not part of the production contract. If
the private bridge is unavailable, chained profiles should degrade or fail
closed rather than silently bypassing Mieru/link-crypto.

## zapret2 policy

The zapret2 layer must be reworked as a narrow private helper, not as a broad network owner.

Rules for 2.1:

- Entry public profile: only Entry ingress `TCP/443` and `UDP/443`.
- Interconnect profile: only Entry-to-Transit bridge traffic.
- Transit profile: only Tracegate-facing public `443` surfaces.
- No broad NFQUEUE or userspace interception over all host traffic.
- Scoped userspace interception is allowed only for Tracegate-owned flows selected by packet mark, cgroup, local bind address, pod label, interface pair or explicit destination tuple.
- Port `443` alone is not a safe selector. Public surfaces sharing `443` must still be separated by role, listener, SNI/ALPN/path, packet mark or local upstream.
- Scoped interception must have a bounded queue, health gate and automatic bypass/rollback for the affected link only.
- No `nft flush ruleset`, interface restart, route replacement or conntrack flush during reload.
- Reloads must be atomic and preserve existing connections.
- If private zapret2 fails, it must not drop the node network. The baseline transport should continue without that layer.
- `TRACEGATE_ZAPRET_MAX_WORKERS=1` remains the default for Entry. Raise only from metrics, not speculation.

The public repo should continue to expose only metadata and preflight checks. The real packet policy remains private.

MTProto gets its own stricter obfuscation budget:

- use only the `mtproto-extra` profile and only behind the dedicated MTProto fronting path;
- aggressive packet shaping is acceptable if it occasionally breaks Telegram proxy sessions;
- MTProto policy must still be protocol-valid enough for Telegram clients to reconnect;
- MTProto failures must not widen zapret2 scope or affect V1-V7 traffic.

## MTProto core profile

Persistent Telegram Proxy access remains part of core Tracegate 2.1, not an optional private add-on. The private implementation may stay outside Git, but the Helm chart and control plane must treat MTProto grants, public profile generation and runtime health as first-class product surfaces.

Recommended production shape:

`Telegram client -> dedicated MTProto domain TCP/443 -> edge/fronting SNI demux -> private MTProto obfuscation layer -> MTProxy-compatible backend`

Core rules:

- Use a dedicated real domain for MTProto. Do not reuse the panel, V1/V5, or decoy hostnames.
- Keep the public `t.me/proxy` / `tg://proxy` delivery path in the bot.
- Prefer fake-TLS client secrets with a real domain (`ee...domain`) as the default user-facing mode.
- Keep random-padding (`dd...`) available as a fallback cohort when fake-TLS reachability degrades.
- Store only one raw 32-hex-character server secret in the private MTProto Secret; fake-TLS and random-padding client secrets are generated for user delivery, not mounted as runtime private material.
- Keep raw client delivery only as an emergency/debug mode.
- Run the backend on loopback or a private pod-local address. Public `TCP/443` must be owned by the fronting layer.
- Allow MTProto-specific process restarts, secret cohort rotations and zapret2 policy reloads when needed. This exception is limited to MTProto and must not restart the gateway pod.
- Preserve the current account-bound grant model: issued secrets stay persistent and revocation updates MTProto state through the agent path.

Maximum obfuscation stack, in order of preference:

1. dedicated DNS-only MTProto hostname;
2. L4 fronting/demux on `TCP/443`;
3. fake-TLS MTProto secret mode;
4. per-account persistent issued secrets;
5. private `mtproto-extra` zapret2 shaping;
6. optional private carrier experiments, but only if they do not require Telegram client changes.

Do not chain MTProto through the Entry-to-Transit bridge by default. Telegram Proxy should stay Transit-direct because client support is stricter and the user explicitly accepts MTProto session instability only for stronger camouflage, not for extra routing complexity.

## Private encrypted link algorithm

Do not design custom cryptography for Tracegate 2.1. Use Mieru as the encrypted link envelope and zapret2 as an optional outer shaping layer. zapret2 alone is not an encryption layer; it can only modify how the already-encrypted carrier is observed on the wire.

Default decision:

- stable or moderate-DPI paths: Mieru only;
- harsh-DPI paths: Mieru plus scoped zapret2 on the outer Mieru connection;
- never use zapret2 alone when the requirement is encryption.
- do not apply Mieru plus zapret2 blindly to every public `443` connection. `443` is only the shared external port, not proof that the same obfuscation layer is safe for all profiles.

Mieru plus zapret2 applies by default only to links where Tracegate controls both endpoints:

- Entry-to-Transit private bridge;
- Router-to-Entry private bridge;
- Router-to-Transit private bridge.

For ordinary mobile/desktop client profiles, Mieru requires an explicit client-side wrapper or a router-side adapter. Without that, direct V1/V3/V5/V7 users keep their native transport, and zapret2 can only be applied as a scoped server-side shaping policy where it is protocol-safe. For router-based users, the router can place all inner Tracegate profiles inside the Mieru link, so those flows get Mieru plus optional zapret2 indirectly.

Link classes:

| Link | Default | Purpose |
| --- | --- | --- |
| `entry-transit` | Mieru + optional zapret2 | Universal private bridge for V2/V4/V6 chain traffic. |
| `router-entry` | Mieru + optional zapret2 | Customer/operator router enters the chain path without exposing raw profile internals. |
| `router-transit` | Mieru + optional zapret2 | Customer/operator router reaches Transit directly for V1/V3/V5/V7-style routing. |

Algorithm:

1. `agent` renders `<private-runtime-root>/link-crypto/<role>/desired-state.{json,env}` with link class, role pair, local bind address, public endpoint, selected Tracegate profile set and profile generation. It does not render private packet policy.
2. A private profile resolver loads `/etc/tracegate/private/mieru/{client,server}.json`, the scoped zapret2 profile, or an equivalent Kubernetes `Secret` mounted as files.
3. The local chain-proxy or router adapter sends all selected traffic to a loopback listener owned by `link-crypto`.
4. `link-crypto` opens a Mieru session to the remote side and encrypts the inner stream/datagram relay. Credentials are per link class and generation, not per user.
5. If the profile enables zapret2, the private wrapper marks only the outer Mieru socket or pod traffic and applies the selected zapret2 policy to that marked flow.
6. The remote Mieru endpoint decrypts and forwards to a fixed local target:
   - `entry-transit`: Transit local egress or Transit local chain ingress;
   - `router-entry`: Entry local chain ingress;
   - `router-transit`: Transit local direct ingress.
7. Health checks observe the local listener, remote Mieru session and final local target separately. A failure can disable the link or fall back to a lower tier, but cannot flush host networking.
8. Rotation is generation-based: start new Mieru listener/client with generation `N+1`, move new flows to it, keep generation `N` draining until idle timeout, then stop it.

Private profile fields, all outside Git:

- Mieru server/client credentials and users.
- Outer port, transport mode and domain/SNI choices.
- zapret2 strategy id, packet shaping parameters, timing windows and classifier data.
- Link-specific MTU/MSS, keepalive, retry and idle-drain values.
- Router enrollment tokens and per-router allowed route sets.

Public repository fields are limited to non-sensitive schema names:

- `linkClass`, `profileId`, `generation`, `enabled`, `localBind`, `remotePublicEndpoint`, `allowedTarget`, `healthPolicy`, `fallbackTier`.
- Preflight may verify that a private profile exists and that its checksum changed, but must not print the profile body.

Recommended defaults:

- `entry-transit`: Mieru TCP-like carrier on `443` or a dedicated private port hidden behind fronting; zapret2 enabled only if direct Mieru is classified.
- `router-entry`: Mieru carrier with router-specific credentials; zapret2 optional and preferably applied on the router only if the router has enough CPU.
- `router-transit`: Mieru carrier with direct Transit endpoint; zapret2 optional and isolated from WireGuard/WSTunnel.
- Keep one active private encrypted link per path by default. Do not run selector probes across several encrypted links on low-RAM Entry nodes.

## Decoy handling

Do not change decoy sites in Tracegate 2.1.

Helm should support:

- `decoy.existingConfigMap` for lab.
- `decoy.hostPath` or PVC for production private assets.
- Current `/etc/tracegate/private/overlays` sync path for compatibility with Tracegate 2.

The chart must not embed new decoy HTML/CSS/JS and must not make decoy asset updates restart gateway pods.

## Mieru and RESTLS

Mieru is worth testing as an optional direct Transit profile because it is designed to be hard to classify, does not require TLS, supports TCP/UDP proxy modes and has current releases. The tradeoff is client ecosystem and a separate credential model.

RESTLS should stay lab-only. The idea is relevant for TLS impersonation research, but production risk is high: smaller ecosystem, less operational evidence, and more chance that client support becomes the bottleneck.

Recommendation:

- Add a `directObfuscation.experimental` block in values.
- Allow `mieru` as a disabled-by-default V8 direct profile.
- Keep `restls` as a private lab transport, not a supported public variant.
- Do not wrap every direct profile through Mieru/RESTLS. Apply only to profiles whose clients and traffic shape are tested.

## TUIC v5 versus Hysteria2

Do not replace V3/V4 Hysteria2 with TUIC v5 in the first production cut.

Arguments for TUIC:

- QUIC-based proxy with TCP and UDP relay.
- Protocol v5 is the current version.
- sing-box and several clients support it.
- It has clean authentication and congestion-control options.

Arguments against replacing Hysteria2 now:

- The TUIC protocol repo explicitly focuses on specification and has no official implementation.
- Current Tracegate users already have Hysteria2 operational experience and client expectations.
- Hysteria2 has a stronger masquerade story for the existing V3/V4 product surface.
- sing-box recommends disabling TUIC 0-RTT because of replay risk, so the headline 0-RTT advantage is not a production default.
- Replacing Hysteria2 changes the UDP fingerprint and support matrix at the same time as k3s, WireGuard, ShadowTLS and interconnect changes. That is too much blast radius.

Decision: add TUIC as a lab profile after V5/V6/V7 and the Entry-to-Transit bridge are stable. Reconsider replacement only if lab metrics show better reachability and no client-support regression.

## Helm rollout design

Use one chart, but separate static topology from live state:

- Static Helm values: sidecars, listeners, ports, role placement, private handoff paths, coarse profile enablement.
- Live state: users, peers, credentials, runtime contracts, zapret2 runtime-state.
- Data-plane pod templates must not checksum user secrets.
- Gateway Deployments default to `RollingUpdate` with `maxUnavailable=0`.
  Because hostNetwork ports often cannot roll in-place on a single pinned node,
  an unsafe upgrade should stall before deleting the active gateway pod.
- Gateway PDB, probes and private preflight are part of the production guardrail
  set and should not be disabled by normal values overlays.
- `Recreate` is a lab-only maintenance opt-in. For production, structural
  data-plane upgrades require a spare node handoff or a planned maintenance
  gate. They are not a normal user operation.
- Control-plane Deployments can roll normally with readiness probes and PDBs.

Gateway probes:

- Startup probes should wait for local dependencies without forcing quick CrashLoopBackOff.
- Liveness probes should check process health, not remote Internet reachability.
- Readiness may reflect degraded backhaul, but must not restart the pod.

## Implementation milestones

1. Restore `deploy/k3s/tracegate` as the only production chart, using the old chart as scaffolding and current Tracegate 2 `entry/transit` naming.
2. Port the current xray-centric public bundle contract into Helm without changing decoys.
3. Add `sing-box` sidecar and config model for ShadowTLS V3 + Shadowsocks-2022.
4. Implement the Stealth Transit Bridge for V2/V4/V6, outside Xray.
5. Add V7 WireGuard-over-WSTunnel with live peer sync and MTU safeguards.
6. Move V1 compatibility to a gRPC-first HTTPS carrier with legacy WS fallback.
7. Promote MTProto to the k3s core chart with dedicated fronting, persistent grants and the `mtproto-extra` obfuscation profile.
8. Add private Mieru-based encrypted link contracts for Entry-to-Transit, Router-to-Entry and Router-to-Transit.
9. Rework zapret2 wrapper metadata and preflight for narrow scoped policies, with the explicit MTProto stability exception.
10. Add k3s private Secret preflight before gateway listeners start; reject placeholders, broad NFQUEUE, host-wide zapret2 scopes, legacy Shadowsocks methods, non-v3 ShadowTLS, non-raw MTProto server secrets and WireGuard lifecycle hooks.
    WireGuard preflight also rejects host route side effects: DNS rewrites, saved config, default or split-default AllowedIPs, MTU outside 1200..1420 and PersistentKeepalive outside 0..60.
11. Add k3s private reload validation for profile and link-crypto handoffs, using redacted marker files instead of pod restarts.
    Profile-driven and link-crypto sidecars must wait for desired-state, env and
    a marker that is not older than either file; if a marker is missing or stale
    during upgrade, the agent schedules the narrow reload hook again.
12. Keep gateway rollouts on `RollingUpdate` with `maxUnavailable=0`; unsafe single-node hostNetwork upgrades must stall instead of deleting the active gateway pod first.
13. Add Mieru/RESTLS experimental direct values, disabled by default.
14. Add TUIC v5 lab profile and compare against Hysteria2 after the base 2.1 rollout is stable.

## Acceptance tests

- `helm template` renders with Transit-only and Entry+Transit values.
- Gateway pods fail fast when required private Secret files are missing, placeholder-filled or request host-wide interception.
- `profiles` and `link-crypto` reload hooks validate generated handoffs and write redacted markers without logging profile bodies; sidecars do not start from missing or stale validation state.
- Adding, revoking and rotating 100 users causes zero gateway pod restarts.
- WireGuard peer add/remove changes live interface state without restarting WSTunnel or WireGuard.
- ShadowTLS outer config remains stable during per-user Shadowsocks changes.
- Private encrypted link profile bodies never appear in Helm values, ConfigMaps, rendered manifests, logs or Git-tracked files.
- Rotating an `entry-transit` Mieru generation moves new chain flows without dropping unrelated host traffic.
- Killing zapret2 wrapper does not drop existing non-zapret Tracegate connections and does not affect SSH/control-plane access.
- Restarting or rotating MTProto obfuscation may interrupt Telegram Proxy sessions, but does not restart or degrade V1-V7.
- MTProto grants continue to issue stable `tg://proxy` and `https://t.me/proxy` links after Helm reinstall/upgrade.
- Decoy asset update does not change gateway pod template hash.
- Entry CPU stays within budget under V2/V6 chain load with zapret2 enabled.
- V4 remains usable when the TCP bridge is active, and lab metrics explicitly record UDP-over-TCP penalty.

## Sources checked

- Current repository docs and private handoff scaffolds in `README.md`, `CHANGELOG.md`, `deploy/systemd/private-example`.
- Historical k3s chart at commit `cd3138b` and WireGuard/Hysteria backplane changes around `f1c5d38` and `0244870`.
- Current MTProto scaffold in `deploy/systemd/private-example/mtproto` and MTProto helpers in `src/tracegate/services/mtproto.py`.
- WSTunnel upstream: https://github.com/erebe/wstunnel
- WireGuard quick start: https://www.wireguard.com/quickstart/
- Shadowsocks SIP022: https://shadowsocks.org/doc/sip022.html
- ShadowTLS V3 upstream notes: https://github.com/ihciah/shadow-tls/wiki/V3-Protocol
- sing-box ShadowTLS docs: https://sing-box.sagernet.org/configuration/inbound/shadowtls/
- sing-box Shadowsocks docs: https://sing-box.sagernet.org/configuration/inbound/shadowsocks/
- sing-box WireGuard endpoint docs: https://sing-box.sagernet.org/configuration/endpoint/wireguard/
- Hysteria2 docs: https://www.hy2.io/
- sing-box Hysteria2 docs: https://sing-box.sagernet.org/configuration/inbound/hysteria2/
- TUIC protocol repo: https://github.com/tuic-protocol/tuic
- sing-box TUIC docs: https://sing-box.sagernet.org/configuration/inbound/tuic/
- Mieru upstream: https://github.com/enfein/mieru
- RESTLS upstream: https://github.com/3andne/restls
