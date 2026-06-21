# Protocols & DPI Resistance

The stealth core of Tracegate. Per-protocol deep dive (server + client + stealth
properties), the SNI-demux design, the SNI catalog strategy, and the DPI threat
model. The authoritative server-side rendering is
`deploy/k3s/tracegate/templates/configmaps.yaml`; client-side rendering is
`src/tracegate/client_export/config.py`. The `bundles/` directory holds generic
reference templates only.

## 1. The shared surface: TLS/443 with SNI demux

Every TCP transport is multiplexed onto **TCP/443** and routed by HAProxy on the
**TLS SNI** in the ClientHello (`configmaps.yaml`, frontend
`fe_tracegate_<role>_tls`). The external fingerprint is therefore "a single TLS
service on 443," which is the only shape that reliably survives a TLS-only
environment.

Demux order (first match wins), each to a loopback backend:

| SNI matches | Backend | Transport |
|-------------|---------|-----------|
| ShadowTLS `serverName` | `be_shadowtls` | Shadowsocks-2022 + ShadowTLS v3 |
| MTProto FakeTLS SNI | `be_mtproto*` | Telemt (MTProto) |
| chain-bridge / Reality multi-group SNIs | `be_chain_bridge_*` / `be_reality_*` | Entry↔Endpoint XHTTP/Reality |
| TLS-adapter serverName(s) | `be_https_adapter` (nginx) | VLESS-WS, VLESS-gRPC, WireGuard-WS, Grafana, client-config |
| (default) | `be_reality` | VLESS + Reality (XHTTP) |

Per-source protection on the frontend (Entry ingress): a stick-table caps
**concurrent connections per source** (`maxConnectionsPerSource`, default 8) and
**new connections per 10s** (`newConnectionsPer10Seconds`, default 12), with a
5s `inspect-delay` so routing waits for the SNI. This directly implements the DPI
note "limit simultaneous new TLS sessions per public name."

UDP/443 is **not** on this frontend — it is owned end-to-end by the standalone
Hysteria2 process.

## 2. VLESS + Reality (XHTTP) — primary direct profile

**Server** (`vless-reality-in` / `entry-in`): `protocol: vless`,
`network: xhttp`, `security: reality`. Reality settings: `dest` (the real
upstream handshake target), `serverNames` (accepted SNIs), `privateKey`
(injected from the private Secret), `shortIds`, `xhttpSettings.path:
/api/v1/update`, `show: false`. Sniffing enabled (`http`, `tls`, `quic`) for
routing.

**Why it is stealthy.** Reality has **no certificate of its own**: it proxies the
TLS handshake to a real third-party site (`dest`) and only "steals" the session
for authenticated clients, so SNI inspection and certificate-chain inspection see
a genuine visit to that site. XHTTP framing makes the inner stream look like
ordinary HTTP traffic. There is no proxy-shaped ClientHello to fingerprint.

**Hard dependency.** The whole argument collapses if `dest`/`serverNames` is a
domain that is unreachable, DPI-flagged, or atypical for the IP. This is the SNI
catalog's job (§7) and the subject of finding F8.

**Client** (`client_export/config.py`): emits the Reality public key, shortId,
`serverName`, `fingerprint: chrome`, XHTTP path. The control plane assigns a free
`(Endpoint shard IP, SNI)` pair from the configured pool and prevents reuse while
a revision is active (no user-chosen SNI for direct Reality).

## 3. Hysteria2 (+ Salamander) — primary direct UDP profile

**Server** (standalone `hysteria` sidecar, `server.yaml`): listens UDP/443; TLS
cert/key with `sniGuard: dns-san`; `auth.type: http` to the agent
`/v1/hysteria/auth` with `insecure: false`; **`obfs.type: salamander`**
(mandatory, password from the Secret); **`masquerade.type: file`** serving the
decoy directory; QUIC `maxIdleTimeout: 30s`; `congestion.type: bbr`;
`trafficStats` on loopback with a secret.

**Why it is stealthy.** Salamander obfuscates the QUIC/UDP packets so they do not
carry a Hysteria2 signature; the masquerade makes an HTTP/3 prober (or a browser
hitting the IP) see a plausible website instead of a proxy; auth is out-of-band
via the control plane. UDP is treated as a *measured* secondary — the guide tells
users to prefer Entry Chain on mobile and not to start with Hysteria2 when UDP is
throttled.

**Backhaul variant** (`backhaul-client.yaml`, Entry→Endpoint): the same Hysteria2
with Salamander as a secondary backhaul transport behind the XHTTP/Reality
primary; `insecure: false`, conservative BBR profile, SOCKS5 on loopback.

## 4. Shadowsocks-2022 + ShadowTLS v3 — Backup profile

**Server**: an Xray `shadowsocks` inbound (`ss2022-in`, loopback) with method
`2022-blake3-aes-128-gcm`, fronted by a `shadow-tls --v3 server` sidecar
(`--listen 127.0.0.1:14443 --server 127.0.0.1:18443`). HAProxy routes the
ShadowTLS `serverName` to `be_shadowtls`.

**Why it is stealthy.** SS-2022 is an AEAD construction (`2022-blake3-aes-*-gcm`)
with replay protection and no length/header tells of older Shadowsocks. ShadowTLS
v3 wraps it in a *real* TLS handshake to `serverName`, so the outer flow is
indistinguishable from a TLS visit to that domain. Node-side ShadowTLS outer
credentials are static; SS-2022 user keys remain per-connection.

**Critical invariants** (chart-guarded): the ShadowTLS `serverName` must be
**distinct** from the active Reality SNI pool (SNI-demux collision guard in
`secrets.yaml`) and must not be a forbidden FakeTLS domain. F8 fixed a default
(`splitter.wb.ru`) that violated the latter; a regression test now guards it.

**Client**: `client_export/config.py` emits SS-2022 + ShadowTLS v3 with a warning
that clients importing it as plain Shadowsocks will time out (the ShadowTLS plugin
is required).

## 5. VLESS-WS and VLESS-gRPC — Backup profiles

**Server**: `vless-ws-in` (`network: ws`, path `/ws`, `security: none`) and
`vless-grpc-in` (`network: grpc`, serviceName `tracegate.v1.Edge`,
`security: none`) listen on loopback; **nginx** (`be_https_adapter`) terminates
TLS 1.2/1.3 and proxies the WS upgrade / gRPC to them. Heartbeat on WS (15s).

**Why it is stealthy.** Both ride a normal nginx TLS vhost with a real
certificate, so the outer fingerprint is a standard HTTPS site serving WebSocket
/ gRPC. Backup VLESS gRPC is intended behind Cloudflare (proxied `proxy_fqdn`,
HTTP/2); Backup VLESS WS uses the direct Endpoint site hostname (HTTP/1.1) with
its real cert. Raw Reality/Hysteria2/MTProto records must stay DNS-only.

## 6. WireGuard-over-WebSocket — Backup profile

**Server**: a `wireguard` sidecar plus `wstunnel`; nginx exposes the WG-WS path
(`wireguard.wstunnel.publicPath`, default `/wgws`) on the TLS vhost and proxies
the WS upgrade to the wstunnel websocket port.

**Why it is stealthy.** Raw WireGuard has an unmistakable UDP handshake
fingerprint; wrapping it in a WS/TLS upgrade behind nginx makes it look like
ordinary WebSocket traffic on 443. Client defaults: `wireguard_mtu: 1280`,
`allowed_ips: 0.0.0.0/0, ::/0`, `dns: 1.1.1.1`; the server public key is
client-safe, private material stays in the Secret.

## 7. MTProto (Telemt, FakeTLS)

**Server**: Telemt on the Endpoint, `route.mode = entry-endpoint-tunnel`. The
public MTProto hostname (DNS-only) resolves to the same Entry IP as the other
Entry TCP/443 transports; HAProxy demuxes the FakeTLS SNI to an Entry-local Xray
tunnel inbound that carries it to Endpoint-local Telemt. The Endpoint exposes no
public MTProto listener.

**Stealth rules** (enforced in `values.yaml` + chart):
- FakeTLS SNI is `ctlog2024.mail.ru` (from the Russian mobile whitelist),
  distinct from the public address hostname.
- `mtproto.stealth.forbiddenTlsDomains` deny-lists `yandex.ru`, `splitter.wb.ru`;
  `requireWhitelistedTlsDomain: true`; Telemt `unknown_sni_action = "mask"`.
- The 16-byte secret is validated (32 hex chars) in the seed-runtime init.

MTProto is deliberately **separate from the VPN profiles** — a Telegram-only
access path, not a VPN replacement.

## 8. Entry ↔ Endpoint backhaul

Universal Entry uses a **bounded XHTTP/REALITY shard pool** as primary and a
**single shared Hysteria2/Salamander** client sidecar as secondary. It does *not*
start a process per user and does *not* race both transports in parallel
(`maxParallelHandshakes: 1`, `multiplexSingleTls: true`). An Xray balancer
(`endpoint-backhaul`) round-robins the XHTTP shards with the Hysteria2 outbound as
`fallbackTag`; an observatory probes shard health. The backhaul fails closed and
is the only client egress path for Entry — Entry ingress IPs are never egress
identities.

## 9. SNI catalog strategy

`src/tracegate/staticdata/sni_catalog.yaml` is the single source of truth for
camouflage domains: each entry has a stable `id` (referenced by revisions),
`enabled` state, and an operational `note` (e.g. "TLS 1.3 verified from production
Endpoint" vs "handshake timed out from production"). Exactly 10 are enabled at a
time; `test_sni_catalog_integrity.py` enforces ordering, provider hygiene, and
that known-bad domains (`yandex.ru`, `splitter.wb.ru`, `vk.com`, `ok.ru`,
`www.wildberries.ru`) are never enabled.

Front selection rules (the project's own methodology, `docs/dpi-research-notes.md`
and `protocols-and-routing.md`):
- Use only reviewed, **less-popular** domains from the maintained whitelist; never
  Google/Bing/Microsoft/arbitrary third-party SNI.
- Treat reachability/TLS-1.3 as a **measured property** validated from the target
  network — not a config assumption.
- ShadowTLS / chain fronts must be **distinct** from the Reality lease pool.

Finding **F8** is exactly a drift from rule 1–2 (defaults pointing at
catalog-disabled / forbidden fronts); see
[90-findings-register.md](90-findings-register.md).

## 10. Routing & split-tunnel

Xray routing (`configmaps.yaml`): `bittorrent` is blackholed on all user
inbounds; `geoip:private` is blocked. In non-`entry-endpoint` Entry mode, Russian
domains (`geosite:category-ru`, an extensive TLD regex set, and the bundled
`russia-mobile-internet-whitelist.txt`) and `geoip:ru` go **direct**, the rest is
backhauled — a split-tunnel that keeps domestic traffic off the proxy path. In
`entry-endpoint` mode the Entry backhauls all user traffic to Endpoint.

## 11. Port matrix

| Port | Proto | Owner | Notes |
|------|-------|-------|-------|
| 443 | TCP | HAProxy | SNI demux → all TCP transports |
| 443 | UDP | Hysteria2 | Salamander + masquerade |
| 4443 | UDP | interconnect | Entry↔Endpoint backhaul (`TRACEGATE_INTERCONNECT_UDP_PORT`) |
| 8443 | TCP+UDP | — | forbidden public port (`TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT`), dropped |
| 8070 | TCP | agent | inter-node control (nftables-gated) |
| 80 | TCP | nginx (Endpoint) | decoy + ACME + redirects |
| loopback | — | sidecars | xray/ss2022/shadowtls/wstunnel/telemt backends |

(F4 corrected a stale bundle comment that mislabeled UDP/4443 as the Hysteria2
port.)
