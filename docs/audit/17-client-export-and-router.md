# Client Export & Tracegate-Router Compatibility

How structured connection data becomes importable client profiles, the supported
formats, and what "compatible with Tracegate-Router" means in practice.

## 1. Export builders (`src/tracegate/client_export`)

`config.py` renders one `ExportResult` per profile family from the *effective*
connection config:

| Family | Builder output | Title |
|--------|----------------|-------|
| VLESS + Reality (XHTTP) | URI link | "VLESS REALITY link" |
| VLESS WS+TLS | URI link | "VLESS WS+TLS link" |
| VLESS gRPC+TLS | URI link | "VLESS gRPC+TLS link" |
| Hysteria2 (direct / chain) | URI link | "Hysteria2 link" |
| Shadowsocks-2022 + ShadowTLS | `ss://` link + plugin opts | "Shadowsocks-2022 + ShadowTLS" |
| WireGuard-over-WS | WGWS config attachment | "WGWS config" |
| MTProto (FakeTLS) | `tg://` / `https://` link | "Telegram Proxy link" |

`export_v2rayn` renders the v2rayN format; `bundle.py` assembles a multi-profile
**bundle** (per-profile JSON records, links, and **sing-box outbounds**) for
clients that import a whole device at once.

## 2. Formats produced

- **URI links** (`vless://`, `hysteria2://`, `ss://`, `tg://`) for quick import.
- **JSON attachments** (sing-box-style outbounds via
  `_singbox_outbounds_for_profile`) for engine-level import.
- **Per-device bundles** combining the device's connections.
- **v2rayN** subscription format.

Each export carries the assigned `(server, port, sni, uuid/credentials, profile)`
and self-describing notes (e.g. the SS-2022 export warns that importing it as
plain Shadowsocks will time out without the ShadowTLS v3 plugin).

## 3. Delivery path

The bot delivers links/QR/JSON in-chat; the public `/client-config/<token>` path
(nginx → API) serves a bundle behind an **HMAC-signed, expiring** token
(`services/client_config_tokens.py`). One profile is intended per device — the bot
copy and welcome message enforce the "one profile, one device, one client"
discipline, and reissuing a revision rotates the `(shard, SNI)` pair.

## 4. Tracegate-Router compatibility

"Tracegate-Router" is the client-side router that consumes these exports as its
upstream transports. Compatibility is maintained through:

- **sing-box-compatible outbounds** (`bundle.py`), the common engine format the
  router and the recommended clients (Karing, INCY, Throne, Shadowrocket) accept.
- **Router profile selection sets** (`services/connection_profiles.py`):
  `router_transit_tcp_selected_profiles()` / `router_transit_udp_selected_profiles()`
  expose the curated profile families (e.g. `V0`/`V1`/`V2`/`V3`) the router pairs
  with its TCP and UDP link-crypto transports — mirrored in the chart's
  `linkCrypto.roles.*.selectedProfiles`.
- **Stable, structured fields** so the router can map a Tracegate profile to its
  own transport without bespoke parsing.

The private repo carries router-facing examples
(`client-configs/tracegate-personal-tun-rules.json.example`,
`shadowrocket-tracegate-ru-direct.conf`) that demonstrate the split-tunnel rules
(RU-direct) the exports are designed to feed.

## 5. Client guidance (security-relevant)

The bot guide actively steers users toward clients that keep local SOCKS/HTTP
proxies closed and authenticated, and warns against LAN/Port/Proxy sharing and
against importing one config into multiple devices. This is part of the threat
model: a careless client (open local proxy / external controller without auth) is
an exposure even when the transport is sound.
