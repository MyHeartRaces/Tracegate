# Tracegate 3 Architecture

Tracegate 3 is the two-node Entry and Endpoint architecture. Client-facing
services share one Entry address. User traffic and Telegram proxy traffic leave
through Endpoint.

## Client Profiles

The bot exposes devices inside `Connections`. A user may have up to three
devices and each device may have up to seven connections.

Primary profiles:

- `VLESS Reality`
- `Hysteria2`
- `Entry Chain (Mobile)`

Backup profiles:

- `VLESS gRPC`: Cloudflare-proxied Endpoint hostname over HTTP/2;
- `VLESS WebSocket`: direct Endpoint site hostname with its real TLS certificate;
- `Shadowsocks`
- `WireGuard over WebSocket`

NaiveProxy and the old per-transport Chain profile variants are not issued in
Tracegate 3.

## Shared Entry Surface

The one-address Entry contract uses:

- TCP/443: HAProxy L4 SNI demux for TLS, Reality/XHTTP and MTProto FakeTLS;
- UDP/443: public Hysteria2;
- UDP/4443: private legacy link-crypto interconnect only;
- a global Entry traffic cap of 65 Mbit/s.

Raw MTProto TCP cannot use an ordinary Cloudflare proxied record. Its public
hostname must be DNS-only and resolve to the shared Entry address.

## MTProto Data Path

```text
Telegram client
  -> DNS-only public MTProto hostname:443 on Entry
  -> HAProxy FakeTLS SNI demux
  -> Entry-local Xray tunnel inbound
  -> authenticated Reality/XHTTP Entry-to-Endpoint backhaul
  -> Endpoint-local Telemt
  -> Telegram network through Endpoint egress
```

Telemt runs only on Endpoint and listens on loopback. Endpoint does not expose a
public MTProto frontend in `entry-endpoint-tunnel` mode. Xray does not preserve
the HAProxy PROXY header, so Telemt uses `proxy_protocol = false` in this mode.

The initial public-safe FakeTLS SNI is `ctlog2024.mail.ru`, selected from the
bundled Russian mobile whitelist. It is not a permanent value. Operators must
probe candidate domains from target networks before adding them to
`mtproto.stealth.validatedTlsDomains`.

MTProto invariants:

- public address hostname and FakeTLS SNI must differ;
- `yandex.ru` and `splitter.wb.ru` are forbidden MTProto FakeTLS SNI values;
- fallback runtimes are disabled in the two-node tunnel mode;
- SNI rotation must be preceded by TLS and sustained-payload validation;
- client traffic must fail closed if the Endpoint backhaul is unavailable.

## Backhaul

The primary Entry-to-Endpoint carrier is VLESS Reality/XHTTP with a small pool
of connect-level SNI shards. Hysteria2 with Salamander is the independent
fallback. Public-safe examples use less-popular domains from the bundled
whitelist rather than `yandex.ru` or `splitter.wb.ru`.

Only one backhaul dial is opened for a connection. Health checks remove failed
XHTTP shards without creating parallel connection bursts.

## Deploy Inputs

Public-safe starting points:

- `deploy/k3s/values-universal-entry.example.yaml`: one Entry address;
- `deploy/k3s/values-entry-endpoint.example.yaml`: sharded Entry reference;
- `deploy/k3s/prod-overlay-check.py`: production overlay validation.

Production overlays must provide real addresses, DNS names, pinned images,
external Secrets, TLS material and firewall state outside the public
repository.

The active Entry and Endpoint `NodeEndpoint` rows must set `proxy_fqdn` to
their respective Cloudflare-proxied gRPC hostnames. Raw Reality, Hysteria2,
WebSocket and MTProto hostnames remain outside that proxied surface.

## Validation

```bash
helm lint deploy/k3s/tracegate
helm template tracegate deploy/k3s/tracegate
helm template tracegate deploy/k3s/tracegate \
  -f deploy/k3s/values-universal-entry.example.yaml
pytest -q
```
