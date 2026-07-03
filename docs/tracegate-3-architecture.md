# Tracegate 3 architecture

The new production target is deployed in two phases.

## Endpoint first

Endpoint has four public IPv4 addresses:

- one service/egress IP with no proxy client listeners;
- three direct/Backup client-ingress shard IPs.

Every Endpoint data-plane runtime runs in the k3s `gateway-endpoint` pod,
including MTG and WireGuard-over-WebSocket. Gateway state uses a PVC;
hostPath data-plane state is forbidden.

Direct VLESS Reality revisions lease exclusive active
`(Endpoint shard IP, SNI)` pairs. HAProxy binds TCP only to active/draining
shards and mandatory host nftables rejects client ports on the service/egress
IP and disabled shards.

## Full phase

Entry adds one public IP after Endpoint validation. Entry Chain uses
Cloudflare-proxied gRPC/TLS/H2 and a bounded Entry-to-Endpoint backhaul pool:
Shadowsocks-2022/ShadowTLS v3 primary and Hysteria2/Gecko secondary. MTProto
enters through shared Entry TCP/443 and terminates at Endpoint-local Telemt in
TLS-only FakeTLS mode. Direct Hysteria2 additionally exposes a dedicated
Salamander listener for broad client compatibility; Gecko remains available.

All client internet traffic exits only through the Endpoint service/egress IP.
Entry retains the global 65 Mbit/s cap.

## Entry-to-Endpoint link-crypto interconnect

The secure Entry↔Endpoint interconnect runs a sing-box Shadowsocks-2022 AEAD
inner carrier with ShadowTLS v3 camouflage inside the mandatory WSS
(wstunnel) outer tunnel. `interconnect.entryTransit.innerCarrier` is locked to
`shadowsocks2022`; promotion checks require SS2022 AEAD, ShadowTLS v3,
SPKI-pinned WSS, HMAC admission and no direct backhaul. The UDP backhaul uses
Hysteria2/Gecko.

## Excluded from new production

NaiveProxy, MasterDNS, host-wide Zapret2 NFQUEUE, legacy Transit,
`transitRouter`, host-level LUKS runtime guards and experimental profiles are
outside the pod-only new-production contract. Scoped zapret2 may still exist
for non-link-crypto surfaces such as MTProto, but it is not part of the TCP
link-crypto carrier.

## Public-safe inputs

- `deploy/k3s/values-endpoint-first.example.yaml`
- `deploy/k3s/values-entry-endpoint.example.yaml`
- `deploy/k3s/prod-overlay-check.py`
- `deploy/k3s/pod-runtime-readiness.py`
- `deploy/k3s/endpoint-ingress-firewall.py`
