# Tracegate 3 architecture

The new production target is deployed in two phases.

## Endpoint first

Endpoint has four public IPv4 addresses:

- one service/egress IP with no proxy client listeners;
- three direct/Backup client-ingress shard IPs.

Every Endpoint data-plane runtime runs in the k3s `gateway-transit`
compatibility pod, including Telemt and WireGuard-over-WebSocket. Gateway state
uses a PVC; hostPath data-plane state is forbidden.

Direct VLESS Reality revisions lease exclusive active
`(Endpoint shard IP, SNI)` pairs. HAProxy binds TCP only to active/draining
shards and mandatory host nftables rejects client ports on the service/egress
IP and disabled shards.

## Full phase

Entry adds one public IP after Endpoint validation. Entry Chain uses
Cloudflare-proxied gRPC/TLS/H2 and a bounded Entry-to-Endpoint backhaul pool:
VLESS Reality/XHTTP primary and Hysteria2/Salamander secondary. MTProto enters
through shared Entry TCP/443 and terminates at Endpoint-local Telemt.

All client internet traffic exits only through the Endpoint service/egress IP.
Entry retains the global 65 Mbit/s cap.

## Entry-to-Endpoint link-crypto interconnect

The secure Entry↔Endpoint interconnect runs an inner encrypted carrier inside
the mandatory WSS (wstunnel) outer tunnel. Mieru is the current inner carrier;
an additive migration to Shadowsocks-2022 (sing-box) is implemented behind
`interconnect.entryTransit.innerCarrier` (default `mieru`), with the carrier
swap gated on a production soak. The UDP backhaul stays on Hysteria2/Salamander.

## Excluded from new production

NaiveProxy (removed in Tracegate 3), MasterDNS, host-wide Zapret2 NFQUEUE,
legacy Transit, `transitRouter`, host-level LUKS runtime guards and
experimental profiles are outside the pod-only new-production contract.
Mieru and scoped zapret2 are **not** excluded — they are the active inner
link-crypto carrier and its flow-scoped DPI shaping.

## Public-safe inputs

- `deploy/k3s/values-endpoint-first.example.yaml`
- `deploy/k3s/values-entry-endpoint.example.yaml`
- `deploy/k3s/prod-overlay-check.py`
- `deploy/k3s/pod-runtime-readiness.py`
- `deploy/k3s/endpoint-ingress-firewall.py`
