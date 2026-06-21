# Network Boundary & Egress Isolation

How Tracegate constrains what is reachable, enforces a single egress identity,
and fails closed. The host-level policy is rendered by the Python firewall
scripts in `deploy/k3s/`; the in-pod policy is HAProxy/nginx (see
[12-protocols-and-dpi.md](12-protocols-and-dpi.md)).

## 1. Design goals

1. **Client ingress identities are disjoint from the single egress identity** — a
   network observer cannot tie the egress IP to a specific client listener pool.
2. **Service IP carries no client bind** — control/egress surfaces are not also
   client entry points.
3. **Fail closed** — if the protected route or firewalls are not in place, traffic
   stops rather than leaking.
4. **Proxied origins are locked to the provider's source ranges** — a proxied DNS
   record must not leave a directly reachable probing target.

## 2. Host nftables renderers (rendered from chart values)

All four are pure renderers (`render(values) -> str`) that merge chart values
with the private overlay and emit an nftables table. They validate IPs/ports and
`SystemExit` on bad input, so a malformed overlay fails the render rather than
producing a permissive ruleset.

### `endpoint-ingress-firewall.py`
- Rejects client TCP ports on the **service IP + disabled shard IPs** with
  `tcp reset` (`iifname != "lo"`).
- Accepts client UDP on the service IP **only when `ct status dnat`** (i.e. it
  arrived via the egress DNAT) and drops it on the service/disabled IPs otherwise.
- Net effect: no client can bind/reach the service IP directly; only legitimately
  DNATed Hysteria2 UDP is accepted.

### `endpoint-egress-firewall.py`
- `prerouting` DNAT: shard UDP/443 → `service_ip:443`.
- `postrouting` SNAT: traffic from the shard IPs → `service_ip`.
- Net effect: all client egress leaves as the single service/egress identity; the
  three ingress shard IPs never appear as an egress source.

### `entry-ingress-firewall.py`
- Rejects client TCP ports (`tcp reset`) and drops client UDP on the Entry
  **service IP + disabled shard IPs** (incl. MTProto public port when enabled).

### `universal-entry-origin-firewall.py`
- Accepts Entry `:443` only from the Entry self IP and the configured **Cloudflare
  `allowedSourceCidrs`** (each validated as a **public + global IPv4** network);
  everything else gets `tcp reset`.
- Requires `originFirewall.required` and `denyDirectAccess`, and `publicTcp == 443`
  — enforcing the "restrict a proxied origin to the provider's current source
  ranges" DPI rule.

## 3. In-pod host nftables bundles

`bundles/base-entry/nftables.conf` and `bundles/base-transit/nftables.conf` are
the generic host base policies: default-drop input, allow established/related,
SSH, agent control (`8070`), public data-plane (`80/443` TCP, `443/4443` UDP), and
explicitly **drop** the forbidden split-guard ports (`tcp {4443,8443}`, `udp 8443`).
(F4 corrected the comment that mislabeled UDP/4443 — Hysteria2 is UDP/443; UDP/4443
is the interconnect backhaul, per `constants.py`.)

## 4. Agent-side egress enforcement

The chart pushes the egress-isolation contract to the agent as env
(`AGENT_EGRESS_*`, from `network.egressIsolation`):

- `required: true`, `mode: dedicated-egress-ip`.
- `forbidIngressIpAsEgress: true`, `requireTransitEgressPublicIP: true`.
- `clientLeakMitigation: egress-ip-only`.
- `enforcement.snat: required`, `enforcement.ingressPublicIpOutbound: forbidden`,
  `enforcement.managedBy: /etc/tracegate/private/egress-isolation`.

The agent validates these invariants and the runtime contract exposes them
(`configmaps.yaml` runtime-contract) so preflight can verify them.

## 5. Entry traffic shaping (tc)

When enabled (`gateway.trafficShaping.entry`), the agent applies an
`tc-htb-egress-plus-ingress-police` profile on the Entry host interface
(`failClosed: true`, `maxMbit`, `burstKbit`). This bounds per-Entry throughput so
a single Entry cannot become an obvious high-volume outlier. Chain-client Hysteria2
rate limits and `ignoreClientBandwidth` are likewise contract-driven.

## 6. Fail-closed chain

| Stage | Control |
|-------|---------|
| Deploy | `deploy.sh` refuses rollout unless Endpoint ingress/egress (and Entry origin, past `endpoint-first`) firewalls are active |
| Render | Firewall renderers `SystemExit` on invalid IP/port/CIDR; chart `secrets.yaml` `fail`s on contract violations |
| Runtime | Entry fails closed when the Endpoint route is down; backhaul `failClosed: true` |
| Ingress | service/disabled IPs reject client ports; UDP only via DNAT |
| Origin | Universal Entry `:443` restricted to Cloudflare CIDRs |

## 7. Port exposure summary

See the port matrix in [12-protocols-and-dpi.md](12-protocols-and-dpi.md) §11.
Public exposure is intentionally minimal: TCP/443 (SNI demux), UDP/443
(Hysteria2), UDP/4443 (interconnect, between the two nodes only), and SSH for
management. Everything else is loopback or nftables-gated.
