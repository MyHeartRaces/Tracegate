# Telegram resilience under DPI and whitelist networks

This document describes the availability model for Telegram in general
terms. It does not claim that one proxy endpoint can remain reachable under
every filtering policy. If a provider allows no route to a
Tracegate-controlled or relay destination, a server-side change cannot create
one. Deployment-specific routing is private state.

## Two paths

1. **Native MTProxy** for an unmodified Telegram client: a FakeTLS proxy link
   served by the deployment's Telegram Proxy runtime (Telemt).
2. **Telegram over a Tracegate tunnel**: the operating system or a router
   sends ordinary Telegram traffic through a working Tracegate profile, with
   Telegram's own proxy setting disabled.

The second path is the only generally useful design when a provider allows
HTTPS to a limited set of networks but blocks the proxy address.

## Filtering model

Published field reports describe several independent failure modes:

- destination IP, subnet or ASN classification;
- TLS ClientHello/SNI/fingerprint classification;
- a temporary freeze after a burst of parallel TLS handshakes;
- payload-volume limits on one TCP flow;
- active probing and protocol-specific packet-size classification;
- a strict allowlist under which an ingress address is never routable.

These modes require different responses. Changing SNI does not fix an IP/ASN
allowlist. REALITY or FakeTLS can imitate a TLS destination, but it does not
move packets to that destination's IP. A community domain whitelist is an
input for carrier testing, not proof that an arbitrary server using one of its
names will be allowed. Tracegate treats every SNI and fingerprint property as
provider-specific and expiring.

## Principles

- Telemt runs in TLS-only mode with a validated decoy name and a matching
  real-site mask; classic and secure MTProxy modes stay disabled.
- Issued proxy links keep working: secrets are not rotated underneath users,
  and access entries are regenerated atomically on issue and revoke without
  restarting the proxy.
- Telemt improves server-side TLS behaviour and active-probe masking, but it
  does not control the Telegram application's own ClientHello, and native
  Telegram has no MTProxy-over-WebSocket mode.
- A single ingress address is a single filtering and provider failure domain;
  name aliases on one address do not change that. Rotation on every
  connection attempt is not used: it increases handshake bursts and
  destabilizes clients.
- Availability is never claimed from a TCP-open check. A release gate needs an
  authenticated, sustained protocol probe through the public path.

## Whitelist-mode decision tree

1. If native MTProxy transfers sustained payload, use it.
2. If the proxy address is blocked but a Tracegate profile works, disable
   Telegram's internal proxy and use the system or router tunnel.
3. If the TCP carriers fail but an independent UDP path works, use a
   Hysteria2 profile.
4. If none of the controlled or relay destinations is reachable, report the
   path as unavailable. Do not loop through address or SNI rotations.

## Observability

- authenticated proxy probe success and duration;
- proxy runtime readiness, restarts and image digest;
- reconnect rate and successful payload duration per carrier;
- carrier results labelled by provider, access type and region, without
  storing user addresses or secrets.

Proxy access entries and generated links are secret material: keep them in
gateway state with mode `0600`, never on command lines or in shared logs. The
repository includes `scripts/probe_mtproto.py` for the authenticated part of
the release gate; feed the secret through stdin or an ignored file.

## References

- [Telegram MTProxy](https://github.com/TelegramMessenger/MTProxy)
- [Telemt](https://github.com/telemt/telemt)
- [net4people issue 490](https://github.com/net4people/bbs/issues/490)
- [June 2026 ClientHello observations](https://habr.com/ru/articles/1044396/)
- [Siberian blocking observations](https://habr.com/ru/articles/1010336/)
- [Community mobile whitelist dataset](https://github.com/hxehex/russia-mobile-internet-whitelist)
