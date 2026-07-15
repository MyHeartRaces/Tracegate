# Host runtime services

Tracegate production uses Linux hosts with systemd, host PostgreSQL, Docker
data-plane processes and host networking. The units here are the complete
native Entry/Endpoint runtime; private environment files, credentials and
rendered profiles remain operator-managed.

`tracegate-clock-sync-from-rtc.timer` is an opt-in fallback for hosts where:

- NTP/UDP 123 is blocked;
- the host RTC has been verified against an external trusted clock;
- system clock drift is large enough to break timestamp-authenticated
  transports such as MTProto FakeTLS.

Install the service and timer in `/etc/systemd/system/`, then enable the timer.
Do not enable it on hosts with an untrusted or local-time RTC.

`tracegate-wireguard-sync.service` connects the host-based WireGuard runtime to
the canonical private profile handoff written by the Endpoint agent. It applies
WGWS peers live with `wg set`, removes revoked peers, and does not restart the
WireGuard or WSTunnel data plane.

Before packaging or rollout, run `python3 scripts/check_host_runtime.py` and
`tracegate-host-private-preflight` for each role-specific private profile tree.

The units in this directory are the canonical host data-plane runtime. They
pull upstream `latest` images before every start. Environment-specific values
stay outside the release. `tracegate-shadowtls-env` derives the root-only
ShadowTLS service environment from `/etc/tracegate/tracegate.env`; the example
file documents the two resulting fields without containing a real secret.

Shadowsocks-2022 is terminated by the `ss2022-in` inbound in the isolated
`tracegate-xray-ss2022` process. Xray cannot mutate Shadowsocks-2022 users with
HandlerService, so the agent restarts only this dedicated runtime when an SS
connection is issued or revoked. Primary VLESS/REALITY sessions are unaffected.
The former standalone `ssserver` unit must not run because the isolated Xray
runtime owns `127.0.0.1:18443`.
