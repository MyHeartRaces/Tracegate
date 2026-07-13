# Host runtime services

Tracegate production uses Linux hosts with systemd, Docker and host networking.
The public repository ships only generic units; private environment files,
credentials and rendered profiles remain operator-managed.

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
