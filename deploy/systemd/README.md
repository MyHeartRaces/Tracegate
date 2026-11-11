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

Before packaging or rollout, run `python3 scripts/check_host_runtime.py` and
`tracegate-host-private-preflight` for each role-specific private profile tree.

The units in this directory are the canonical host data-plane runtime. Engine
units never pull at start: each one reads
`EnvironmentFile=/var/lib/tracegate/artifacts/active/<component>.env` (a single
`TRACEGATE_IMAGE=<repo>@sha256:<digest>` line written by `tracegate-artifacts`),
runs `/usr/local/sbin/tracegate-artifact-verify <component>` as its first
`ExecStartPre` (read-only; fails with the next command to run when the recorded
image is missing), and starts `${TRACEGATE_IMAGE}`. A restart therefore cannot
change an engine version, and an unreachable registry never blocks a start.
New engine versions are staged explicitly with `tracegate-artifacts stage`,
probed, promoted and restarted one unit at a time; `tracegate-artifacts
status` reports drift between running containers and the recorded digests.
Environment-specific values stay outside the release. The `tracegate-shadowtls-backhaul-env`,
`tracegate-shadowtls-backhaul2-env`, `tracegate-shadowtls-entry-env` and
`tracegate-shadowtls-entry2-env` helpers derive the root-only ShadowTLS service
environments from `/etc/tracegate/tracegate.env` and the private overlay.

Shadowsocks-2022 is terminated by the `ss2022-backhaul-in` inbound in the
isolated `tracegate-xray-ss2022` process. Xray cannot mutate Shadowsocks-2022
users with HandlerService, so the agent restarts only this dedicated runtime
when an SS connection is issued or revoked. Primary VLESS/REALITY sessions are
unaffected. The former standalone `ssserver` unit must not run because the
isolated Xray runtime owns `127.0.0.1:18444`.
