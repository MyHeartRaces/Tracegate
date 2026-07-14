---
name: tracegate-hysteria-udp-diagnostics
description: >
  Use this skill when Tracegate Hysteria connections disconnect periodically,
  QUIC streams collapse together, or a host-runtime migration may have lost
  Linux UDP tuning. Diagnose live packet loss, restore the tracked host sysctl
  contract, and verify both Hysteria modes without exposing client credentials.
license: MIT
metadata:
  author: Tracegate maintainers
  version: "1.0"
---

# Tracegate Hysteria UDP diagnostics

This procedure separates a Hysteria service failure from kernel-level UDP
receive-buffer loss and keeps the permanent fix in the host-based release.

**Failure pattern:** Hysteria services stay active while multiple QUIC streams
end with `timeout: no recent network activity`; `UdpRcvbufErrors` grows because
the host reverted to the roughly 208 KiB Linux defaults after a reboot or
deployment migration.

**Verified by:** both Gecko and Salamander transferred 25 MB through
authenticated clients with HTTP 200, all 728 repository tests passed, and
`UdpRcvbufErrors` did not increase after the fix and load test.

## When to use this

- Hysteria disconnects recur without a corresponding systemd or container restart.
- Several streams on one QUIC session close at the same timestamp.
- The host-based runtime was reinstalled, rebooted, or migrated from the retired k3s deployment.

## Procedure

- [ ] 1. Establish whether the process or network device failed. Check both
  Hysteria services, `NRestarts`, recent journals, NIC error/drop counters,
  conntrack occupancy, memory pressure, and OOM events. Do not restart anything
  until the evidence is captured.

- [ ] 2. Record the cumulative kernel UDP counters and current buffer limits:

  ```sh
  nstat -az | awk '/UdpInErrors|UdpRcvbufErrors|UdpSndbufErrors/{print}'
  sysctl net.core.rmem_default net.core.rmem_max \
    net.core.wmem_default net.core.wmem_max
  ```

  Treat growth in `UdpRcvbufErrors` as direct evidence that the receive socket
  could not accept packets. Compare deltas; these counters do not reset when a
  service restarts.

- [ ] 3. Make the fix in the public host-runtime contract. The canonical file
  is `deploy/host/90-tracegate-quic.conf`, and
  `deploy/host/tracegate-host-install` must copy and apply it. Keep all four
  default/max receive/send values at 16 MiB. Extend
  `scripts/check_host_runtime.py` and its test when the contract changes.

- [ ] 4. Apply the tracked file to the affected host using operator-provided
  SSH host/key inputs. Do not paste credentials or private environment files
  into commands, logs, the public repo, or this skill. Install it as
  `/etc/sysctl.d/90-tracegate-quic.conf`, apply it with `sysctl -p`, then restart
  only the Gecko and Salamander Hysteria services so their sockets are recreated
  under the new limits.

- [ ] 5. Confirm the actual socket buffers rather than only the global sysctl:

  ```sh
  ss -u -a -m -n -p
  ```

  The UDP/443 and UDP/8444 listeners should report `rb16777216` and
  `tb16777216`. Both services must remain active with `NRestarts=0` after the
  intentional restart.

- [ ] 6. Run authenticated payload probes for both active obfuscation modes.
  Obtain temporary client configs through the normal production export or
  database-backed application path without printing secrets. Delete the files
  and containers afterward. A port-open probe alone is insufficient.

- [ ] 7. Sample `UdpRcvbufErrors` for several minutes and again after payload
  load. It must stay at the recorded baseline. Run the full test suite, build
  the host-runtime archive, confirm the sysctl profile is inside it, and run the
  public-release privacy check before pushing.

## Gotchas

- The current production layout is host-based systemd plus Docker. Do not put
  the fix back under retired `deploy/k3s`; it will not reach the host.
- A healthy listener or one successful request does not disprove burst loss.
  Use kernel counter deltas and an authenticated transfer for both Gecko and
  Salamander.
- Multiple production addresses may belong to the same host. Verify interfaces
  before treating them as an independent external probe source.
- The active Hysteria configs and `/etc/tracegate/tracegate.env` contain
  credentials. Inspect structure or generate ephemeral probe files without
  emitting their values, then remove the files.

## What didn't work

- Looking only at systemd restarts, NIC errors, or conntrack usage missed the
  failure: all were healthy while the kernel had already accumulated UDP
  receive-buffer drops.
- Restarting Hysteria alone temporarily cleared sessions but left the roughly
  208 KiB limit in place, so the failure could recur and the tuning would still
  be lost after reboot.
- Reusing the old k3s sysctl location looked historically correct but was inert
  after the host-runtime migration.
