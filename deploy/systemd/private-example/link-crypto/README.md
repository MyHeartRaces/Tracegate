# Tracegate private link-crypto scaffold

This directory is a public scaffold for the private Entry-Transit / Router-Entry /
Router-Transit link encryption adapter.

The agent writes the public desired state here:

- `<private-runtime-root>/link-crypto/entry/desired-state.json`
- `<private-runtime-root>/link-crypto/entry/desired-state.env`
- `<private-runtime-root>/link-crypto/transit/desired-state.json`
- `<private-runtime-root>/link-crypto/transit/desired-state.env`

The desired state intentionally contains no Mieru, Hysteria2, Salamander or
zapret2 packet profiles. It points at private files such as
`/etc/tracegate/private/mieru/client.json`,
`/etc/tracegate/private/mieru/server.json`,
`/etc/tracegate/private/udp-link/client.yaml` and scoped zapret2 profile files.

Operational rules:

- keep `TRACEGATE_LINK_CRYPTO_ENABLED=false` until the private Mieru profile is present
- use Mieru for the outer encrypted carrier
- use Hysteria2 with Salamander for UDP-capable link classes
- keep the handoff marked as `managedBy=link-crypto` and `xrayBackhaul=false`
- keep `transportProfiles.localSocks.auth=required` and never allow anonymous localhost SOCKS5
- apply zapret2 only to marked link-crypto flow, never to all host traffic
- do not use NFQUEUE or host-wide interception for this adapter
- keep UDP links fail-closed with anti-replay, anti-amplification, MTU clamp and source validation enabled
- use `tracegate-paired-udp-obfs-runner` with `paired-obfs.env` when paired UDP obfs is enabled
- keep `TRACEGATE_UDP_OBFS_AUTO_FIREWALL=false`; apply any firewall marks/rules in a private scoped layer
- reload must not restart existing link generations; start missing processes only
- place real Mieru, Hysteria2, Salamander and zapret2 profiles outside Git

`run-link-crypto.sh.example` validates the public handoff, writes a private last-action
record, calls an optional private runner, starts only missing `mieru run -c <profile>`
processes and delegates UDP-link process planning to `tracegate-link-crypto-runner`.
The bundled paired-obfs runner validates the private `paired-obfs.env` profile and
execs `udp2raw` in the foreground without writing secrets into runner plans. Replace
the shell wrapper with a private implementation when you need custom generation
draining, routing marks, nftables marks or router-side adapters.
