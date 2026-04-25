# Tracegate private link-crypto scaffold

This directory is a public scaffold for the private Entry-Transit / Router-Entry /
Router-Transit link encryption adapter.

The agent writes the public desired state here:

- `<private-runtime-root>/link-crypto/entry/desired-state.json`
- `<private-runtime-root>/link-crypto/entry/desired-state.env`
- `<private-runtime-root>/link-crypto/transit/desired-state.json`
- `<private-runtime-root>/link-crypto/transit/desired-state.env`

The desired state intentionally contains no Mieru credentials or zapret2 packet
profiles. It points at private files such as `/etc/tracegate/private/mieru/client.json`,
`/etc/tracegate/private/mieru/server.json` and scoped zapret2 profile files.

Operational rules:

- keep `TRACEGATE_LINK_CRYPTO_ENABLED=false` until the private Mieru profile is present
- use Mieru for the outer encrypted carrier
- keep the handoff marked as `managedBy=link-crypto` and `xrayBackhaul=false`
- keep `transportProfiles.localSocks.auth=required` and never allow anonymous localhost SOCKS5
- apply zapret2 only to marked link-crypto flow, never to all host traffic
- do not use NFQUEUE or host-wide interception for this adapter
- reload must not restart existing link generations; start missing processes only
- place real Mieru and zapret2 profiles outside Git

`run-link-crypto.sh.example` validates the public handoff, writes a private last-action
record, calls an optional private runner, and starts only missing `mieru run -c <profile>`
processes. Replace it with a private implementation when you need custom generation
draining, routing marks, nftables marks, or router-side adapters.
