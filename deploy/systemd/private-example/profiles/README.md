# Tracegate private profile adapter scaffold

This directory is a public scaffold for V5/V6/V7 private transport adapters.

The agent writes private desired state here:

- `<private-runtime-root>/profiles/entry/desired-state.json`
- `<private-runtime-root>/profiles/entry/desired-state.env`
- `<private-runtime-root>/profiles/transit/desired-state.json`
- `<private-runtime-root>/profiles/transit/desired-state.env`

Unlike the link-crypto handoff, this desired state contains secret material for
Shadowsocks-2022, ShadowTLS V3, WireGuard/WSTunnel and required local SOCKS5 auth.
Keep it under the private runtime root and never commit rendered copies.

Operational rules:

- keep `TRACEGATE_PROFILES_ENABLED=false` until the private profile adapter exists
- keep `transportProfiles.localSocks.auth=required` and profile names aligned with the runtime contract
- require local SOCKS5 authentication for every generated profile, including loopback
- do not start anonymous local listeners
- do not apply host-wide packet interception
- do not restart existing profile generations during reload
- let the private runner own real `sing-box`, `shadow-tls`, `wstunnel` and WireGuard process layout

`run-profiles.sh.example` validates the private desired state and writes a redacted
manifest for operators. It intentionally does not print or copy profile secrets. When
enabled, it calls `TRACEGATE_PROFILES_RUNNER` and passes only the desired-state path and
manifest path through environment variables.
