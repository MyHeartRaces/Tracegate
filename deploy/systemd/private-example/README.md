# Tracegate 2 private overlays

This directory is intentionally outside the public repository contract.

Use it for:

- private `Xray` overlay fragments that should not be committed
- local post-render automation such as `zapret2` bootstrap
- optional static/auth surfaces and local-only host tuning

The public renderer reads these locations:

- `/etc/tracegate/private/overlays/entry`
- `/etc/tracegate/private/overlays/transit`
- `/etc/tracegate/private/render-hook.sh`
- `/etc/tracegate/private/systemd`
- `/etc/tracegate/private/fronting`
- `/etc/tracegate/private/profiles`
- `/etc/tracegate/private/link-crypto`
- `/etc/tracegate/private/zapret`
- `/etc/tracegate/private/mtproto`

`install.sh` now seeds these public handoff locations from the matching `*.example`
files when the live targets are still missing, so a fresh testbed starts with a
working baseline without manual copies.

The agent also emits a public runtime snapshot for local wrappers:

- `/var/lib/tracegate/agent-entry/runtime/runtime-contract.json`
- `/var/lib/tracegate/agent-transit/runtime/runtime-contract.json`
- `<private-runtime-root>/obfuscation/<role>/runtime-state.json`
- `<private-runtime-root>/obfuscation/<role>/runtime-state.env`
- `<private-runtime-root>/profiles/<role>/desired-state.json`
- `<private-runtime-root>/profiles/<role>/desired-state.env`
- `<private-runtime-root>/link-crypto/<role>/desired-state.json`
- `<private-runtime-root>/link-crypto/<role>/desired-state.env`

`<private-runtime-root>` defaults to the sibling `private/` directory next to `AGENT_DATA_ROOT`
for the stock systemd layout, or can be forced explicitly via `PRIVATE_RUNTIME_ROOT`.
`validate-runtime-contracts.sh` consumes the profile and link-crypto desired-state files when
present and fails promotion if local SOCKS5 auth is disabled, host-wide interception or broad
NFQUEUE is enabled, or V5/V6/V7 private material still contains placeholders.

Supported overlay file names:

- `xray.merge.json`: deep-merge into the rendered `xray.json`
- `xray.json`: full replacement
- `haproxy.cfg`, `nginx.conf`, `nftables.conf`: full replacement
- `decoy/`: optional static/auth content copied into the active decoy root when present

Important limitation:

- Tracegate 2.2 uses standalone Hysteria2 for the public UDP surface; Xray-native Hysteria is legacy compatibility only.
- `FinalMask` and `TLS ECH` are `Xray` features. They can be injected through private overlays only where the actual runtime leg is terminated by `Xray`.
- `zapret2` is intentionally not modeled in the public repo. Use `render-hook.sh` or host-local systemd units to keep the packet-splitting policy private.
- the seeded wrapper examples consume the same public runtime-state handoff contract, but never ship the actual `zapret2` policy or segmentation algorithm
- `xray-centric` typically needs a full `xray.json` replacement instead of a shallow merge, because transport arrays such as `inbounds`, `outbounds` and `routing.rules` are replaced as full lists during overlay merge.
- If you are operating the legacy `xray-centric` profile and want the public renderer to inject private `FinalMask` or `ECH` into the generated Xray-native Hysteria inbound, point the shared env at private files such as `XRAY_HYSTERIA_FINALMASK_{ENTRY,TRANSIT}_FILE` and `XRAY_HYSTERIA_ECH_SERVER_KEYS_{ENTRY,TRANSIT}_FILE`. Keep the file contents private; only the file paths belong in host-local env.

Xray-centric migration note:

- The current code keeps Xray-native Hysteria client row support only for the explicit legacy `xray-centric` path.
- The generated private `xray.json` replacements are an activation mechanism for that compatibility path, not for the Tracegate 2.2 default.

Recommended workflow:

1. Edit the shared env in `/etc/tracegate/tracegate.env`.
2. Place private overlay fragments under `/etc/tracegate/private/overlays/{entry,transit}`.
3. Run `render-materialized-bundles.sh`.
4. Reapply bundles through the API so the agent refreshes `runtime/*` and `runtime-contract.json`.
5. Run `validate-runtime-contracts.sh` on a testbed before promoting the overlay set to production.
6. Run `render-xray-centric-overlays.sh` only when the private overlay set needs full replacement `xray.json` files for the explicit legacy xray-centric path.
7. Optionally implement `/etc/tracegate/private/render-hook.sh` for local-only post-processing.
8. Optionally adapt the examples under `/etc/tracegate/private/systemd` if obfuscation must run as a dedicated host-local service.
9. Keep the private TCP/443 demux under `/etc/tracegate/private/fronting` so it stays independent from both `Xray` and the private `MTProto` gateway.
10. Reapply bundles through the API or restart the role services as needed.
