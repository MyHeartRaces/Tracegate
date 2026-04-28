# Tracegate 2 private systemd helpers

This directory is a host-local scaffold for private transport wrappers.

Intended use cases:

- private `zapret2` wrappers
- host-local `FinalMask` staging
- decoy sync daemons
- custom packet camouflage processes that must not be described in the public repository
- low-overhead role profiles for `Entry`, `Transit` and the mandatory interconnect path

Seeded files:

- `obfuscation.env.example`: generic environment contract
- `run-obfuscation.sh.example`: wrapper entrypoint with `start|reload|stop <role>`
- `tracegate-obfuscation@.service.example`: example `oneshot` unit for `entry` / `transit`
- `../zapret/*.env.example`: private low-overhead profile metadata for `Entry`, `Transit`, the interconnect path and `MTProto`

Available runtime metadata for these wrappers:

- `/var/lib/tracegate/agent-entry/runtime/runtime-contract.json`
- `/var/lib/tracegate/agent-transit/runtime/runtime-contract.json`
- `<private-runtime-root>/obfuscation/<role>/runtime-state.json`
- `<private-runtime-root>/obfuscation/<role>/runtime-state.env`

`<private-runtime-root>` defaults to the sibling `private/` directory next to the role
agent runtime roots, or can be pinned explicitly with `PRIVATE_RUNTIME_ROOT`.

Recommended workflow:

1. `install.sh` seeds `/etc/tracegate/private/systemd/obfuscation.env`, `run-obfuscation.sh` and `/etc/systemd/system/tracegate-obfuscation@.service` from these examples when the live files are missing.
2. Read the role-specific `runtime-contract.json` so the wrapper derives active decoy roots and Xray/Hysteria state from the reconciled runtime instead of hardcoding them.
3. Use the generated `runtime-state.{json,env}` files plus `TRACEGATE_ZAPRET_PROFILE_FILE` as the only public handoff into the private backend.
4. Keep `Entry` narrower than `Transit`, and keep the interconnect profile narrower than both public-facing roles.
5. Replace `run-obfuscation.sh` with a private implementation or install a private executable at `TRACEGATE_ZAPRET_RUNNER`.
6. Point `AGENT_RELOAD_OBFUSCATION_CMD` at `systemctl reload tracegate-obfuscation@<role> || systemctl restart tracegate-obfuscation@<role>` if the agent should trigger the helper automatically.
7. If you need a different service shape, replace the seeded `/etc/systemd/system/tracegate-obfuscation@.service` with a private unit.
8. Keep the actual segmentation / fingerprint / camouflage algorithm out of Git.
9. Run `validate-runtime-contracts.sh --zapret-root /etc/tracegate/private/zapret` on a testbed before promotion if the private profile metadata diverges from the seeded low-overhead defaults.

This scaffold is intentionally generic. The public project defines the service boundary, not the obfuscation logic.

The seeded wrapper now exposes the selected backend, zapret profile file paths and
policy/state directories inside `runtime-state.json` so preflight can catch stale
handoff wiring before a private runner is promoted.
