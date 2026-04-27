Tracegate 2 private zapret2 profiles

These files define the public handoff surface for a private `zapret2` backend.

What belongs here:

- role-specific profile selectors for `Entry` and `Transit`
- a mandatory low-overhead `Entry` to `Transit` interconnect profile
- a separate `MTProto` extra profile that can be applied only when a private MTProto backend exists
- CPU / overhead goals and scope boundaries

What must not live here:

- the real packet-splitting algorithm
- fingerprint mutations
- private host lists or classifier rules
- any command line that would fully disclose the private `zapret2` policy

Low-overhead design goals:

- `Entry`: touch only the chained ingress surface and keep the policy narrower than Transit
- `Entry-to-Transit`: apply before every backhaul tunnel and keep the scope fixed to tcp/udp `443`
- `Transit`: apply only to Tracegate-facing public surfaces on `443`; Transit remains the primary endpoint before Internet egress
- clients: no local `zapret2` profile bundle in this repository

Recommended operator workflow:

1. `install.sh` seeds the live profile files without the `.example` suffix when they are still missing, so a fresh testbed already has the public metadata surface in place.
2. Keep the profile names stable so the wrapper can select them by role.
3. Let the private backend read `TRACEGATE_ZAPRET_PROFILE_FILE`, `TRACEGATE_ZAPRET_INTERCONNECT_PROFILE_FILE` and `TRACEGATE_ZAPRET_MTPROTO_PROFILE_FILE`.
4. Keep the actual `zapret2` algorithm in the private runner, not in these files.
5. Before rollout, run `validate-runtime-contracts.sh --zapret-root /etc/tracegate/private/zapret` so the public metadata is checked for scope widening, missing `443` coverage and CPU/worker drift.

Current product boundary:

- `V1` / `V2`: `VLESS`
- `V3` / `V4`: `Hysteria2`
- `V5` / `V6`: `Shadowsocks-2022 + ShadowTLS V3`
- `V7`: `WireGuard over WSTunnel`
- `Entry-to-Transit`: mandatory private relay masking surface for `V2` / `V6` over TCP plus `V4` over the separate UDP link, outside Xray and scoped to the link-crypto outer flow
- `MTProto`: persistent account-bound Telegram access through the bot plus a dedicated private zapret profile

The `entry-transit-stealth.env.example` file is the mandatory interconnect metadata surface. The `mtproto-extra.env.example` file is the reserved policy surface for Telegram-recognizable MTProto payload shaping.
