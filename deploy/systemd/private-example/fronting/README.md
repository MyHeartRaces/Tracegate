Tracegate 2 private TCP/443 fronting scaffold

This directory defines the public handoff surface for a private `TCP/443` demux layer on `Transit`.

Scope:

- dedicated host-local service contract for server-side fronting
- runtime-state handoff from the existing obfuscation wrapper
- no public implementation of the actual traffic classification logic beyond a host-local `haproxy` transport split

Important boundary:

- this scaffold stays disabled by default until the private backend is validated on a testbed
- own only `TCP/443`; do not claim public `UDP/8443`
- keep the actual classifier, fake-handshake logic and packet shaping outside Git
- keep `MTProto` on its own dedicated real hostname instead of reusing the main public surface
- keep the default listen address on a local test port until the demux is validated end-to-end

Recommended shape:

1. Let the private fronting service own only public `TCP/443`.
2. Keep public `UDP/8443` on the active runtime owner.
3. Route `REALITY`, `WS+TLS` and `MTProto` legs into separate local upstreams.
4. Keep `MTProto` and `zapret2` as separate private layers behind the fronting service.
5. Validate the demux first on a local test port such as `127.0.0.1:10443`.
6. Do not move the listener onto public `:443` until the private backend is verified on a testbed.

The seeded wrapper writes `last-action.json` with the selected backend, upstreams,
Transit runtime-state handoff path and MTProto profile file so public preflight can
catch stale fronting wiring before rollout.

Seeded files:

- `fronting.env.example`: public config contract for a private fronting layer
- `run-fronting.sh.example`: wrapper entrypoint with `start|reload|stop <role>`
- `tracegate-fronting@.service.example`: example `oneshot` unit that manages a private daemonized `haproxy`

`install.sh` also seeds the live defaults under `/etc/tracegate/private/fronting/`
and `/etc/systemd/system/tracegate-fronting@.service` when they do not exist yet.
