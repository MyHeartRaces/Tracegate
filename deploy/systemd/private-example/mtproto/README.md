Tracegate 2 private MTProto gateway scaffold

This directory defines the public handoff surface for a private `MTProto` gateway that can be backed by the official Telegram `MTProxy` binary.

Scope:

- dedicated host-local service contract for `MTProto`
- a role-oriented env file for `Transit`
- runtime-state handoff from the existing obfuscation wrapper
- a systemd-managed wrapper that can supervise an out-of-tree private runner or fall back to the official `MTProxy` binary behind HAProxy
- a local `public-profile.json` handoff file with ready-to-open MTProto deep links for downstream UX surfaces

Important boundary:

- keep client-facing MTProto secrets, deep links and any operator tags outside Git
- keep `MTProto` packet handling and any extra camouflage logic outside public docs
- use a real dedicated domain for fake-TLS masking, not the same hostname used by the panel or public decoy
- keep that hostname `DNS only` unless you have a real L4 proxy such as Cloudflare Spectrum; ordinary orange-cloud HTTP proxying is the wrong layer for MTProto

Recommended shape:

1. Let `HAProxy` or another private fronting layer keep owning public `:443`.
2. Bind the actual `MTProxy` process to loopback when the official binary accepts it, or to the host interface address when it rejects `127.0.0.1` as `--address`.
3. Use zero extra workers in TLS-transport mode unless you have a measured reason to raise it.
4. Apply `zapret2` only as an extra private layer around that backend, not as a system-wide rule set.
5. Keep the MTProto service independent from `Xray` reloads.
6. Prefer a dedicated real domain such as `proxied.tracegate.su`, with its own certificate/backend behavior, instead of reusing the main project surface hostname.
7. Keep the canonical fronting service scaffold under `/etc/tracegate/private/fronting`; the file in this directory is only the MTProto-side handoff contract.

Validation note:

- `openssl s_client` is not a valid health check for MTProto fake-TLS mode. The server expects a Telegram-specific fake-TLS `ClientHello` signed with the 16-byte MTProto secret. Use a Telegram client or a protocol-aware fake-TLS probe when validating the backend and the fronting path.

Seeded files:

- `mtproto.env.example`: public config contract for a private gateway
- `fronting-transit.env.example`: public handoff for a private TCP/443 demux layer on Transit
- `run-mtproto.sh.example`: wrapper entrypoint with `start|reload|stop <role>`, `public-profile.json` / issued-state handoff generation and a direct fallback path for the official `MTProxy` binary
- `tracegate-mtproto@.service.example`: example oneshot manager unit for a daemonized private runner

`install.sh` also seeds `/etc/tracegate/private/mtproto/{mtproto.env,fronting-transit.env,run-mtproto.sh}`
and `/etc/systemd/system/tracegate-mtproto@.service` when the live files are missing.

The seeded wrapper writes `last-action.json`, `public-profile.json` and `issued.json`, and all of them are now part of the public preflight surface so domain/port/profile drift can be detected before promotion.

When `TRACEGATE_MTPROTO_RUNNER` is absent but `TRACEGATE_MTPROTO_BINARY` points at a working
official `MTProxy` install, the wrapper refreshes `getProxySecret` / `getProxyConfig`, keeps the
main secret in `secret.txt`, appends persistent account-bound secrets from `issued.json` and supervises the local listener itself. The wrapper uses a private PID namespace by default when `unshare` is available because the official binary can crash on long-lived hosts once the host PID counter exceeds `65535`.

The public `install-runtime.sh` helper now supports this testbed path directly when invoked with
`INSTALL_COMPONENTS=xray,mtproto`. That opt-in mode installs the official `MTProxy` binary under
`/opt/MTProxy`, seeds `secret.txt` / `issued.json` and refreshes the bootstrap files
expected by `run-mtproto.sh`.
