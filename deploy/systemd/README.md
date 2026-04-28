# Tracegate 2 systemd deployment

Tracegate 2 is designed to run cleanly on plain Linux hosts without Kubernetes.

The deploy kit in this directory covers the control plane and both node-agent roles:

- `tracegate-api.service`
- `tracegate-dispatcher.service`
- `tracegate-bot.service`
- `tracegate-agent-entry.service`
- `tracegate-agent-transit.service`
- `tracegate-xray@.service`
- `tracegate-hysteria@.service`
- `tracegate-haproxy@.service`
- `tracegate-nginx@.service`
- `tracegate.env.example`
- `transit-single.env.example`
- `entry.env.example`
- `transit.env.example`
- `install.sh`
- `install-runtime.sh`
- `replace-transit-node.sh`
- `validate-runtime-contracts.sh`
- `render-materialized-bundles.sh`
- `render-xray-centric-overlays.sh`

## Expected layout

- application checkout: `/opt/tracegate`
- shared environment file: `/etc/tracegate/tracegate.env`
- optional node-specific environment files:
  - `/etc/tracegate/entry.env`
  - `/etc/tracegate/transit.env`
- Transit-only replacement can run from a single file: `/etc/tracegate/tracegate.env`
- agent / dispatcher state: `/var/lib/tracegate`

## Quick install

The fastest path is the helper script:

```bash
sudo ./deploy/systemd/install.sh
```

It will:

- copy the repository to `/opt/tracegate`
- create `/etc/tracegate`
- install the Python package into `/opt/tracegate/.venv`
- install the unit files into `/etc/systemd/system`
- seed missing env files from the bundled `*.env.example` templates
- seed `/etc/tracegate/private` with safe example files for private overlays and hooks

For Transit-only replacement, keep everything in one file instead:

```bash
sudo TRACEGATE_INSTALL_ROLE=transit TRACEGATE_SINGLE_ENV_ONLY=true ./deploy/systemd/install.sh
```

That path seeds `/etc/tracegate/tracegate.env` from `transit-single.env.example` and leaves `transit.env`
optional, so the node can be rebuilt from a single host profile.

Node runtime binaries are installed separately:

```bash
sudo /opt/tracegate/deploy/systemd/install-runtime.sh
```

Defaults:

- `XRAY_VERSION=latest`
- `XRAY_INSTALL_POLICY=if-missing`
- `HYSTERIA_VERSION=latest`
- `HYSTERIA_INSTALL_POLICY=if-missing`
- `INSTALL_COMPONENTS=auto`
- `INSTALL_BIN_DIR=/usr/local/bin`
- `INSTALL_PROXY_STACK=true`
- `TRACEGATE_ENV_FILE=/etc/tracegate/tracegate.env`
- `MTPROTO_GIT_REF=master`
- `MTPROTO_INSTALL_POLICY=if-missing`
- `MTPROTO_INSTALL_ROOT=/opt/MTProxy`
- `MTPROTO_REFRESH_BOOTSTRAP=if-missing`

The runtime installer resolves official upstream release assets and verifies Xray checksums before replacing the
binaries. Hysteria2 can also be pinned with `HYSTERIA_SHA256` when byte-for-byte verification is required. The
default `if-missing` policies make repeat runs deterministic on an already provisioned host: existing Xray,
Hysteria2 and MTProxy binaries are reused, and MTProto bootstrap files are only refreshed when they are absent.

`INSTALL_COMPONENTS=auto` follows `AGENT_RUNTIME_PROFILE`. The default `tracegate-2.2` profile installs Xray and
standalone Hysteria2; legacy profile names such as `split` and `xray-hysteria` are normalized into the explicit
`xray-centric` compatibility path.

If you also want the private Transit MTProto scaffold to be runnable on a testbed, install it explicitly:

```bash
sudo INSTALL_COMPONENTS=xray,hysteria,mtproto /opt/tracegate/deploy/systemd/install-runtime.sh
```

That opt-in path builds the official Telegram `MTProxy` binary from the upstream
`TelegramMessenger/MTProxy` repository, seeds `/etc/tracegate/private/mtproto/secret.txt`,
seeds `/var/lib/tracegate/private/mtproto/issued.json` and refreshes the loopback
bootstrap files used by the seeded wrapper:

- `/var/lib/tracegate/private/mtproto/runtime/proxy-secret`
- `/var/lib/tracegate/private/mtproto/runtime/proxy-multi.conf`

Bundle materialization is a separate step:

```bash
sudo /opt/tracegate/deploy/systemd/render-materialized-bundles.sh
```

It renders operator values into `BUNDLE_MATERIALIZED_ROOT` so `/dispatch/reapply-base` can ship real server configs
instead of the placeholder repo templates.
The same step also writes `BUNDLE_MATERIALIZED_ROOT/.tracegate-deploy-manifest.json` with per-role
file digests, feature flags and the expected public/private units for rollout.

Optional full `xray.json` overlay generation for `xray-centric`:

```bash
sudo /opt/tracegate/deploy/systemd/render-xray-centric-overlays.sh
```

Recommended preflight before production:

```bash
sudo /opt/tracegate/deploy/systemd/validate-runtime-contracts.sh
```

This validates the current `Entry` / `Transit` `runtime-contract.json` pair and is intended
to be run on a non-production testbed before private `zapret2`, `FinalMask`, `ECH` or any
full `xray.json` overlay set is promoted to production.

On single-node testbeds the same helper auto-detects whether only `Entry` or only `Transit`
runtime-contracts are present and switches into single-role preflight automatically. Override
that explicitly with `PREFLIGHT_MODE=entry|transit|pair` when needed.

If `/etc/tracegate/private/zapret` exists, the helper also validates the low-overhead
`entry-lite.env`, `transit-lite.env`, mandatory `entry-transit-stealth.env` and optional `mtproto-extra.env`
metadata so scope widening or accidental host-wide rules are caught before rollout.

If `/etc/tracegate/private/systemd/obfuscation.env` exists, the helper also validates
that the host-local obfuscation wrapper contract still points at the expected private
runtime root, role-specific runtime-contract paths, zapret profile files and interfaces.

If `${PRIVATE_RUNTIME_ROOT:-<derived>}/obfuscation/{entry,transit}/runtime-state.json` and/or
`${PRIVATE_RUNTIME_ROOT:-<derived>}/obfuscation/{entry,transit}/runtime-state.env` exist, the same
helper also validates that the emitted wrapper handoff still matches the reconciled
`runtime-contract.json` pair, the selected zapret profile files, and that the JSON/ENV
handoff surfaces still describe the same runtime state.

If `${PRIVATE_RUNTIME_ROOT:-<derived>}/fronting/last-action.json`,
`/etc/tracegate/private/fronting/fronting.env`,
`${PRIVATE_RUNTIME_ROOT:-<derived>}/mtproto/last-action.json`,
`/etc/tracegate/private/mtproto/mtproto.env` or
`${PRIVATE_RUNTIME_ROOT:-<derived>}/mtproto/public-profile.json` exist, preflight also checks
that the Transit-side fronting and MTProto scaffolds still point at the expected
runtime-state, profile files and dedicated MTProto domain/port handoff.

`validate-runtime-contracts.sh` accepts an explicit `PRIVATE_RUNTIME_ROOT`, otherwise it
derives the default handoff root from the sibling of `ENTRY_RUNTIME_CONTRACT` /
`TRANSIT_RUNTIME_CONTRACT`. With the stock systemd layout this still resolves to
`/var/lib/tracegate/private`.

Like the render helpers, preflight also loads `${CONFIG_DIR:-/etc/tracegate}/tracegate.env`,
`entry.env` and `transit.env` first, so host-local overrides for `AGENT_DATA_ROOT`,
`PRIVATE_RUNTIME_ROOT` or MTProto/fronting paths are picked up automatically.

This command writes full replacement `xray.json` overlays into `BUNDLE_PRIVATE_OVERLAY_ROOT`
for `entry` and `transit`. It is intended only for the legacy `xray-centric` compatibility path where Hysteria
ingress is terminated by `Xray` instead of the separate `hysteria` service.

Sensitive transport camouflage can stay outside the repository:

- `BUNDLE_PRIVATE_OVERLAY_ROOT` may point to a private overlay tree, by default `/etc/tracegate/private/overlays`
- `TRACEGATE_PRIVATE_RENDER_HOOK` may point to an executable post-render hook, by default `/etc/tracegate/private/render-hook.sh`
- `/etc/tracegate/private/systemd` is seeded with host-local `oneshot` wrapper examples for private `zapret2` or `FinalMask` integration
- `/etc/tracegate/private/fronting` is seeded with a disabled-by-default service scaffold for a private TCP/443 demux layer
- `/etc/tracegate/private/zapret` is seeded with low-overhead role profile examples for `Entry`, `Transit`, the mandatory interconnect path and the private `MTProto` path
- `/etc/tracegate/private/mtproto` is seeded with a disabled-by-default service scaffold for a private `MTProto` gateway
- the render pipeline will apply private replacements / merges after the public bundle templates are materialized
- `render-xray-centric-overlays.sh` also writes `BUNDLE_PRIVATE_OVERLAY_ROOT/.tracegate-overlay-manifest.json`
  so the private `xray.json` replacements can be reviewed before activation

For `MTProto`, prefer a dedicated real hostname instead of reusing the main public project domain.
If that hostname sits behind Cloudflare, ordinary proxied DNS is the wrong layer for raw MTProto/TCP; use `DNS only`
or a real L4 product such as Spectrum.

## Manual install

Install the Python package and expose the console scripts:

```bash
python3 -m venv /opt/tracegate/.venv
/opt/tracegate/.venv/bin/pip install -U pip
/opt/tracegate/.venv/bin/pip install /opt/tracegate
```

Then copy the units into `/etc/systemd/system/`, place the env files under `/etc/tracegate/`, reload systemd and enable the required services.

## Transit Node Replacement

The old Tracegate node-replacement contract still applies conceptually:

1. rebuild the Transit host
2. reapply the base runtime for `TRANSIT`
3. reissue active revisions

For Tracegate 2 this is now implemented as a plain-host systemd flow:

```bash
sudo TRACEGATE_ENV_FILE=/etc/tracegate/tracegate.env /opt/tracegate/deploy/systemd/replace-transit-node.sh
```

`replace-transit-node.sh` is Transit-only and idempotent. It will:

- bootstrap host prerequisites (`curl`, `rsync`, `python3`, `python3-venv`)
- run `install.sh` in `TRACEGATE_INSTALL_ROLE=transit`
- run `install-runtime.sh` with `INSTALL_COMPONENTS` from the same env file
- render materialized bundles
- optionally render private xray-centric overlays
- enable the Transit runtime units, including the seeded private companions when their unit files exist
- wait for the local or configured API `/health` endpoint before dispatching control-plane operations
- call `/dispatch/reapply-base` with `{"role":"TRANSIT"}`
- wait for the Transit `runtime-contract.json` emitted by the agent and then validate it with `PREFLIGHT_MODE=transit`
- call `/dispatch/reissue-current-revisions`

The recommended single-file host profile for this workflow is:

- `deploy/systemd/transit-single.env.example`

It keeps:

- Transit runtime values
- MTProto/fronting hints
- replacement toggles such as `TRACEGATE_REPLACE_API_URL`
- runtime installer choices such as `INSTALL_COMPONENTS=xray,hysteria,mtproto`
- install policies such as `XRAY_INSTALL_POLICY=if-missing`, `MTPROTO_INSTALL_POLICY=if-missing` and `MTPROTO_REFRESH_BOOTSTRAP=if-missing`

The repository also ships a matching GitHub Actions workflow:

- `.github/workflows/transit-node-replacement.yml`

Expected GitHub secrets:

- `TRACEGATE_TRANSIT_HOST`
- `TRACEGATE_TRANSIT_SSH_USER` (defaults to `root` when omitted)
- `TRACEGATE_TRANSIT_SSH_PORT` (defaults to `22` when omitted)
- `TRACEGATE_TRANSIT_SSH_KEY`
- `TRACEGATE_TRANSIT_SINGLE_ENV`

`TRACEGATE_TRANSIT_SINGLE_ENV` should contain the full contents of the single-file Transit profile.

Example:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tracegate-api tracegate-dispatcher tracegate-bot
sudo systemctl enable --now tracegate-agent-entry
sudo systemctl enable --now tracegate-agent-transit
sudo systemctl enable --now tracegate-haproxy@entry tracegate-nginx@entry
sudo systemctl enable --now tracegate-xray@entry tracegate-hysteria@entry
sudo systemctl enable --now tracegate-haproxy@transit tracegate-nginx@transit
sudo systemctl enable --now tracegate-xray@transit tracegate-hysteria@transit
```

Use only the units needed on a given host:

- control-plane host: `tracegate-api`, `tracegate-dispatcher`, `tracegate-bot`
- Entry host, `tracegate-2.2`: `tracegate-agent-entry`, `tracegate-haproxy@entry`, `tracegate-nginx@entry`, `tracegate-xray@entry`, `tracegate-hysteria@entry`
- Transit host, `tracegate-2.2`: `tracegate-agent-transit`, `tracegate-haproxy@transit`, `tracegate-nginx@transit`, `tracegate-xray@transit`, `tracegate-hysteria@transit`
- Legacy `xray-centric` hosts omit `tracegate-hysteria@<role>` because Hysteria is Xray-owned there.

Recommended env layout:

- `tracegate.env` for shared API, bot, dispatcher and host defaults
- `entry.env` for Entry-only agent settings such as data root and reload hooks
- `transit.env` for Transit-only agent settings
- `PRIVATE_RUNTIME_ROOT` if the private handoff surfaces must not live next to `AGENT_DATA_ROOT`
- `TRANSIT_DECOY_AUTH_LOGIN`, `TRANSIT_DECOY_AUTH_PASSWORD`, `TRANSIT_DECOY_SECRET_PATH`, `TRANSIT_DECOY_GITHUB_REPO_URL` and `MTPROTO_PUBLIC_PROFILE_FILE` for the optional private Transit auth/static surface
- `/etc/tracegate/private/overlays/{entry,transit}` for secret runtime overlays that must not live in Git
- `/etc/tracegate/private/render-hook.sh` for local post-render automation such as private obfuscation bootstrap
- `/etc/tracegate/private/systemd` for host-local wrapper services that own private packet camouflage or transport-masking daemons
- `/etc/tracegate/private/fronting` for a private TCP/443 demux layer that stays separate from the MTProto backend
- `/etc/tracegate/private/profiles` for the private V5/V6/V7 profile adapter scaffold and runner handoff
- `/etc/tracegate/private/link-crypto` for the private Mieru Entry-Transit / router link scaffold and runner handoff
- `/etc/tracegate/private/zapret` for private role-oriented policy metadata without publishing the actual `zapret2` algorithm
- `/etc/tracegate/private/mtproto` for a private MTProto gateway that can be fronted behind the same public `443` surface
- `AGENT_RELOAD_OBFUSCATION_CMD` for an optional host-local wrapper reload when `runtime-contract.json` changes
- `AGENT_RELOAD_FRONTING_CMD` for a Transit-only private TCP/443 demux reload when the handoff surface changes
- `AGENT_RELOAD_MTPROTO_CMD` for a Transit MTProto gateway reload when handoff metadata or account-bound grants rotate
- `AGENT_RELOAD_PROFILES_CMD` for a private profile adapter reload when V5/V6/V7 desired state changes
- `AGENT_RELOAD_LINK_CRYPTO_CMD` for a private Mieru link adapter reload when link desired-state changes
- `ZAPRET_PROFILE_ROOT` for the runtime preflight helper if the private zapret metadata lives outside `/etc/tracegate/private/zapret`

Runtime profile note:

- `AGENT_RUNTIME_PROFILE=tracegate-2.2` is the current Tracegate 2 default
- `AGENT_RUNTIME_PROFILE=tracegate-2.1` keeps the no-Xray-backhaul contract but remains a legacy compatibility profile
- older profile names such as `split` and `xray-hysteria` are treated as aliases of `xray-centric`
- `INSTALL_COMPONENTS=auto` and the helper output from `install.sh` both follow `AGENT_RUNTIME_PROFILE`
- `INSTALL_COMPONENTS=xray,hysteria,mtproto` is the intended Transit-only opt-in when the private MTProto wrapper should supervise the official `MTProxy` binary directly on a testbed
- when `AGENT_XRAY_API_ENABLED=true`, Tracegate 2.2 pushes VLESS changes through the Xray gRPC API; Hysteria2 auth is served by the agent's local HTTP auth endpoint

Important shared variables for bundle rendering:

- `REALITY_PRIVATE_KEY_ENTRY`
- `REALITY_PRIVATE_KEY_TRANSIT`
- `REALITY_PUBLIC_KEY_TRANSIT`
- `REALITY_SHORT_ID_ENTRY`
- `REALITY_SHORT_ID_TRANSIT`
- `HYSTERIA_SALAMANDER_PASSWORD_ENTRY`
- `HYSTERIA_SALAMANDER_PASSWORD_TRANSIT`
- `HYSTERIA_STATS_SECRET_ENTRY`
- `HYSTERIA_STATS_SECRET_TRANSIT`
- `ENTRY_TLS_SERVER_NAME`
- `TRANSIT_TLS_SERVER_NAME`
- `BUNDLE_PRIVATE_OVERLAY_ROOT`
- `TRACEGATE_PRIVATE_RENDER_HOOK`
- `XRAY_CENTRIC_DECOY_DIR`

`XRAY_CENTRIC_DECOY_DIR` is the shared decoy root used by:

- rendered `nginx.conf` on `Entry` and `Transit`
- standalone Hysteria2 masquerade directories in `tracegate-2.2`
- Xray-native `Hysteria` masquerade directories in the legacy `xray-centric` overlay generator

Tracegate 2.2 keeps TCP and UDP public surfaces split: TCP fronting stays on `443`, Hysteria2 stays on `udp/8443`, and host firewall bundles explicitly drop `udp/443` plus `tcp/8443`.

`tracegate-nginx@.service` is not pinned to `/var/www/decoy`; the decoy tree only needs to be readable by `nginx`,
so `XRAY_CENTRIC_DECOY_DIR` may point to any host path with suitable permissions.

Private overlay contract:

- `entry/xray.merge.json`, `transit/xray.merge.json`: deep-merge into the rendered `xray.json`
- `entry/xray.json`, `transit/xray.json`: full replacement for the rendered `xray.json`
- `entry/haproxy.cfg`, `entry/nginx.conf`, `entry/nftables.conf` and Transit equivalents: full file replacement
- `entry/decoy/` and `transit/decoy/`: optional private static/auth content copied into the active decoy root when present

The public repository does not ship decoy HTML assets. This is the intended place for private `FinalMask`, `TLS ECH`,
static/auth surfaces or external obfuscation glue that
should not be committed into the public repository.

`render-xray-centric-overlays.sh` is the safest starting point for the future runtime refactor:

- it reads the already materialized `xray.json` when available
- it falls back to repo bundle templates if materialized bundles are absent
- it writes full `entry/xray.json` and `transit/xray.json` replacements into the private overlay root
- it does not switch the active runtime profile by itself

The node runtime units read directly from the reconciled agent runtime tree:

- `/var/lib/tracegate/agent-entry/runtime/haproxy/haproxy.cfg`
- `/var/lib/tracegate/agent-entry/runtime/nginx/nginx.conf`
- `/var/lib/tracegate/agent-entry/runtime/xray/config.json`
- `/var/lib/tracegate/agent-entry/runtime/hysteria/server.yaml`
- `/var/lib/tracegate/agent-transit/runtime/haproxy/haproxy.cfg`
- `/var/lib/tracegate/agent-transit/runtime/nginx/nginx.conf`
- `/var/lib/tracegate/agent-transit/runtime/xray/config.json`
- `/var/lib/tracegate/agent-transit/runtime/hysteria/server.yaml`

The agent also writes `/var/lib/tracegate/agent-{entry,transit}/runtime/runtime-contract.json`.
This is the public machine-readable hand-off for host-local wrappers that need to detect
the active decoy root, standalone Hysteria masquerade directories, legacy Xray-native Hysteria state,
or whether `FinalMask` and `ECH` are currently present in the reconciled runtime.

The agent now materializes private handoff surfaces under the effective private runtime root
(default sibling `private/` next to `AGENT_DATA_ROOT`, or explicit `PRIVATE_RUNTIME_ROOT`):

- `<private-runtime-root>/obfuscation/<role>/runtime-state.json`
- `<private-runtime-root>/obfuscation/<role>/runtime-state.env`
- `<private-runtime-root>/profiles/<role>/desired-state.json`
- `<private-runtime-root>/profiles/<role>/desired-state.env`
- `<private-runtime-root>/link-crypto/<role>/desired-state.json`
- `<private-runtime-root>/link-crypto/<role>/desired-state.env`

These are intended as the only public hand-off into private `zapret2`, `Mieru` and profile
adapter backends. Keep the actual segmentation / packet manipulation logic, Mieru profiles
and generated V5/V6/V7 credentials outside the repository. The optional
`/etc/tracegate/private/profiles/run-profiles.sh` scaffold validates the secret profile
desired-state and emits only a redacted manifest. The optional
`/etc/tracegate/private/link-crypto/run-link-crypto.sh` scaffold validates the link handoff
and starts missing Mieru processes without restarting existing generations.
`validate-runtime-contracts.sh` includes these handoffs when present and rejects disabled
local SOCKS5 auth, host-wide interception, broad NFQUEUE, invalid V5/V6 stages, and
placeholder WireGuard/WSTunnel material before promotion.

If `AGENT_RELOAD_OBFUSCATION_CMD`, `AGENT_RELOAD_LINK_CRYPTO_CMD`,
`AGENT_RELOAD_FRONTING_CMD` and/or `AGENT_RELOAD_MTPROTO_CMD` are configured, the
agent will run them only when
`runtime-contract.json` or the generated private handoff surfaces actually change. Persistent
account-bound MTProto access secrets live in `issued.json` and are managed through the
Transit-side agent surface via the Telegram bot.

`tracegate-xray@.service` exposes a real `ExecReload`, so agent reload hooks can use `systemctl reload`.
`tracegate-haproxy@.service` owns public TCP/443 fanout toward local `Xray` and `Nginx`.
`tracegate-nginx@.service` terminates the optional `VLESS WS+TLS` leg and can serve host-local static content when one
is staged into the active decoy root.

The unit files use `StateDirectory=tracegate`, `ConfigurationDirectory=tracegate` and `RuntimeDirectory=tracegate`
so the filesystem layout matches the service contract by default.

`dispatcher` ops alerts are designed to run without Kubernetes. The active Tracegate 2 repository only keeps
Prometheus-backed disk checks and outbox health alerts for the dispatcher path.
