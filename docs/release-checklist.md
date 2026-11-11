# Production release checklist

## Public release

- The worktree is clean and the version is new.
- `make release-check` passes.
- `scripts/build_release_artifacts.sh VERSION` produces wheel, sdist,
  `tracegate-host-runtime-VERSION.tar.gz` and `SHA256SUMS`.
- Engine units never pull at start: every engine starts the image recorded by
  immutable digest in the host artifact store (`tracegate-artifacts verify`
  passes for the target role), and `deploy/host/artifacts.json` lists exactly
  the components that run containers.
- The public privacy scanner reports no live address, domain, credential,
  private key, client export or operator filesystem path.

## Private inputs

- Live inventory, image digests, domains, addresses and rendered profiles are
  committed only to `tracegate-private`, encrypted with SOPS where they contain
  credentials.
- Decrypted `/etc/tracegate/deploy.env` and `/etc/tracegate/tracegate.env` exist
  only on operator/production hosts and have mode `0600` or `0400`.
- `/var/lib/tracegate/private` is populated from the reviewed private overlay;
  it is never copied into the public release archive.
- `tracegate-host-private-preflight` passes for every role-specific profile
  tree.

## Pre-deployment gate

- Verify release checksums and install into a new `/opt/tracegate/releases/*`
  directory; do not overwrite the current release.
- `tracegate-host-deploy preflight` passes using the production env files.
- `tracegate-artifacts verify --units <role units>` passes on the target host
  and `tracegate-artifacts status` shows no drift for the role.
- The configured off-host PostgreSQL backup command succeeds and a restore was
  tested recently.
- Required firewall, TLS renewal, nginx/HAProxy, Xray, Hysteria, ShadowTLS
  and Telemt services are healthy for the target role.

## Upgrade

- Deploy one role at a time and keep the previous release directory.
- Run the migration one-shot before switching application services.
- Require `/ready` (including a database query), agent health and sustained
  payload probes before completing the rollout.
- Verify Telegram Proxy issue/revoke, Reality, both Hysteria variants, Chain,
  both Backup variants and SS2022/ShadowTLS.
- Verify Grafana traffic panels in MB and the new Telemt/SS collectors.

## Engine update

- Updating an engine is explicit, never a side effect of a restart:
  `tracegate-artifacts stage <component>`, probe the staged engine through the
  real client path, `tracegate-artifacts promote <component> <digest>`,
  restart one affected unit, probe again, then continue with the rest.
- Record the promoted digests and the probe results in the private repository.

## Rollback

- If readiness or payload gates fail, restore the prior immutable image
  selection with `tracegate-host-deploy rollback`.
- Database migrations are not automatically downgraded. Production migrations
  must preserve compatibility with the immediately preceding image.
- Keep the database backup and previous release until the observation window
  and scheduled restore check complete.
