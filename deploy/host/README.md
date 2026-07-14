# Host production deployment

This directory is the public, environment-neutral deployment contract for
Tracegate 3. Production hosts use Docker Compose, systemd and host networking;
no Kubernetes or Helm component is required.

Private inputs are deliberately external:

- `/etc/tracegate/deploy.env` selects tagged images and paths;
- `/etc/tracegate/tracegate.env` contains runtime credentials and has mode
  `0600` or `0400`;
- `/var/lib/tracegate/private` contains rendered role profiles, TLS material
  and other operator-owned files.

Never copy those files into the public checkout or release archive.

## Install and activate

1. Verify `SHA256SUMS`, then extract `tracegate-host-runtime-VERSION.tar.gz`.
2. Run `sudo deploy/host/tracegate-host-install VERSION` from the extracted
   directory. Installation stores the host bundle under
   `/opt/tracegate/releases/VERSION/runtime`, updates `/opt/tracegate/current`
   atomically, installs the canonical host systemd units and helper scripts,
   but does not enable or start data-plane services. The sibling `app` and
   `venv` directories remain available to native control-plane deployments.
3. Place the private files above and run
   `/opt/tracegate/current/deploy/host/tracegate-host-deploy preflight`.
4. Enable `tracegate-host.service` for the control-plane host. Add the
   `gateway` Compose profile only on a host that runs the Tracegate agent.
5. Use `tracegate-host-deploy deploy` for upgrades. It requires an operator
   backup command, pulls current tagged images, applies migrations, waits for readiness
   and rolls the image selection back if the health gate fails.

`rollback` restores the previous image selection. Alembic migrations are not
downgraded, so every production migration must remain backward-compatible for
at least one release.
