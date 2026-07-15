# Native host production runtime

Tracegate production runs directly on Linux hosts with systemd, host
PostgreSQL, Docker-backed data-plane services and host networking. There is no
parallel container orchestrator or Compose control plane.

Private inputs remain outside the public release:

- `/etc/tracegate/deploy.env` contains non-secret host deployment coordinates;
- `/etc/tracegate/tracegate.env` is the Endpoint runtime environment;
- `/etc/tracegate/tracegate-entry.env` is the Entry runtime environment;
- `/var/lib/tracegate/private` contains rendered private profiles and TLS data.

## Release lifecycle

1. Verify `SHA256SUMS` and extract `tracegate-host-runtime-VERSION.tar.gz`.
2. Run `tracegate-host-install VERSION`. It validates the archive, creates an
   immutable versioned venv from the bundled wheel, installs tracked systemd
   units and host helpers, and applies the QUIC sysctl profile. It does not
   switch the active release or restart traffic.
3. Render the correct role environment and run
   `tracegate-host-deploy preflight VERSION`.
4. Run `tracegate-host-deploy deploy VERSION`. Endpoint deployment takes a
   database backup and applies forward-compatible migrations before atomically
   switching `/opt/tracegate/current`, `/opt/tracegate/app` and
   `/opt/tracegate/venv`. Role services are restarted in dependency order and
   both API and agent readiness are required.
5. If readiness fails, the previous symlink targets and systemd files are
   restored automatically. `tracegate-host-deploy rollback` performs the same
   restoration explicitly. Database migrations are never downgraded.

The application wheel is versioned and immutable. Upstream data-plane engines
continue to track `latest`; their systemd units pull before every start.
