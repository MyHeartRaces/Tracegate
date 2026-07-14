# Host operator workflow

Tracegate production is managed through tagged upstream container images,
Docker Compose, systemd and private role overlays.

1. Build and validate the public release with `make release-check` and
   `scripts/build_release_artifacts.sh VERSION`.
2. Record the selected application and PostgreSQL image tags in the private
   repository. Production follows `latest` and pulls it before promotion.
3. Render/decrypt the reviewed private inventory into root-only files outside
   both repositories.
4. Verify checksums, install the host-runtime archive into a new release
   directory, then run `tracegate-host-deploy preflight`.
5. Run `tracegate-host-deploy deploy`. The command requires a successful backup,
   applies migrations, replaces containers and waits for database-backed API
   readiness.
6. Validate role services and sustained client payload before proceeding to the
   next host.
7. On failure, use `tracegate-host-deploy rollback`; retain the failed logs,
   backup and release directory for review.

Environment-specific inventory, DNS, firewall inputs, certificates, rendered
profiles, decoy content and credentials belong exclusively to
`tracegate-private` and production storage.
