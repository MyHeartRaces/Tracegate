# PostgreSQL Backup and Restore Checks

Tracegate can write encrypted PostgreSQL backups to an off-node Restic
repository and periodically prove that the latest snapshot restores into a
temporary PostgreSQL instance.

The chart keeps this feature disabled by default. Production enables it only
through ignored private values and an external Secret. No repository URL,
password or object-storage credential belongs in the public repository.

## Secret contract

Create the Secret named by
`controlPlane.database.backup.repositorySecretName`. It must expose:

- `RESTIC_REPOSITORY`;
- `RESTIC_PASSWORD`;
- backend-specific variables such as `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY` and `AWS_DEFAULT_REGION` for an S3-compatible
  repository.

Initialize the repository once from the operator environment before enabling
the CronJobs. The scheduled backup fails closed when the repository is absent
or cannot be authenticated.

## Jobs

`postgres-backup` runs `pg_dump` in custom format, uploads the dump with
Restic client-side encryption and applies daily, weekly and monthly retention.
Concurrent backups are forbidden.

`postgres-restore-check` restores the latest tagged snapshot into an empty
volume, starts a disposable PostgreSQL server, runs `pg_restore
--exit-on-error`, and verifies that the Alembic version table exists. It never
connects to or modifies the production database.

After enabling the jobs, trigger each CronJob once manually and require both
Jobs to complete before treating backups as operational. Keep object-storage
versioning or immutability independent of the cluster credentials.
