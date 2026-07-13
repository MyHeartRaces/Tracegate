# PostgreSQL backup and restore checks

Production upgrades require `TRACEGATE_BACKUP_COMMAND`. The command is owned by
the private operator environment and must create an encrypted off-host backup;
the public repository never contains repository credentials.

The deployment command stops before image promotion when the backup command
fails. Operators must also schedule a restore into a disposable PostgreSQL
instance and retain its result through the release observation window.

Database rollback is intentionally not automated. Alembic migrations must
remain compatible with the immediately preceding application image so image
rollback stays safe.
