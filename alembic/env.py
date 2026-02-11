from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy import pool
from sqlalchemy import text

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

def _sync_database_url() -> str:
    """
    Alembic runs with a sync SQLAlchemy engine.

    The app uses asyncpg, so we convert `postgresql+asyncpg://...` -> `postgresql+psycopg://...`
    (psycopg is already a dependency).
    """
    url = os.getenv("DATABASE_URL") or config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError("DATABASE_URL is required for alembic")
    return url.replace("+asyncpg", "+psycopg")


# Import models so metadata is populated for autogenerate.
from tracegate.db import Base  # noqa: E402
import tracegate.models  # noqa: F401,E402

target_metadata = Base.metadata

# Prevent concurrent migrations when multiple pods start at the same time.
MIGRATION_ADVISORY_LOCK_KEY = 73284923

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = _sync_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = create_engine(_sync_database_url(), poolclass=pool.NullPool)

    with connectable.connect() as connection:
        if connection.dialect.name == "postgresql":
            # Transaction-scoped advisory lock avoids concurrent runners and is auto-released on commit/rollback.
            connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_ADVISORY_LOCK_KEY})

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
