from __future__ import annotations

import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import bindparam, create_engine, text

from tracegate.settings import get_settings

# v0.1 baseline revision (schema created by Base.metadata.create_all in v0.1)
BASELINE_REVISION = "10691de66f04"


def _sync_database_url(url: str) -> str:
    # App uses asyncpg; Alembic uses sync engine.
    return url.replace("+asyncpg", "+psycopg")


def _alembic_config(*, sync_database_url: str) -> Config:
    ini_path = os.getenv("TRACEGATE_ALEMBIC_INI") or "alembic.ini"
    path = Path(ini_path)
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.exists():
        raise RuntimeError(f"alembic.ini not found: {path}")

    cfg = Config(str(path))
    cfg.set_main_option("sqlalchemy.url", sync_database_url)
    return cfg


def migrate_db() -> None:
    """
    Apply Alembic migrations.

    Bootstrap behavior:
    - if DB already has v0.1 tables but has no alembic_version, stamp BASELINE_REVISION
      and then upgrade to head.
    - if DB is empty, just upgrade to head (creates schema).
    """
    settings = get_settings()
    if not settings.database_url:
        raise RuntimeError("DATABASE_URL is required")

    sync_url = _sync_database_url(settings.database_url)
    cfg = _alembic_config(sync_database_url=sync_url)

    engine = create_engine(sync_url, pool_pre_ping=True)
    with engine.begin() as conn:
        has_alembic = conn.execute(text("SELECT to_regclass('public.alembic_version')")).scalar() is not None
        if not has_alembic:
            # If core tables exist, this is a pre-Alembic v0.1 DB.
            has_user_table = conn.execute(text("SELECT to_regclass('public.tg_user')")).scalar() is not None
            if has_user_table:
                command.stamp(cfg, BASELINE_REVISION)

    command.upgrade(cfg, "head")

    # Ensure configured superadmins are always SUPERADMIN, even for upgraded DBs
    # where users existed before the role column was introduced.
    if settings.superadmin_telegram_ids:
        stmt = text("UPDATE tg_user SET role = 'SUPERADMIN' WHERE telegram_id IN :ids").bindparams(
            bindparam("ids", expanding=True)
        )
        with engine.begin() as conn:
            conn.execute(stmt, {"ids": list(settings.superadmin_telegram_ids)})


def main() -> None:
    migrate_db()
