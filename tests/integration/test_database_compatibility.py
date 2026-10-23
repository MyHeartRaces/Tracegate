"""Opt-in PostgreSQL checks; every test creates and drops its own new database.

TRACEGATE_TEST_POSTGRES_URL points at an isolated PostgreSQL test cluster with
CREATE DATABASE permission. Existing databases are never cleared or migrated.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from alembic import command
from tracegate.cli import migrate_db as migration
from tracegate.client_export.config import export_client_config
from tracegate.enums import ConnectionVariant, RecordStatus, UserRole
from tracegate.models import Connection, ConnectionRevision, User
from tracegate.settings import Settings

pytestmark = pytest.mark.skipif(
    not os.getenv("TRACEGATE_TEST_POSTGRES_URL"),
    reason="requires an isolated PostgreSQL test cluster",
)
ROOT = Path(__file__).resolve().parents[2]
HEAD = "7b31d4e9a205"


@pytest.fixture
def database_url():
    admin_url = make_url(os.environ["TRACEGATE_TEST_POSTGRES_URL"])
    name = "tracegate_compat_" + uuid4().hex
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.exec_driver_sql(f'CREATE DATABASE "{name}"')
    try:
        yield admin_url.set(database=name)
    finally:
        with admin.connect() as connection:
            connection.execute(
                text("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                     "WHERE datname = :name AND pid <> pg_backend_pid()"),
                {"name": name},
            )
            connection.exec_driver_sql(f'DROP DATABASE "{name}"')
        admin.dispose()


def _config(url) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url.render_as_string(hide_password=False).replace("%", "%%"))
    return config


def _seed_issued_connections(engine, *, legacy_variant: bool) -> list[dict]:
    device_id = uuid4()
    rows = []
    has_is_active = any(column["name"] == "is_active" for column in inspect(engine).get_columns("device"))
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO tg_user (telegram_id, devices_max, entitlement_status, created_at, updated_at) "
            "VALUES (9001, 9, 'ACTIVE', now(), now())"
        ))
        columns = ", is_active" if has_is_active else ""
        values = ", true" if has_is_active else ""
        connection.execute(text(
            f"INSERT INTO device (id, user_id, name, status, created_at{columns}) "
            f"VALUES (:id, 9001, 'existing-phone', 'ACTIVE', now(){values})"
        ), {"id": device_id})
        for protocol, effective in [
            ("VLESS_REALITY", {
                "protocol": "vless", "transport": "reality_raw",
                "server": "entry.tracegate.test", "port": 443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "sni": "camouflage.tracegate.test",
                "reality": {"public_key": "EXISTING-PUBLIC-KEY", "short_id": "abcd"},
            }),
            ("HYSTERIA2", {
                "protocol": "hysteria2", "server": "endpoint.tracegate.test", "port": 443,
                "auth": {"type": "userpass", "username": "existing-user", "password": "existing-password"},
                "obfs": {"type": "salamander", "password": "existing-obfs-password"},
                "tls": {"server_name": "endpoint.tracegate.test", "insecure": False},
            }),
        ]:
            connection_id, revision_id = uuid4(), uuid4()
            variant = "V2" if protocol == "HYSTERIA2" else "V1"
            connection.execute(text(
                "INSERT INTO connection (id, user_id, device_id, protocol, mode, variant, "
                "profile_name, custom_overrides_json, status, created_at) "
                "VALUES (:id, 9001, :device, :protocol, 'DIRECT', :variant, "
                "'existing-profile', '{}', 'ACTIVE', now())"
            ), {"id": connection_id, "device": device_id, "protocol": protocol,
                "variant": variant.replace("V", "B") if legacy_variant else variant})
            connection.execute(text(
                "INSERT INTO connection_revision (id, connection_id, slot, status, "
                "effective_config_json, created_at) "
                "VALUES (:id, :connection, 0, 'ACTIVE', CAST(:effective AS json), now())"
            ), {"id": revision_id, "connection": connection_id, "effective": json.dumps(effective)})
            rows.append({"connection_id": connection_id, "revision_id": revision_id,
                         "variant": ConnectionVariant(variant),
                         "effective": effective, "export": export_client_config(effective)})
    return rows


@pytest.mark.asyncio
@pytest.mark.parametrize("starting_revision", [None, "10691de66f04", "e1c7a4b9d2f0", HEAD])
async def test_old_databases_keep_issued_credentials_and_remain_writable(
    database_url, monkeypatch, starting_revision: str | None,
) -> None:
    raw_url = database_url.render_as_string(hide_password=False)
    monkeypatch.setenv("DATABASE_URL", raw_url)
    # None represents v0.1 installations from before Alembic stamping existed.
    command.upgrade(_config(database_url), starting_revision or migration.BASELINE_REVISION)
    engine = create_engine(database_url)
    try:
        if starting_revision is None:
            with engine.begin() as connection:
                connection.execute(text("DROP TABLE alembic_version"))
        expected = _seed_issued_connections(
            engine, legacy_variant=starting_revision in (None, migration.BASELINE_REVISION),
        )
        settings = Settings(_env_file=None, database_url=raw_url, superadmin_telegram_ids=[9001])
        monkeypatch.setattr(migration, "get_settings", lambda: settings)
        migration.migrate_db()
        migration.migrate_db()  # A second startup must be idempotent.
        with engine.connect() as connection:
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == HEAD
            assert connection.execute(text("SELECT count(*) FROM connection_revision")).scalar_one() == 2
    finally:
        engine.dispose()

    async_engine = create_async_engine(database_url.set(drivername="postgresql+asyncpg"))
    try:
        async with AsyncSession(async_engine, expire_on_commit=False) as session:
            user = await session.get(User, 9001)
            assert user is not None
            assert user.role == UserRole.SUPERADMIN
            assert user.devices_max == 9
            for row in expected:
                connection = await session.get(Connection, row["connection_id"])
                revision = await session.get(ConnectionRevision, row["revision_id"])
                assert connection is not None and revision is not None
                assert connection.variant == row["variant"]
                assert revision.status == RecordStatus.ACTIVE
                assert revision.slot == 0
                assert revision.effective_config_json == row["effective"]
                assert export_client_config(revision.effective_config_json) == row["export"]
            user.telegram_first_name = "still-writable"
            await session.commit()
        async with AsyncSession(async_engine) as session:
            assert await session.scalar(select(User.telegram_first_name).where(User.telegram_id == 9001)) == "still-writable"
    finally:
        await async_engine.dispose()
