from pathlib import Path

import pytest

from tracegate.cli.migrate_db import _alembic_config


@pytest.mark.parametrize("url", [
    "postgresql+psycopg://operator:p%40ss%25word@localhost/tracegate",
    "postgresql+psycopg:///tracegate?host=%2Ftmp%2Ftracegate-postgres",
])
def test_migration_config_preserves_encoded_database_urls(monkeypatch, url: str) -> None:
    root = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("TRACEGATE_ALEMBIC_INI", str(root / "alembic.ini"))

    config = _alembic_config(sync_database_url=url)

    assert config.get_main_option("sqlalchemy.url") == url
