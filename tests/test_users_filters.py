from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from tracegate.models import User
from tracegate.services.user_cleanup import user_without_artifacts_predicate, user_without_connections_predicate


def test_user_without_artifacts_predicate_uses_device_and_connection_existence() -> None:
    stmt = select(User.telegram_id).where(user_without_artifacts_predicate())
    sql = str(stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))

    assert "NOT (EXISTS" in sql
    assert "FROM device" in sql
    assert "FROM connection" in sql


def test_user_without_connections_predicate_uses_connection_existence() -> None:
    stmt = select(User.telegram_id).where(user_without_connections_predicate())
    sql = str(stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))

    assert "NOT (EXISTS" in sql
    assert "FROM connection" in sql
