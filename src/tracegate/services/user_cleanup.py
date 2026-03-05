from sqlalchemy import exists, select
from sqlalchemy.sql.elements import ColumnElement

from tracegate.enums import RecordStatus
from tracegate.models import Connection, Device, User


def user_without_connections_predicate() -> ColumnElement[bool]:
    has_connection = exists(
        select(Connection.id).where(
            Connection.user_id == User.telegram_id,
            Connection.status == RecordStatus.ACTIVE,
        )
    )
    return ~has_connection


def user_without_artifacts_predicate() -> ColumnElement[bool]:
    has_device = exists(
        select(Device.id).where(
            Device.user_id == User.telegram_id,
            Device.status == RecordStatus.ACTIVE,
        )
    )
    has_connection = exists(
        select(Connection.id).where(
            Connection.user_id == User.telegram_id,
            Connection.status == RecordStatus.ACTIVE,
        )
    )
    return (~has_device) & (~has_connection)
