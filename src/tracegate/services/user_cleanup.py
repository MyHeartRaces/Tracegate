from sqlalchemy import exists, select
from sqlalchemy.sql.elements import ColumnElement

from tracegate.enums import RecordStatus
from tracegate.models import Connection, Device, MTProtoAccessGrant, User


def user_without_connections_predicate() -> ColumnElement[bool]:
    has_connection = exists(
        select(Connection.id).where(
            Connection.user_id == User.telegram_id,
            Connection.status == RecordStatus.ACTIVE,
        )
    )
    has_mtproto_access = exists(
        select(MTProtoAccessGrant.telegram_id).where(
            MTProtoAccessGrant.telegram_id == User.telegram_id,
            MTProtoAccessGrant.status == RecordStatus.ACTIVE,
        )
    )
    return (~has_connection) & (~has_mtproto_access)


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
    has_mtproto_access = exists(
        select(MTProtoAccessGrant.telegram_id).where(
            MTProtoAccessGrant.telegram_id == User.telegram_id,
            MTProtoAccessGrant.status == RecordStatus.ACTIVE,
        )
    )
    return (~has_device) & (~has_connection) & (~has_mtproto_access)
