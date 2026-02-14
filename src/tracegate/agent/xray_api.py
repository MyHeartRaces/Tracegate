from __future__ import annotations

import grpc

from tracegate.settings import Settings

from xray.app.proxyman.command import command_pb2, command_pb2_grpc
from xray.app.stats.command import command_pb2 as stats_command_pb2
from xray.app.stats.command import command_pb2_grpc as stats_command_pb2_grpc
from xray.common.protocol import user_pb2
from xray.common.serial import typed_message_pb2
from xray.proxy.vless import account_pb2


class XrayApiError(RuntimeError):
    pass


class XrayApiInboundMissing(XrayApiError):
    pass


def _stub(settings: Settings) -> tuple[grpc.Channel, command_pb2_grpc.HandlerServiceStub]:
    channel = grpc.insecure_channel(settings.agent_xray_api_server)
    return channel, command_pb2_grpc.HandlerServiceStub(channel)


def _stats_stub(settings: Settings) -> tuple[grpc.Channel, stats_command_pb2_grpc.StatsServiceStub]:
    channel = grpc.insecure_channel(settings.agent_xray_api_server)
    return channel, stats_command_pb2_grpc.StatsServiceStub(channel)


def list_inbound_user_emails(settings: Settings, *, inbound_tag: str) -> set[str]:
    channel, stub = _stub(settings)
    try:
        resp = stub.GetInboundUsers(
            command_pb2.GetInboundUserRequest(tag=inbound_tag, email=""),
            timeout=float(settings.agent_xray_api_timeout_seconds or 3),
        )
    except grpc.RpcError as exc:  # pragma: no cover
        details = str(exc)
        if "handler not found" in details or "failed to get handler" in details:
            raise XrayApiInboundMissing(f"inbound not found: {inbound_tag}") from exc
        raise XrayApiError(f"GetInboundUsers failed for inbound={inbound_tag}: {exc}") from exc
    finally:
        channel.close()

    emails: set[str] = set()
    for row in resp.users:
        email = str(row.email or "").strip()
        if email:
            emails.add(email)
    return emails


def add_vless_user(settings: Settings, *, inbound_tag: str, email: str, uuid: str) -> None:
    email_s = str(email or "").strip()
    uuid_s = str(uuid or "").strip()
    if not email_s or not uuid_s:
        raise ValueError("email/uuid are required to add a VLESS user")

    account = account_pb2.Account(id=uuid_s, encryption="none")
    user = user_pb2.User(
        level=0,
        email=email_s,
        account=typed_message_pb2.TypedMessage(
            type="xray.proxy.vless.Account",
            value=account.SerializeToString(),
        ),
    )
    op = command_pb2.AddUserOperation(user=user)
    req = command_pb2.AlterInboundRequest(
        tag=inbound_tag,
        operation=typed_message_pb2.TypedMessage(
            type="xray.app.proxyman.command.AddUserOperation",
            value=op.SerializeToString(),
        ),
    )

    channel, stub = _stub(settings)
    try:
        stub.AlterInbound(req, timeout=float(settings.agent_xray_api_timeout_seconds or 3))
    except grpc.RpcError as exc:  # pragma: no cover
        details = str(exc)
        if "already exists" in details:
            return
        raise XrayApiError(f"AddUser failed for inbound={inbound_tag} email={email_s}: {exc}") from exc
    finally:
        channel.close()


def remove_user(settings: Settings, *, inbound_tag: str, email: str) -> None:
    email_s = str(email or "").strip()
    if not email_s:
        raise ValueError("email is required to remove a user")

    op = command_pb2.RemoveUserOperation(email=email_s)
    req = command_pb2.AlterInboundRequest(
        tag=inbound_tag,
        operation=typed_message_pb2.TypedMessage(
            type="xray.app.proxyman.command.RemoveUserOperation",
            value=op.SerializeToString(),
        ),
    )

    channel, stub = _stub(settings)
    try:
        stub.AlterInbound(req, timeout=float(settings.agent_xray_api_timeout_seconds or 3))
    except grpc.RpcError as exc:  # pragma: no cover
        details = str(exc)
        if "not found" in details or "doesn't exist" in details:
            return
        raise XrayApiError(f"RemoveUser failed for inbound={inbound_tag} email={email_s}: {exc}") from exc
    finally:
        channel.close()


def sync_inbound_users(settings: Settings, *, inbound_tag: str, desired_email_to_uuid: dict[str, str]) -> bool:
    """
    Make inbound users match exactly the desired set (by email).

    Returns True if any add/remove was attempted.
    """
    desired: dict[str, str] = {}
    for email, uuid in (desired_email_to_uuid or {}).items():
        email_s = str(email or "").strip()
        uuid_s = str(uuid or "").strip()
        if not email_s or not uuid_s:
            continue
        desired[email_s] = uuid_s

    try:
        current = list_inbound_user_emails(settings, inbound_tag=inbound_tag)
    except XrayApiInboundMissing:
        return False
    desired_emails = set(desired.keys())

    to_add = sorted(desired_emails - current, key=str)
    to_remove = sorted(current - desired_emails, key=str)
    changed = bool(to_add or to_remove)

    for email in to_add:
        add_vless_user(settings, inbound_tag=inbound_tag, email=email, uuid=desired[email])
    for email in to_remove:
        remove_user(settings, inbound_tag=inbound_tag, email=email)

    return changed


def query_user_traffic_bytes(settings: Settings, *, reset: bool = False) -> dict[str, dict[str, int]]:
    """
    Query Xray StatsService for per-user traffic counters.

    Returns mapping:
      { email: {"uplink": bytes, "downlink": bytes} }
    """
    channel, stub = _stats_stub(settings)
    try:
        resp = stub.QueryStats(
            stats_command_pb2.QueryStatsRequest(pattern="user>>>*>>>traffic>>>*", reset=bool(reset)),
            timeout=float(settings.agent_xray_api_timeout_seconds or 3),
        )
    except grpc.RpcError as exc:  # pragma: no cover
        raise XrayApiError(f"QueryStats failed: {exc}") from exc
    finally:
        channel.close()

    out: dict[str, dict[str, int]] = {}
    for row in resp.stat:
        name = str(getattr(row, "name", "") or "").strip()
        value = int(getattr(row, "value", 0) or 0)
        if not name:
            continue
        parts = name.split(">>>")
        if len(parts) < 4:
            continue
        if parts[0] != "user" or parts[2] != "traffic":
            continue
        email = str(parts[1] or "").strip()
        direction = str(parts[3] or "").strip().lower()
        if not email or direction not in {"uplink", "downlink"}:
            continue
        bucket = out.setdefault(email, {"uplink": 0, "downlink": 0})
        bucket[direction] = value
    return out
