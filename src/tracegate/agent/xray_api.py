from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlparse

import grpc

from tracegate.settings import Settings

from xray.app.proxyman.command import command_pb2, command_pb2_grpc
from xray.app.stats.command import command_pb2 as stats_command_pb2
from xray.app.stats.command import command_pb2_grpc as stats_command_pb2_grpc
from xray.common.protocol import user_pb2
from xray.common.serial import typed_message_pb2
from xray.proxy.hysteria.account import config_pb2 as hysteria_account_pb2
from xray.proxy.vless import account_pb2


class XrayApiError(RuntimeError):
    pass


class XrayApiInboundMissing(XrayApiError):
    pass


def _is_loopback_host(host: str) -> bool:
    normalized = str(host or "").strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _xray_api_target_host(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    if raw.startswith("unix:"):
        return "localhost"
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme == "unix":
            return "localhost"
        return str(parsed.hostname or "").strip()

    host, sep, port_raw = raw.rpartition(":")
    if not sep or not host or not port_raw:
        return ""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host.strip()


def _require_loopback_xray_api_target(settings: Settings) -> str:
    target = str(settings.agent_xray_api_server or "").strip()
    host = _xray_api_target_host(target)
    if not _is_loopback_host(host):
        raise XrayApiError(f"Xray API server must be loopback-bound, got {target or 'missing'}")
    return target


def _build_vless_user(*, email: str, uuid: str) -> user_pb2.User:
    email_s = str(email or "").strip()
    uuid_s = str(uuid or "").strip()
    if not email_s or not uuid_s:
        raise ValueError("email/uuid are required to build a VLESS user")

    account = account_pb2.Account(id=uuid_s, encryption="none")
    return user_pb2.User(
        level=0,
        email=email_s,
        account=typed_message_pb2.TypedMessage(
            type="xray.proxy.vless.Account",
            value=account.SerializeToString(),
        ),
    )


def _build_hysteria_user(*, email: str, auth: str) -> user_pb2.User:
    email_s = str(email or "").strip()
    auth_s = str(auth or "").strip()
    if not email_s or not auth_s:
        raise ValueError("email/auth are required to build a Hysteria user")

    account = hysteria_account_pb2.Account(auth=auth_s)
    return user_pb2.User(
        level=0,
        email=email_s,
        account=typed_message_pb2.TypedMessage(
            type="xray.proxy.hysteria.account.Account",
            value=account.SerializeToString(),
        ),
    )


def _serialize_string_field(field_number: int, value: str) -> bytes:
    payload = str(value or "").encode("utf-8")
    if field_number < 1:
        raise ValueError("protobuf field number must be positive")
    key = (field_number << 3) | 2
    out = bytearray()
    while key >= 0x80:
        out.append((key & 0x7F) | 0x80)
        key >>= 7
    out.append(key)
    length = len(payload)
    while length >= 0x80:
        out.append((length & 0x7F) | 0x80)
        length >>= 7
    out.append(length)
    out.extend(payload)
    return bytes(out)


def _build_shadowsocks2022_user(*, email: str, key: str) -> user_pb2.User:
    email_s = str(email or "").strip()
    key_s = str(key or "").strip()
    if not email_s or not key_s:
        raise ValueError("email/key are required to build a Shadowsocks-2022 user")

    return user_pb2.User(
        level=0,
        email=email_s,
        account=typed_message_pb2.TypedMessage(
            type="xray.proxy.shadowsocks_2022.Account",
            value=_serialize_string_field(1, key_s),
        ),
    )


def _add_user(settings: Settings, *, inbound_tag: str, email: str, user: user_pb2.User) -> None:
    email_s = str(email or "").strip()
    if not email_s:
        raise ValueError("email is required to add an Xray user")

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


def _stub(settings: Settings) -> tuple[grpc.Channel, command_pb2_grpc.HandlerServiceStub]:
    channel = grpc.insecure_channel(_require_loopback_xray_api_target(settings))
    return channel, command_pb2_grpc.HandlerServiceStub(channel)


def _stats_stub(settings: Settings) -> tuple[grpc.Channel, stats_command_pb2_grpc.StatsServiceStub]:
    channel = grpc.insecure_channel(_require_loopback_xray_api_target(settings))
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
    _add_user(settings, inbound_tag=inbound_tag, email=email, user=_build_vless_user(email=email, uuid=uuid))


def add_hysteria_user(settings: Settings, *, inbound_tag: str, email: str, auth: str) -> None:
    _add_user(settings, inbound_tag=inbound_tag, email=email, user=_build_hysteria_user(email=email, auth=auth))


def add_shadowsocks2022_user(settings: Settings, *, inbound_tag: str, email: str, key: str) -> None:
    _add_user(
        settings,
        inbound_tag=inbound_tag,
        email=email,
        user=_build_shadowsocks2022_user(email=email, key=key),
    )


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


def sync_inbound_users(settings: Settings, *, inbound_tag: str, desired_email_to_user: dict[str, dict[str, str] | str]) -> bool:
    """
    Make inbound users match exactly the desired set (by email).

    Returns True if any add/remove was attempted.
    """
    desired: dict[str, dict[str, str]] = {}
    for email, raw_spec in (desired_email_to_user or {}).items():
        email_s = str(email or "").strip()
        if not email_s:
            continue
        if isinstance(raw_spec, str):
            uuid_s = str(raw_spec or "").strip()
            if not uuid_s:
                continue
            desired[email_s] = {"protocol": "vless", "uuid": uuid_s}
            continue
        if not isinstance(raw_spec, dict):
            continue

        protocol = str(raw_spec.get("protocol") or "").strip().lower() or "vless"
        if protocol == "vless":
            uuid_s = str(raw_spec.get("uuid") or "").strip()
            if not uuid_s:
                continue
            desired[email_s] = {"protocol": "vless", "uuid": uuid_s}
            continue
        if protocol == "hysteria":
            auth_s = str(raw_spec.get("auth") or "").strip()
            if not auth_s:
                continue
            desired[email_s] = {"protocol": "hysteria", "auth": auth_s}
            continue
        if protocol == "shadowsocks2022":
            key_s = str(raw_spec.get("key") or "").strip()
            if not key_s:
                continue
            desired[email_s] = {"protocol": "shadowsocks2022", "key": key_s}

    try:
        current = list_inbound_user_emails(settings, inbound_tag=inbound_tag)
    except XrayApiInboundMissing:
        return False
    desired_emails = set(desired.keys())

    to_add = sorted(desired_emails - current, key=str)
    to_remove = sorted(current - desired_emails, key=str)
    changed = bool(to_add or to_remove)

    for email in to_add:
        spec = desired[email]
        protocol = str(spec.get("protocol") or "").strip().lower()
        if protocol == "hysteria":
            add_hysteria_user(settings, inbound_tag=inbound_tag, email=email, auth=str(spec.get("auth") or "").strip())
        elif protocol == "shadowsocks2022":
            add_shadowsocks2022_user(
                settings,
                inbound_tag=inbound_tag,
                email=email,
                key=str(spec.get("key") or "").strip(),
            )
        else:
            add_vless_user(settings, inbound_tag=inbound_tag, email=email, uuid=str(spec.get("uuid") or "").strip())
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
            # Xray StatsService QueryStats uses prefix matching, not glob/regex.
            # Example stat name: "user>>>EMAIL>>>traffic>>>uplink"
            stats_command_pb2.QueryStatsRequest(pattern="user>>>", reset=bool(reset)),
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


def query_inbound_traffic_bytes(settings: Settings, *, reset: bool = False) -> dict[str, dict[str, int]]:
    """
    Query Xray StatsService for per-inbound traffic counters.

    Returns mapping:
      { inbound_tag: {"uplink": bytes, "downlink": bytes} }
    """
    channel, stub = _stats_stub(settings)
    try:
        resp = stub.QueryStats(
            stats_command_pb2.QueryStatsRequest(pattern="inbound>>>", reset=bool(reset)),
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
        if parts[0] != "inbound" or parts[2] != "traffic":
            continue
        inbound_tag = str(parts[1] or "").strip()
        direction = str(parts[3] or "").strip().lower()
        if not inbound_tag or direction not in {"uplink", "downlink"}:
            continue
        bucket = out.setdefault(inbound_tag, {"uplink": 0, "downlink": 0})
        bucket[direction] = value
    return out
