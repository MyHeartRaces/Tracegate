"""Shared helpers for the bot tests (no tests here).

Some agent tests install a bare ``prometheus_client`` stub via ``setdefault``
during collection, so the bot is imported with a complete stub in place and
the original module is restored afterwards.
"""

from __future__ import annotations

import sys
import types
import uuid
from types import SimpleNamespace
from typing import Any


def import_bot() -> None:
    stub = types.ModuleType("prometheus_client")
    stub.Counter = lambda *args, **kwargs: None
    stub.Gauge = lambda *args, **kwargs: None
    stub.Histogram = lambda *args, **kwargs: None
    stub.start_http_server = lambda *args, **kwargs: None
    original = sys.modules.get("prometheus_client")
    sys.modules["prometheus_client"] = stub
    try:
        import tracegate.bot.main  # noqa: F401
    finally:
        if original is None:
            sys.modules.pop("prometheus_client", None)
        else:
            sys.modules["prometheus_client"] = original


import_bot()


def new_id() -> str:
    return str(uuid.uuid4())


class DummyBot:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self.deleted: list[tuple[int, int]] = []
        self.fail_for: set[int] = set()

    async def send_message(self, *, chat_id: int, text: str, **kwargs: Any) -> SimpleNamespace:
        if int(chat_id) in self.fail_for:
            raise RuntimeError("chat unavailable")
        self.sent.append({"chat_id": chat_id, "text": text, **kwargs})
        return SimpleNamespace(message_id=len(self.sent))

    async def delete_message(self, *, chat_id: int, message_id: int) -> None:
        self.deleted.append((chat_id, message_id))


class DummyMessage:
    def __init__(self, text: str | None = None, *, user_id: int = 1, bot: DummyBot | None = None) -> None:
        self.text = text
        self.caption = None
        self.from_user = SimpleNamespace(id=user_id, username=None, first_name=None, last_name=None)
        self.chat = SimpleNamespace(id=user_id, type="private")
        self.message_id = 500
        self.bot = bot or DummyBot()
        self.answers: list[tuple[str, dict[str, Any]]] = []
        self.edits: list[tuple[str, dict[str, Any]]] = []
        self.photos: list[dict[str, Any]] = []
        self.documents: list[dict[str, Any]] = []
        self.edit_error: Exception | None = None

    async def answer(self, text: str, **kwargs: Any) -> SimpleNamespace:
        self.answers.append((text, kwargs))
        return SimpleNamespace(message_id=1000 + len(self.answers))

    async def edit_text(self, text: str, **kwargs: Any) -> None:
        if self.edit_error is not None:
            raise self.edit_error
        self.edits.append((text, kwargs))

    async def answer_photo(self, photo: Any, **kwargs: Any) -> SimpleNamespace:
        self.photos.append({"photo": photo, **kwargs})
        return SimpleNamespace(message_id=2000 + len(self.photos))

    async def answer_document(self, document: Any, **kwargs: Any) -> SimpleNamespace:
        self.documents.append({"document": document, **kwargs})
        return SimpleNamespace(message_id=3000 + len(self.documents))

    # Convenience views.
    @property
    def screens(self) -> list[str]:
        return [text for text, _kwargs in self.edits]

    @property
    def sent_texts(self) -> list[str]:
        return [text for text, _kwargs in self.answers]

    def last_keyboard(self) -> Any:
        for _text, kwargs in reversed(self.edits + self.answers):
            if kwargs.get("reply_markup") is not None:
                return kwargs["reply_markup"]
        return None


class DummyCallback:
    def __init__(self, data: str, *, user_id: int = 1, message: DummyMessage | None = None) -> None:
        self.data = data
        self.from_user = SimpleNamespace(id=user_id, username=None, first_name=None, last_name=None)
        self.message = message or DummyMessage(user_id=user_id)
        self.bot = self.message.bot
        self.answers: list[tuple[str | None, dict[str, Any]]] = []

    async def answer(self, text: str | None = None, **kwargs: Any) -> None:
        self.answers.append((text, kwargs))


class DummyState:
    def __init__(self, data: dict[str, Any] | None = None, state: Any = None) -> None:
        self.state = state
        self.data: dict[str, Any] = dict(data or {})
        self.cleared = 0

    async def set_state(self, value: Any) -> None:
        self.state = value

    async def get_state(self) -> Any:
        return self.state

    async def clear(self) -> None:
        self.cleared += 1
        self.state = None
        self.data = {}

    async def get_data(self) -> dict[str, Any]:
        return dict(self.data)

    async def update_data(self, **kwargs: Any) -> dict[str, Any]:
        self.data.update(kwargs)
        return dict(self.data)


def buttons(keyboard: Any) -> list[Any]:
    return [button for row in keyboard.inline_keyboard for button in row] if keyboard is not None else []


def button_texts(keyboard: Any) -> list[str]:
    return [str(button.text) for button in buttons(keyboard)]


def callback_datas(keyboard: Any) -> list[str]:
    return [str(button.callback_data) for button in buttons(keyboard) if button.callback_data is not None]


class FakeApi:
    """In-memory stand-in for TracegateApiClient used by handler tests."""

    def __init__(self) -> None:
        self.users: dict[int, dict] = {
            1: {"telegram_id": 1, "role": "user", "telegram_username": "alice"},
        }
        self.devices: dict[str, dict] = {}
        self.connections: dict[str, dict] = {}
        self.revisions: dict[str, dict] = {}
        self.calls: list[tuple[str, tuple, dict]] = []
        self.fail: dict[str, BaseException] = {}
        self.mtproto: dict[int, dict] = {}
        self.cleanup_refs: list[dict] = []

    def _record(self, name: str, *args: Any, **kwargs: Any) -> None:
        self.calls.append((name, args, kwargs))
        if name in self.fail:
            raise self.fail[name]

    def called(self, name: str) -> list[tuple[tuple, dict]]:
        return [(args, kwargs) for call, args, kwargs in self.calls if call == name]

    # --- seed helpers
    def add_device(self, user_id: int = 1, name: str = "Телефон") -> dict:
        device = {"id": new_id(), "user_id": user_id, "name": name, "status": "active"}
        self.devices[device["id"]] = device
        return device

    def add_connection(
        self,
        device: dict,
        *,
        protocol: str = "vless_reality",
        mode: str = "chain",
        variant: str = "V1",
        overrides: dict | None = None,
        alias: str | None = None,
        revisions: int = 1,
    ) -> dict:
        connection_id = new_id()
        connection = {
            "id": connection_id,
            "user_id": device["user_id"],
            "device_id": device["id"],
            "device_name": device["name"],
            "alias": alias if alias is not None else f"@alice (1) - {device['name']} - {connection_id}",
            "protocol": protocol,
            "mode": mode,
            "variant": variant,
            "profile_name": "x",
            "custom_overrides_json": overrides or {},
            "status": "active",
        }
        self.connections[connection_id] = connection
        for slot in range(revisions):
            self.add_revision(connection, slot=slot)
        return connection

    def add_revision(self, connection: dict, *, slot: int = 0, status: str = "active") -> dict:
        revision = {
            "id": new_id(),
            "connection_id": connection["id"],
            "slot": slot,
            "status": status,
            "camouflage_sni_id": None,
            "effective_config_json": {"protocol": "vless", "transport": "reality"},
            "created_at": f"2026-11-1{slot}T10:00:00+00:00",
        }
        self.revisions[revision["id"]] = revision
        return revision

    # --- users
    async def get_or_create_user(self, telegram_id: int, **kwargs: Any) -> dict:
        self._record("get_or_create_user", telegram_id, **kwargs)
        return self.users.setdefault(int(telegram_id), {"telegram_id": int(telegram_id), "role": "user"})

    async def get_user(self, telegram_id: int) -> dict:
        self._record("get_user", telegram_id)
        from tracegate.bot.client import ApiClientError

        if int(telegram_id) not in self.users:
            raise ApiClientError(status_code=404, path=f"/users/{telegram_id}", detail='{"detail":"User not found"}')
        return self.users[int(telegram_id)]

    async def accept_bot_welcome(self, telegram_id: int, *, version: str) -> dict:
        self._record("accept_bot_welcome", telegram_id, version=version)
        user = self.users[int(telegram_id)]
        user.update({"bot_welcome_accepted_at": "2026-11-17T00:00:00+00:00", "bot_welcome_version": version})
        return user

    async def list_users(self, role: str | None = None, limit: int = 200, **kwargs: Any) -> list[dict]:
        self._record("list_users", role=role, limit=limit, **kwargs)
        rows = list(self.users.values())
        if role:
            rows = [row for row in rows if row.get("role") == role]
        return rows

    async def set_user_role(self, telegram_id: int, role: str) -> dict:
        self._record("set_user_role", telegram_id, role)
        user = self.users.setdefault(int(telegram_id), {"telegram_id": int(telegram_id)})
        user["role"] = role
        return user

    async def block_user_bot(self, telegram_id: int, **kwargs: Any) -> dict:
        self._record("block_user_bot", telegram_id, **kwargs)
        return {"telegram_id": telegram_id, "bot_blocked_until": "2026-11-20T10:00:00+00:00", "bot_block_reason": kwargs.get("reason")}

    async def unblock_user_bot(self, telegram_id: int) -> dict:
        self._record("unblock_user_bot", telegram_id)
        return {"telegram_id": telegram_id}

    async def revoke_user_access(self, **kwargs: Any) -> dict:
        self._record("revoke_user_access", **kwargs)
        return {"revoked_connections": 2, "revoked_devices": 1, "revoked_mtproto_access": True, "revoked_connection_ids": []}

    async def reset_all_connections(self, **kwargs: Any) -> dict:
        self._record("reset_all_connections", **kwargs)
        return {"revoked_connections": 3, "revoked_mtproto_accesses": 1, "revoked_connection_ids": []}

    async def create_grafana_otp(self, telegram_id: int, scope: str = "user") -> dict:
        self._record("create_grafana_otp", telegram_id, scope=scope)
        return {"expires_at": "2026-11-17T10:05:00Z", "login_url": "https://grafana.example.test/login?code=x"}

    # --- devices
    async def list_devices(self, user_id: int) -> list[dict]:
        self._record("list_devices", user_id)
        return [d for d in self.devices.values() if d["user_id"] == int(user_id) and d["status"] == "active"]

    async def get_device(self, device_id: str) -> dict:
        self._record("get_device", device_id)
        from tracegate.bot.client import ApiClientError

        if str(device_id) not in self.devices:
            raise ApiClientError(status_code=404, path=f"/devices/{device_id}", detail='{"detail":"Device not found"}')
        return self.devices[str(device_id)]

    async def create_device(self, user_id: int, name: str) -> dict:
        self._record("create_device", user_id, name)
        return self.add_device(int(user_id), name)

    async def rename_device(self, device_id: str, name: str) -> dict:
        self._record("rename_device", device_id, name)
        self.devices[str(device_id)]["name"] = name
        return self.devices[str(device_id)]

    async def delete_device(self, device_id: str) -> None:
        self._record("delete_device", device_id)
        self.devices[str(device_id)]["status"] = "revoked"

    # --- connections
    async def list_connections(self, device_id: str) -> list[dict]:
        self._record("list_connections", device_id)
        return [c for c in self.connections.values() if c["device_id"] == str(device_id) and c["status"] == "active"]

    async def get_connection(self, connection_id: str) -> dict:
        self._record("get_connection", connection_id)
        from tracegate.bot.client import ApiClientError

        if str(connection_id) not in self.connections:
            raise ApiClientError(status_code=404, path=f"/connections/{connection_id}", detail="secret-body")
        return self.connections[str(connection_id)]

    async def create_connection_and_revision(self, user_id, device_id, protocol, mode, variant, sni_id, overrides=None):  # noqa: ANN001, ANN201
        self._record("create_connection_and_revision", user_id, device_id, protocol, mode, variant, sni_id, overrides)
        device = self.devices[str(device_id)]
        connection = self.add_connection(
            device, protocol=protocol.value, mode=mode.value, variant=variant.value, overrides=overrides, revisions=0
        )
        revision = self.add_revision(connection)
        return connection, revision

    async def delete_connection(self, connection_id: str) -> None:
        self._record("delete_connection", connection_id)
        self.connections[str(connection_id)]["status"] = "revoked"

    # --- revisions
    async def list_revisions(self, connection_id: str) -> list[dict]:
        self._record("list_revisions", connection_id)
        rows = [r for r in self.revisions.values() if r["connection_id"] == str(connection_id)]
        return sorted(rows, key=lambda r: r["created_at"], reverse=True)

    async def get_revision(self, revision_id: str) -> dict:
        self._record("get_revision", revision_id)
        return self.revisions[str(revision_id)]

    async def issue_revision(self, connection_id: str, sni_id: int | None = None) -> dict:
        self._record("issue_revision", connection_id)
        return self.add_revision(self.connections[str(connection_id)], slot=0)

    async def activate_revision(self, revision_id: str) -> dict:
        self._record("activate_revision", revision_id)
        return self.revisions[str(revision_id)]

    async def revoke_revision(self, revision_id: str) -> dict:
        self._record("revoke_revision", revision_id)
        revision = self.revisions[str(revision_id)]
        revision["status"] = "revoked"
        connection = self.connections[revision["connection_id"]]
        if not any(r["status"] == "active" for r in self.revisions.values() if r["connection_id"] == connection["id"]):
            connection["status"] = "revoked"
        return revision

    # --- bot messages
    async def register_bot_message(self, **kwargs: Any) -> dict:
        self._record("register_bot_message", **kwargs)
        return {}

    async def cleanup_bot_messages(self, **kwargs: Any) -> list[dict]:
        self._record("cleanup_bot_messages", **kwargs)
        return list(self.cleanup_refs)

    # --- mtproto
    async def get_mtproto_access(self, telegram_id: int) -> dict:
        self._record("get_mtproto_access", telegram_id)
        from tracegate.bot.client import ApiClientError

        if int(telegram_id) not in self.mtproto:
            raise ApiClientError(status_code=404, path="/mtproto", detail="none")
        return self.mtproto[int(telegram_id)]

    async def list_mtproto_access(self, **kwargs: Any) -> list[dict]:
        self._record("list_mtproto_access", **kwargs)
        return [{"telegram_id": key, **value} for key, value in self.mtproto.items()]

    async def issue_mtproto_access(self, **kwargs: Any) -> dict:
        self._record("issue_mtproto_access", **kwargs)
        self.mtproto[int(kwargs["telegram_id"])] = {"label": kwargs.get("label")}
        return {
            "node": "node-a",
            "grant": {"label": kwargs.get("label")},
            "profile": {
                "server": "proxied.tracegate.test",
                "port": 443,
                "httpsUrl": "https://t.me/proxy?server=proxied.tracegate.test&port=443&secret=ee00",
                "tgUri": "tg://proxy?server=proxied.tracegate.test&port=443&secret=ee00",
                "reused": False,
            },
        }

    async def revoke_mtproto_access(self, telegram_id: int) -> dict:
        self._record("revoke_mtproto_access", telegram_id)
        from tracegate.bot.client import ApiClientError

        if int(telegram_id) not in self.mtproto:
            raise ApiClientError(status_code=404, path="/mtproto", detail="none")
        self.mtproto.pop(int(telegram_id))
        return {}


def test_fake_api_scopes_devices_to_their_owner() -> None:
    import asyncio

    api = FakeApi()
    mine = api.add_device(user_id=1)
    api.add_device(user_id=2)
    assert [row["id"] for row in asyncio.run(api.list_devices(1))] == [mine["id"]]
