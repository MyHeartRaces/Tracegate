from __future__ import annotations

from uuid import UUID

import httpx

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant


class ApiClientError(RuntimeError):
    pass


class TracegateApiClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    async def _request(self, method: str, path: str, **kwargs):
        headers = kwargs.pop("headers", {})
        headers["x-api-token"] = self.token

        async with httpx.AsyncClient(base_url=self.base_url) as client:
            response = await client.request(method, path, headers=headers, timeout=20, **kwargs)

        if response.status_code >= 400:
            detail = response.text
            raise ApiClientError(f"{response.status_code} {path}: {detail}")

        if response.status_code == 204:
            return None
        return response.json()

    async def get_or_create_user(self, telegram_id: int) -> dict:
        try:
            return await self._request("GET", f"/users/telegram/{telegram_id}")
        except ApiClientError:
            return await self._request("POST", "/users", json={"telegram_id": telegram_id})

    async def list_devices(self, user_id: int | str) -> list[dict]:
        return await self._request("GET", f"/devices/by-user/{user_id}")

    async def create_device(self, user_id: int | str, name: str) -> dict:
        return await self._request("POST", "/devices", json={"user_id": str(user_id), "name": name})

    async def delete_device(self, device_id: UUID | str) -> None:
        await self._request("DELETE", f"/devices/{device_id}")

    async def list_connections(self, device_id: UUID | str) -> list[dict]:
        return await self._request("GET", f"/connections/by-device/{device_id}")

    async def get_connection(self, connection_id: UUID | str) -> dict:
        return await self._request("GET", f"/connections/{connection_id}")

    async def list_sni_filtered(self, provider: str | None, *, purpose: str | None = None) -> list[dict]:
        params = {}
        if provider:
            params["provider"] = provider
        if purpose:
            params["purpose"] = purpose
        return await self._request("GET", "/sni", params=params)

    async def list_sni(self) -> list[dict]:
        return await self.list_sni_filtered(None)

    async def list_revisions(self, connection_id: UUID | str) -> list[dict]:
        return await self._request("GET", f"/revisions/by-connection/{connection_id}")

    async def issue_revision(self, connection_id: UUID | str, sni_id: int | None = None) -> dict:
        return await self._request(
            "POST",
            f"/revisions/by-connection/{connection_id}",
            json={"camouflage_sni_id": sni_id, "force": False},
        )

    async def activate_revision(self, revision_id: UUID | str) -> dict:
        return await self._request("POST", f"/revisions/{revision_id}/activate")

    async def revoke_revision(self, revision_id: UUID | str) -> dict:
        return await self._request("POST", f"/revisions/{revision_id}/revoke")

    async def create_connection_and_revision(
        self,
        user_id: int | str,
        device_id: UUID | str,
        protocol: ConnectionProtocol,
        mode: ConnectionMode,
        variant: ConnectionVariant,
        sni_id: int | None,
        custom_overrides_json: dict | None = None,
    ) -> tuple[dict, dict]:
        connection = await self._request(
            "POST",
            "/connections",
            json={
                "user_id": str(user_id),
                "device_id": str(device_id),
                "protocol": protocol.value,
                "mode": mode.value,
                "variant": variant.value,
                "profile_name": variant.value,
                "custom_overrides_json": custom_overrides_json or {},
            },
        )
        revision = await self._request(
            "POST",
            f"/revisions/by-connection/{connection['id']}",
            json={"camouflage_sni_id": sni_id, "force": False},
        )
        return connection, revision

    async def delete_connection(self, connection_id: UUID | str) -> None:
        await self._request("DELETE", f"/connections/{connection_id}")

    async def create_grafana_otp(self, telegram_id: int) -> dict:
        return await self._request("POST", "/grafana/otp", json={"telegram_id": telegram_id})

    async def register_bot_message(
        self,
        *,
        telegram_id: int,
        chat_id: int,
        message_id: int,
        connection_id: UUID | str | None = None,
        device_id: UUID | str | None = None,
        revision_id: UUID | str | None = None,
    ) -> dict:
        return await self._request(
            "POST",
            "/bot-messages",
            json={
                "telegram_id": telegram_id,
                "chat_id": chat_id,
                "message_id": message_id,
                "connection_id": str(connection_id) if connection_id else None,
                "device_id": str(device_id) if device_id else None,
                "revision_id": str(revision_id) if revision_id else None,
            },
        )

    async def cleanup_bot_messages(
        self,
        *,
        connection_id: UUID | str | None = None,
        device_id: UUID | str | None = None,
        revision_id: UUID | str | None = None,
    ) -> list[dict]:
        return await self._request(
            "POST",
            "/bot-messages/cleanup",
            json={
                "connection_id": str(connection_id) if connection_id else None,
                "device_id": str(device_id) if device_id else None,
                "revision_id": str(revision_id) if revision_id else None,
            },
        )

    async def set_user_role(self, telegram_id: int, role: str) -> dict:
        return await self._request("PATCH", f"/users/{telegram_id}/role", json={"role": role})

    async def list_users(self, role: str | None = None, limit: int = 200) -> list[dict]:
        params = {"limit": str(limit)}
        if role:
            params["role"] = role
        return await self._request("GET", "/users", params=params)

    async def list_nodes(self) -> list[dict]:
        return await self._request("GET", "/nodes")
