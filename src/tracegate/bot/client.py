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

    async def list_devices(self, user_id: UUID | str) -> list[dict]:
        return await self._request("GET", f"/devices/by-user/{user_id}")

    async def create_device(self, user_id: UUID | str, name: str) -> dict:
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
        user_id: UUID | str,
        device_id: UUID | str,
        protocol: ConnectionProtocol,
        mode: ConnectionMode,
        variant: ConnectionVariant,
        sni_id: int | None,
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
                "custom_overrides_json": {},
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
