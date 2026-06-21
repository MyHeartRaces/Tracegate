from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID

import pytest

from tracegate.enums import ConnectionMode, ConnectionProtocol
from tracegate.services.revisions import (
    RevisionError,
    _allocate_entry_ingress_pair,
    _entry_ingress_pair_key,
    _infer_legacy_entry_pair,
    _uses_exclusive_entry_pair,
    _uses_exclusive_endpoint_pair,
)
from tracegate.services.sni_catalog import load_catalog


class _Result:
    def __init__(self, values: list[tuple[str | None, dict]]) -> None:
        self._values = values

    def all(self) -> list[tuple[str | None, dict]]:
        return self._values


class _PairSession:
    def __init__(self, used: list[tuple[str | None, dict]] | None = None) -> None:
        self.used = used or []

    async def execute(self, _statement) -> _Result:
        return _Result(self.used)


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        api_internal_token="pair-test-secret",
        grafana_cookie_secret="",
        pseudonym_secret="",
        entry_ingress_alias_token_length=20,
        entry_ingress_exclusive_sni_pairs_enabled=True,
        entry_ingress_sni_pool=[row.fqdn for row in load_catalog() if row.enabled],
        entry_ingress_shards=[
            {"id": "a", "publicIp": "203.0.113.11", "hostnameTemplate": "{token}.a.tracegate.test", "state": "active"},
            {"id": "b", "publicIp": "203.0.113.12", "hostnameTemplate": "{token}.b.tracegate.test", "state": "active"},
            {"id": "c", "publicIp": "203.0.113.13", "hostnameTemplate": "{token}.c.tracegate.test", "state": "active"},
        ],
        endpoint_ingress_alias_token_length=20,
        endpoint_ingress_exclusive_sni_pairs_enabled=True,
        endpoint_ingress_sni_pool=[row.fqdn for row in load_catalog() if row.enabled],
        endpoint_ingress_shards=[
            {"id": "a", "publicIp": "198.51.100.21", "hostnameTemplate": "{token}.a.endpoint.test", "state": "active"},
            {"id": "b", "publicIp": "198.51.100.22", "hostnameTemplate": "{token}.b.endpoint.test", "state": "active"},
            {"id": "c", "publicIp": "198.51.100.23", "hostnameTemplate": "{token}.c.endpoint.test", "state": "active"},
        ],
    )


@pytest.mark.asyncio
async def test_exclusive_entry_pair_allocation_is_stable_and_skips_leased_pair() -> None:
    connection_id = UUID("00000000-0000-0000-0000-000000000123")
    settings = _settings()

    first = await _allocate_entry_ingress_pair(
        _PairSession(),
        connection_id=connection_id,
        rotation_generation=0,
        settings=settings,
    )
    repeated = await _allocate_entry_ingress_pair(
        _PairSession(),
        connection_id=connection_id,
        rotation_generation=0,
        settings=settings,
    )
    replacement = await _allocate_entry_ingress_pair(
        _PairSession([(first.pair_key, {})]),
        connection_id=connection_id,
        rotation_generation=0,
        settings=settings,
    )

    assert first == repeated
    assert replacement.pair_key != first.pair_key
    assert len(first.pair_key) == 64
    assert first.sni.fqdn in settings.entry_ingress_sni_pool
    assert first.host.endswith(f".{first.shard_id}.tracegate.test")


@pytest.mark.asyncio
async def test_exclusive_entry_pair_allocation_reports_pair_capacity_exhaustion() -> None:
    settings = _settings()
    used = [
        _entry_ingress_pair_key(shard["publicIp"], sni)
        for shard in settings.entry_ingress_shards
        for sni in settings.entry_ingress_sni_pool
    ]

    with pytest.raises(RevisionError, match=r"exhausted \(30 active-pair capacity\)"):
        await _allocate_entry_ingress_pair(
            _PairSession([(pair_key, {}) for pair_key in used]),
            connection_id=UUID("00000000-0000-0000-0000-000000000456"),
            rotation_generation=0,
            settings=settings,
        )


def test_exclusive_entry_pair_scope_is_v1_reality_chain_only() -> None:
    settings = _settings()

    assert _uses_exclusive_entry_pair(
        SimpleNamespace(protocol=ConnectionProtocol.VLESS_REALITY, mode=ConnectionMode.CHAIN),
        settings,
    )
    assert not _uses_exclusive_entry_pair(
        SimpleNamespace(protocol=ConnectionProtocol.VLESS_REALITY, mode=ConnectionMode.DIRECT),
        settings,
    )
    assert not _uses_exclusive_entry_pair(
        SimpleNamespace(protocol=ConnectionProtocol.HYSTERIA2, mode=ConnectionMode.CHAIN),
        settings,
    )
    assert _uses_exclusive_endpoint_pair(
        SimpleNamespace(protocol=ConnectionProtocol.VLESS_REALITY, mode=ConnectionMode.DIRECT),
        settings,
    )
    assert not _uses_exclusive_endpoint_pair(
        SimpleNamespace(protocol=ConnectionProtocol.VLESS_REALITY, mode=ConnectionMode.CHAIN),
        settings,
    )


@pytest.mark.asyncio
async def test_exclusive_endpoint_pair_allocates_direct_shard_alias() -> None:
    assignment = await _allocate_entry_ingress_pair(
        _PairSession(),
        connection_id=UUID("00000000-0000-0000-0000-000000000789"),
        rotation_generation=0,
        settings=_settings(),
        role="endpoint",
    )

    assert assignment.public_ip.startswith("198.51.100.")
    assert assignment.host.endswith(f".{assignment.shard_id}.endpoint.test")


def test_infer_legacy_entry_pair_reserves_active_pre_migration_revision() -> None:
    settings = _settings()
    config = {"server": "private-token.b.tracegate.test", "sni": "goya.front-f.example.net"}

    inferred = _infer_legacy_entry_pair(config, settings.entry_ingress_shards)

    assert inferred == (_entry_ingress_pair_key("203.0.113.12", "goya.front-f.example.net"), "b")
