import asyncio
from types import SimpleNamespace
from uuid import UUID

import pytest

from tracegate.enums import ConnectionMode, ConnectionProtocol
from tracegate.services.config_builder import EndpointSet
from tracegate.services.revisions import (
    RevisionError,
    _ensure_chain_config_ready,
    _ensure_chain_endpoint_ready,
    _is_placeholder_host,
    _resolve_node_public_host,
    _resolve_sni,
    _select_revision_sticky_host,
)


def test_is_placeholder_host_detects_example_domain_variants() -> None:
    assert _is_placeholder_host("example.com")
    assert _is_placeholder_host("transit.example.com")
    assert _is_placeholder_host("foo.bar.example.com")
    assert not _is_placeholder_host("node.tracegate.test")
    assert not _is_placeholder_host("198.51.100.23")


def test_resolve_node_public_host_skips_placeholder_fqdn_and_uses_default() -> None:
    host = _resolve_node_public_host(
        fqdn="transit.example.com",
        public_ipv4="198.51.100.23",
        default_host="node.tracegate.test",
    )

    assert host == "node.tracegate.test"


def test_resolve_node_public_host_uses_real_fqdn_when_present() -> None:
    host = _resolve_node_public_host(
        fqdn="entry.node.tracegate.test",
        public_ipv4="203.0.113.20",
        default_host="entry.node.tracegate.test",
    )

    assert host == "entry.node.tracegate.test"


def test_revision_sticky_host_is_stable_and_rotates_by_generation() -> None:
    connection_id = UUID("00000000-0000-0000-0000-000000000123")
    hosts = ["edge-a.tracegate.test", "edge-b.tracegate.test", "edge-c.tracegate.test"]

    first = _select_revision_sticky_host(
        hosts=hosts,
        fallback="fallback.tracegate.test",
        connection_id=connection_id,
        rotation_generation=0,
        role="entry",
    )
    repeated = _select_revision_sticky_host(
        hosts=hosts,
        fallback="fallback.tracegate.test",
        connection_id=connection_id,
        rotation_generation=0,
        role="entry",
    )
    next_generation = _select_revision_sticky_host(
        hosts=hosts,
        fallback="fallback.tracegate.test",
        connection_id=connection_id,
        rotation_generation=1,
        role="entry",
    )
    generations = {
        _select_revision_sticky_host(
            hosts=hosts,
            fallback="fallback.tracegate.test",
            connection_id=connection_id,
            rotation_generation=generation,
            role="entry",
        )
        for generation in range(12)
    }

    assert first == repeated
    assert first != next_generation
    assert generations == set(hosts)


def test_revision_sticky_host_ignores_placeholders_and_duplicates() -> None:
    selected = _select_revision_sticky_host(
        hosts=["entry.example.com", "edge.tracegate.test", "edge.tracegate.test"],
        fallback="fallback.tracegate.test",
        connection_id=UUID("00000000-0000-0000-0000-000000000456"),
        rotation_generation=4,
        role="entry",
    )

    assert selected == "edge.tracegate.test"


def test_resolve_sni_defaults_v1_reality_to_less_popular_pool_target() -> None:
    selected = asyncio.run(_resolve_sni(None, ConnectionProtocol.VLESS_REALITY, None, {}))  # type: ignore[arg-type]

    assert selected is not None
    assert selected.fqdn == "partners.lemanapro.ru"


def test_chain_endpoint_readiness_rejects_placeholder_entry_host() -> None:
    connection = SimpleNamespace(mode=ConnectionMode.CHAIN)
    endpoints = EndpointSet(transit_host="transit.tracegate.test", entry_host="entry.example.com")

    with pytest.raises(RevisionError, match="non-placeholder Entry host"):
        _ensure_chain_endpoint_ready(connection, endpoints)  # type: ignore[arg-type]


def test_chain_config_readiness_rejects_placeholder_entry_server() -> None:
    connection = SimpleNamespace(mode=ConnectionMode.CHAIN)

    with pytest.raises(RevisionError, match="config.server"):
        _ensure_chain_config_ready(  # type: ignore[arg-type]
            connection,
            {"server": "entry.example.com", "chain": {"entry": "entry.example.com"}},
        )


def test_chain_config_readiness_accepts_resolved_entry_server() -> None:
    connection = SimpleNamespace(mode=ConnectionMode.CHAIN)

    _ensure_chain_config_ready(  # type: ignore[arg-type]
        connection,
        {"server": "entry.tracegate.test", "chain": {"entry": "entry.tracegate.test"}},
    )
