import asyncio

from tracegate.enums import ConnectionProtocol
from tracegate.services.revisions import _is_placeholder_host, _resolve_node_public_host, _resolve_sni


def test_is_placeholder_host_detects_example_domain_variants() -> None:
    assert _is_placeholder_host("example.com")
    assert _is_placeholder_host("transit.example.com")
    assert _is_placeholder_host("foo.bar.example.com")
    assert not _is_placeholder_host("myheartraces.space")
    assert not _is_placeholder_host("46.226.165.23")


def test_resolve_node_public_host_skips_placeholder_fqdn_and_uses_default() -> None:
    host = _resolve_node_public_host(
        fqdn="transit.example.com",
        public_ipv4="46.226.165.23",
        default_host="myheartraces.space",
    )

    assert host == "myheartraces.space"


def test_resolve_node_public_host_uses_real_fqdn_when_present() -> None:
    host = _resolve_node_public_host(
        fqdn="entry.myheartraces.space",
        public_ipv4="203.0.113.20",
        default_host="entry.myheartraces.space",
    )

    assert host == "entry.myheartraces.space"


def test_resolve_sni_defaults_v1_reality_to_yandex() -> None:
    selected = asyncio.run(_resolve_sni(None, ConnectionProtocol.VLESS_REALITY, None, {}))  # type: ignore[arg-type]

    assert selected is not None
    assert selected.fqdn == "yandex.ru"
