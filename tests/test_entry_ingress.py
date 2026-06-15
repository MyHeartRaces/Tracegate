from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import yaml

from tracegate.services.revisions import _select_revision_sticky_shard_host


def test_revision_sticky_shard_alias_is_personal_and_rotates() -> None:
    settings = SimpleNamespace(api_internal_token="test-secret", grafana_cookie_secret="", pseudonym_secret="", entry_ingress_alias_token_length=20)
    shards = [
        {"id": "a", "hostnameTemplate": "{token}.a.tracegate.test", "state": "active"},
        {"id": "b", "hostnameTemplate": "{token}.b.tracegate.test", "state": "active"},
        {"id": "c", "hostnameTemplate": "{token}.c.tracegate.test", "state": "active"},
    ]
    connection_id = UUID("00000000-0000-0000-0000-000000000123")

    aliases = [
        _select_revision_sticky_shard_host(
            shards=shards,
            fallback="fallback.tracegate.test",
            connection_id=connection_id,
            rotation_generation=generation,
            settings=settings,
        )
        for generation in range(3)
    ]

    assert len(set(aliases)) == 3
    assert all(str(connection_id) not in alias for alias in aliases)
    assert {alias.rsplit(".", 3)[1] for alias in aliases} == {"a", "b", "c"}


def test_revision_sticky_shard_alias_excludes_draining_shard() -> None:
    settings = SimpleNamespace(api_internal_token="test-secret", grafana_cookie_secret="", pseudonym_secret="", entry_ingress_alias_token_length=20)
    shards = [
        {"id": "a", "hostnameTemplate": "{token}.a.tracegate.test", "state": "active"},
        {"id": "b", "hostnameTemplate": "{token}.b.tracegate.test", "state": "draining"},
        {"id": "c", "hostnameTemplate": "{token}.c.tracegate.test", "state": "active"},
    ]

    aliases = {
        _select_revision_sticky_shard_host(
            shards=shards,
            fallback="fallback.tracegate.test",
            connection_id=UUID("00000000-0000-0000-0000-000000000456"),
            rotation_generation=generation,
            settings=settings,
        )
        for generation in range(8)
    }

    assert all(".b.tracegate.test" not in alias for alias in aliases)


def test_entry_ingress_firewall_script_is_executable() -> None:
    path = Path("deploy/k3s/entry-ingress-firewall.py")

    assert path.stat().st_mode & 0o111
    assert "tracegate_entry_ingress" in path.read_text(encoding="utf-8")
    assert yaml.safe_load(Path("deploy/k3s/tracegate/values.yaml").read_text(encoding="utf-8"))["architecture"]["entryIngress"]["firewall"]["required"] is True


def test_endpoint_ingress_firewall_script_is_executable() -> None:
    path = Path("deploy/k3s/endpoint-ingress-firewall.py")

    assert path.stat().st_mode & 0o111
    assert "tracegate_endpoint_ingress" in path.read_text(encoding="utf-8")
    values = yaml.safe_load(Path("deploy/k3s/tracegate/values.yaml").read_text(encoding="utf-8"))
    assert values["architecture"]["endpointIngress"]["firewall"]["required"] is True
