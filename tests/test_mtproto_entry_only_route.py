"""Telegram Proxy: delivered only through Entry on TCP/443; no Endpoint backup route."""

from __future__ import annotations

import json
from pathlib import Path

from tracegate.bot import main as bot_main
from tracegate.services.mtproto_access import issue_mtproto_access_profile
from tracegate.services.private_handoffs import _write_mtproto_state
from tracegate.services.runtime_preflight import validate_runtime_contract_single
from tracegate.settings import Settings

_SECRET = "00112233445566778899aabbccddeeff"


def _settings(tmp_path: Path, **overrides) -> Settings:
    secret_file = tmp_path / "secrets" / "mtproto.txt"
    secret_file.parent.mkdir(parents=True, exist_ok=True)
    secret_file.write_text(_SECRET, encoding="utf-8")
    values = {
        "agent_data_root": str(tmp_path / "agent"),
        "agent_role": "TRANSIT",
        "private_runtime_root": str(tmp_path / "private"),
        "mtproto_domain": "proxied.tracegate.test",
        "private_mtproto_secret_file": str(secret_file),
    }
    values.update(overrides)
    return Settings(**values)


def _tunnel_settings(tmp_path: Path, **overrides) -> Settings:
    values = {
        "mtproto_route_mode": "entry-endpoint-tunnel",
        "private_mtproto_runtime": "telemt",
        "mtproto_direct_backup_host": "backup.tracegate.test",
        "mtproto_link_trusted_cidrs": "192.0.2.10/32",
    }
    values.update(overrides)
    return _settings(tmp_path, **values)


def _public_profile(settings: Settings) -> dict:
    _write_mtproto_state(settings, runtime_contract_payload={"role": "TRANSIT"})
    path = Path(settings.private_runtime_root) / "mtproto" / "public-profile.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_tunnel_profile_delivers_only_the_entry_route_on_443(tmp_path: Path) -> None:
    payload = _public_profile(_tunnel_settings(tmp_path))

    assert payload["publicPorts"] == [443]
    assert "altPublicPorts" not in payload
    assert payload["routes"] == [
        {
            "id": "entry",
            "label": "Через Entry (основной)",
            "server": "proxied.tracegate.test",
            "port": 443,
            "primary": True,
        }
    ]
    assert "backup.tracegate.test" not in json.dumps(payload)


def test_issued_links_contain_only_entry_443(tmp_path: Path) -> None:
    settings = _tunnel_settings(tmp_path)
    _public_profile(settings)

    profile, *_ = issue_mtproto_access_profile(settings, telegram_id=42)

    assert "links" not in profile
    assert (profile["server"], profile["port"]) == ("proxied.tracegate.test", 443)
    assert "port=443" in profile["tgUri"]
    assert "backup.tracegate.test" not in json.dumps(profile)
    assert "8443" not in json.dumps(profile)


def test_tunnel_without_backup_host_is_unchanged(tmp_path: Path) -> None:
    payload = _public_profile(_tunnel_settings(tmp_path, mtproto_direct_backup_host=""))
    assert payload["publicPorts"] == [443]
    assert "routes" not in payload


def test_non_tunnel_profile_is_unchanged(tmp_path: Path) -> None:
    payload = _public_profile(_settings(tmp_path))
    assert payload["publicPorts"] == [443]
    assert "routes" not in payload


def test_mtproto_fallback_mode_profile_is_unchanged(tmp_path: Path) -> None:
    payload = _public_profile(_settings(tmp_path, mtproto_public_port=8443))
    assert payload["publicPorts"] == [8443, 443]
    assert "altPublicPorts" not in payload


def test_new_grants_use_faketls_ee_secrets_by_default(tmp_path: Path) -> None:
    # With default settings (mtproto_transport="tls") the public profile and
    # every per-user grant are FakeTLS (ee + 16-byte secret + hex SNI domain).
    settings = _tunnel_settings(tmp_path)
    assert settings.mtproto_transport == "tls"
    payload = _public_profile(settings)
    assert payload["transport"] == "tls"
    assert payload["clientSecretHex"].startswith("ee")

    profile, *_ = issue_mtproto_access_profile(settings, telegram_id=99)

    domain_hex = "proxied.tracegate.test".encode("ascii").hex()
    assert profile["clientSecretHex"].startswith("ee")
    assert profile["clientSecretHex"].endswith(domain_hex)
    assert len(profile["clientSecretHex"]) == 2 + 32 + len(domain_hex)
    assert "secret=ee" in profile["httpsUrl"]


def test_entry_tunnel_contract_keeps_tcp_8443_forbidden(tmp_path: Path) -> None:
    from tracegate.agent.reconcile import reconcile_all

    settings = Settings(
        agent_data_root=str(tmp_path),
        agent_runtime_mode="systemd",
        agent_role="ENTRY",
        agent_runtime_profile="tracegate-3",
        default_entry_host="entry.tracegate.test",
        default_transit_host="endpoint.tracegate.test",
        mtproto_domain="proxied.tracegate.test",
        mtproto_route_mode="entry-endpoint-tunnel",
    )
    reconcile_all(settings)
    contract = json.loads((tmp_path / "runtime" / "runtime-contract.json").read_text(encoding="utf-8"))

    assert "mtprotoAltPublicPort" not in contract["fronting"]
    findings = [
        row
        for row in validate_runtime_contract_single(contract, expected_role="ENTRY")
        if "8443" in row.code or "tcp8443" in row.code
    ]
    assert findings == []


def test_bot_link_message_adds_update_hint_after_links() -> None:
    text = bot_main._format_mtproto_link_message(
        {
            "httpsUrl": "https://t.me/proxy?server=proxied.tracegate.test&port=443&secret=ee0011",
            "tgUri": "tg://proxy?server=proxied.tracegate.test&port=443&secret=ee0011",
            "server": "proxied.tracegate.test",
            "port": 443,
        }
    )

    assert text.splitlines()[-1] == bot_main.MTPROTO_UPDATE_TELEGRAM_HINT
    assert "Обновите Telegram до последней версии" in text
    assert text.index("port=443") < text.index(bot_main.MTPROTO_UPDATE_TELEGRAM_HINT)
