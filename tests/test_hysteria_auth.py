import json

from tracegate.agent.hysteria_auth import authenticate_hysteria_userpass, build_hysteria_auth_db
from tracegate.settings import Settings


def test_authenticate_hysteria_userpass_accepts_alias_and_returns_canonical_id(tmp_path) -> None:
    settings = Settings(agent_data_root=str(tmp_path))
    auth_db = build_hysteria_auth_db(
        static_userpass={"bootstrap": "bootstrap-pass"},
        artifacts=[
            {
                "user_id": "123456789",
                "connection_id": "11111111-2222-4333-8444-555555555555",
                "variant": "B3",
                "protocol": "hysteria2",
                "config": {
                    "auth": {
                        "type": "userpass",
                        "username": "b3_123456789_11111111222243338444555555555555",
                        "password": "dev-pass",
                    }
                },
            }
        ],
    )
    auth_path = tmp_path / "runtime/hysteria/auth.json"
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    auth_path.write_text(json.dumps(auth_db, ensure_ascii=True, indent=2), encoding="utf-8")

    ok_legacy, client_id_legacy = authenticate_hysteria_userpass(
        settings,
        "B3 - 123456789 - 11111111-2222-4333-8444-555555555555:dev-pass",
    )
    ok_ios, client_id_ios = authenticate_hysteria_userpass(
        settings,
        "b3_123456789_11111111222243338444555555555555:dev-pass",
    )
    ok_bootstrap, client_id_bootstrap = authenticate_hysteria_userpass(settings, "bootstrap:bootstrap-pass")

    assert ok_legacy is True
    assert ok_ios is True
    assert ok_bootstrap is True
    assert client_id_legacy == "B3 - 123456789 - 11111111-2222-4333-8444-555555555555"
    assert client_id_ios == client_id_legacy
    assert client_id_bootstrap == "bootstrap"


def test_authenticate_hysteria_userpass_rejects_invalid_credentials(tmp_path) -> None:
    settings = Settings(agent_data_root=str(tmp_path))
    auth_path = tmp_path / "runtime/hysteria/auth.json"
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    auth_path.write_text(
        json.dumps({"bootstrap": {"password": "bootstrap-pass", "id": "bootstrap"}}, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )

    assert authenticate_hysteria_userpass(settings, "bootstrap:wrong") == (False, None)
    assert authenticate_hysteria_userpass(settings, "missing:bootstrap-pass") == (False, None)
    assert authenticate_hysteria_userpass(settings, "broken-payload") == (False, None)
