from tracegate.agent.hysteria_clients import build_hysteria_xray_clients


def test_build_hysteria_xray_clients_derives_token_from_userpass_auth() -> None:
    clients = build_hysteria_xray_clients(
        [
            {
                "user_id": "123456789",
                "connection_id": "11111111-2222-4333-8444-555555555555",
                "variant": "V3",
                "protocol": "hysteria2",
                "config": {
                    "auth": {
                        "type": "userpass",
                        "username": "v3_123456789_11111111222243338444555555555555",
                        "password": "dev-pass",
                    }
                },
            }
        ]
    )

    assert clients == [
        {
            "auth": "v3_123456789_11111111222243338444555555555555:dev-pass",
            "email": "V3 - 123456789 - 11111111-2222-4333-8444-555555555555",
        }
    ]


def test_build_hysteria_xray_clients_uses_explicit_token_for_token_mode() -> None:
    clients = build_hysteria_xray_clients(
        [
            {
                "user_id": "42",
                "connection_id": "c2",
                "variant": "V4",
                "protocol": "hysteria2",
                "config": {
                    "auth": {
                        "type": "token",
                        "token": "issued-token",
                        "client_id": "v4_42_c2",
                    }
                },
            }
        ]
    )

    assert clients == [{"auth": "issued-token", "email": "V4 - 42 - c2"}]
