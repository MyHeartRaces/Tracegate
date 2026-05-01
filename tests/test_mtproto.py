import json

import pytest

from tracegate.services.mtproto import (
    MTProtoConfigError,
    build_mtproto_client_secret,
    build_mtproto_official_proxy_command,
    build_mtproto_share_links,
    load_mtproto_issued_secret_hexes,
    load_mtproto_server_secret,
    normalize_mtproto_domain,
    resolve_mtproto_client_secret,
)


def test_build_mtproto_client_secret_for_tls_transport() -> None:
    value = build_mtproto_client_secret(
        "95f0d81f7539ecbe1bd880f48b6a739a",
        transport="tls",
        domain="proxied.tracegate.test",
    )

    assert value == "ee95f0d81f7539ecbe1bd880f48b6a739a70726f786965642e7472616365676174652e74657374"


def test_build_mtproto_client_secret_for_random_padding() -> None:
    value = build_mtproto_client_secret(
        "95f0d81f7539ecbe1bd880f48b6a739a",
        transport="random_padding",
    )

    assert value == "dd95f0d81f7539ecbe1bd880f48b6a739a"


def test_resolve_mtproto_client_secret_accepts_prebuilt_tls_secret() -> None:
    prebuilt = "ee95f0d81f7539ecbe1bd880f48b6a739a70726f786965642e7472616365676174652e74657374"
    assert resolve_mtproto_client_secret(prebuilt) == prebuilt


def test_build_mtproto_share_links_produces_tg_and_https_variants() -> None:
    links = build_mtproto_share_links(
        server="proxied.tracegate.test",
        port=443,
        secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
        transport="tls",
        domain="proxied.tracegate.test",
    )

    assert links.client_secret_hex.startswith("ee95f0d81f7539ecbe1bd880f48b6a739a")
    assert links.tg_uri.startswith("tg://proxy?server=proxied.tracegate.test&port=443&secret=ee95f0")
    assert links.https_url.startswith("https://t.me/proxy?server=proxied.tracegate.test&port=443&secret=ee95f0")


def test_normalize_mtproto_domain_converts_idna() -> None:
    assert normalize_mtproto_domain("тест.example") == "xn--e1aybc.example"


def test_build_mtproto_client_secret_rejects_invalid_hex() -> None:
    with pytest.raises(MTProtoConfigError, match="even number of hex"):
        build_mtproto_client_secret("abc", transport="raw")


def test_load_mtproto_server_secret_reads_16_byte_hex(tmp_path) -> None:
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("95f0d81f7539ecbe1bd880f48b6a739a\n", encoding="utf-8")

    assert load_mtproto_server_secret(secret_file) == "95f0d81f7539ecbe1bd880f48b6a739a"


def test_load_mtproto_issued_secret_hexes_filters_invalid_rows(tmp_path) -> None:
    issued_state_file = tmp_path / "issued.json"
    issued_state_file.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "telegramId": 101,
                        "secretHex": "00112233445566778899aabbccddeeff",
                        "issuedAt": "2026-04-15T02:10:00Z",
                    },
                    {
                        "telegramId": 102,
                        "secretHex": "00112233445566778899aabbccddeeff",
                        "issuedAt": "2026-04-15T02:11:00Z",
                    },
                    {
                        "telegramId": 0,
                        "secretHex": "11112222333344445555666677778888",
                        "issuedAt": "2026-04-15T02:12:00Z",
                    },
                    {
                        "telegramId": 103,
                        "secretHex": "short",
                        "issuedAt": "2026-04-15T02:13:00Z",
                    },
                ],
            },
            ensure_ascii=True,
            indent=2,
        ),
        encoding="utf-8",
    )

    secrets = load_mtproto_issued_secret_hexes(issued_state_file)

    assert secrets == ("00112233445566778899aabbccddeeff",)


def test_build_mtproto_official_proxy_command_accepts_primary_and_issued_secrets() -> None:
    command = build_mtproto_official_proxy_command(
        binary="/opt/MTProxy/objs/bin/mtproto-proxy",
        run_as_user="nobody",
        stats_port=9888,
        listen_port=9443,
        bind_address="127.0.0.1",
        nat_info="127.0.0.1:203.0.113.10",
        primary_secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
        issued_secret_hexes=(
            "fedcba98765432100123456789abcdef",
            "95f0d81f7539ecbe1bd880f48b6a739a",
        ),
        proxy_secret_file="/var/lib/tracegate/private/mtproto/runtime/proxy-secret",
        proxy_config_file="/var/lib/tracegate/private/mtproto/runtime/proxy-multi.conf",
        workers=1,
        proxy_tag="tg-tag",
        tls_mode="private-fronting",
        domain="proxied.tracegate.test",
    )

    assert command.accepted_secret_hexes == (
        "95f0d81f7539ecbe1bd880f48b6a739a",
        "fedcba98765432100123456789abcdef",
    )
    assert command.argv[:7] == (
        "/opt/MTProxy/objs/bin/mtproto-proxy",
        "-u",
        "nobody",
        "-p",
        "9888",
        "-H",
        "9443",
    )
    assert "--domain" in command.argv
    assert "proxied.tracegate.test" in command.argv
    assert "--address" in command.argv
    assert "127.0.0.1" in command.argv
    assert "--nat-info" in command.argv
    assert "127.0.0.1:203.0.113.10" in command.argv
    assert "--aes-pwd" in command.argv
    assert "-P" in command.argv


def test_build_mtproto_official_proxy_command_rejects_invalid_nat_info() -> None:
    with pytest.raises(MTProtoConfigError, match="nat_info"):
        build_mtproto_official_proxy_command(
            binary="/opt/MTProxy/objs/bin/mtproto-proxy",
            run_as_user="nobody",
            stats_port=9888,
            listen_port=9443,
            bind_address="127.0.0.1",
            nat_info="missing-global-address",
            primary_secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
            proxy_secret_file="/var/lib/tracegate/private/mtproto/runtime/proxy-secret",
            proxy_config_file="/var/lib/tracegate/private/mtproto/runtime/proxy-multi.conf",
            workers=1,
            tls_mode="private-fronting",
            domain="proxied.tracegate.test",
        )


def test_build_mtproto_official_proxy_command_allows_zero_workers() -> None:
    command = build_mtproto_official_proxy_command(
        binary="/opt/MTProxy/objs/bin/mtproto-proxy",
        run_as_user="nobody",
        stats_port=9888,
        listen_port=9443,
        primary_secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
        proxy_secret_file="/var/lib/tracegate/private/mtproto/runtime/proxy-secret",
        proxy_config_file="/var/lib/tracegate/private/mtproto/runtime/proxy-multi.conf",
        workers=0,
        tls_mode="private-fronting",
        domain="proxied.tracegate.test",
    )

    assert "-M" not in command.argv
