import json

import pytest

from tracegate.services.mtproto import (
    MTProtoIssuedSecret,
    MTProtoConfigError,
    build_mtproto_client_secret,
    build_mtproto_mtg_config,
    build_mtproto_official_proxy_command,
    build_mtproto_share_links,
    build_mtproto_telemt_config,
    load_mtproto_issued_secret_entries,
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


def test_build_mtproto_share_links_supports_dd_without_tls_domain() -> None:
    links = build_mtproto_share_links(
        server="mtproto.example.org",
        port=443,
        secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
        transport="dd",
    )

    assert links.client_secret_hex == "dd95f0d81f7539ecbe1bd880f48b6a739a"
    assert "server=mtproto.example.org" in links.tg_uri
    assert "secret=dd95f0d81f7539ecbe1bd880f48b6a739a" in links.https_url


def test_build_mtproto_share_links_supports_raw_secret_without_tls_domain() -> None:
    links = build_mtproto_share_links(
        server="mtproto.example.org",
        port=443,
        secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
        transport="raw",
    )

    assert links.client_secret_hex == "95f0d81f7539ecbe1bd880f48b6a739a"
    assert "server=mtproto.example.org" in links.tg_uri
    assert "secret=95f0d81f7539ecbe1bd880f48b6a739a" in links.https_url


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


def test_load_mtproto_issued_secret_entries_preserves_telegram_id(tmp_path) -> None:
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
                    }
                ],
            },
            ensure_ascii=True,
        ),
        encoding="utf-8",
    )

    entries = load_mtproto_issued_secret_entries(issued_state_file)

    assert entries == (MTProtoIssuedSecret(telegram_id=101, secret_hex="00112233445566778899aabbccddeeff"),)


def test_build_mtproto_mtg_config_is_fail_closed_through_socks5() -> None:
    config = build_mtproto_mtg_config(
        listen_port=9443,
        tls_domain="tracegate.test",
        primary_secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
        socks5_proxy="socks5://127.0.0.1:11084",
        domain_fronting_host="tracegate.test",
    )

    assert config.client_secret_hex.startswith("ee95f0d81f7539ecbe1bd880f48b6a739a")
    assert 'bind-to = "127.0.0.1:9443"' in config.config_text
    assert "proxy-protocol-listener = true" in config.config_text
    assert 'host = "tracegate.test"' in config.config_text
    assert 'proxies = ["socks5://127.0.0.1:11084"]' in config.config_text
    assert 'tolerate-time-skewness = "5m"' in config.config_text
    assert "domain-fronting-ip" not in config.config_text
    assert 'proxies = [""]' not in config.config_text
    assert "[defense.anti-replay]" in config.config_text


def test_build_mtproto_mtg_config_pins_legacy_and_current_fronting_ip() -> None:
    config = build_mtproto_mtg_config(
        listen_port=9443,
        tls_domain="front-g.example.net",
        primary_secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
        socks5_proxy="socks5://127.0.0.1:11084",
        domain_fronting_host="192.0.2.12",
    )

    assert 'domain-fronting-ip = "192.0.2.12"' in config.config_text
    assert 'host = "192.0.2.12"' in config.config_text


def test_build_mtproto_mtg_config_allows_endpoint_direct_egress() -> None:
    config = build_mtproto_mtg_config(
        listen_port=9443,
        tls_domain="tracegate.test",
        primary_secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
        domain_fronting_host="tracegate.test",
    )

    assert 'bind-to = "127.0.0.1:9443"' in config.config_text
    assert "proxies =" not in config.config_text
    assert "[network.timeout]" in config.config_text


def test_build_mtproto_mtg_config_rejects_raw_transport() -> None:
    with pytest.raises(MTProtoConfigError, match="MTG runtime requires TLS/FakeTLS"):
        build_mtproto_mtg_config(
            listen_port=9443,
            tls_domain="",
            primary_secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
            transport="raw",
        )


def test_build_mtproto_mtg_config_rejects_invalid_proxy_scheme() -> None:
    with pytest.raises(MTProtoConfigError, match="socks5"):
        build_mtproto_mtg_config(
            listen_port=9443,
            tls_domain="tracegate.test",
            primary_secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
            socks5_proxy="http://127.0.0.1:11084",
            domain_fronting_host="tracegate.test",
        )


def test_build_mtproto_telemt_config_enables_faketls_masking_and_per_user_secrets() -> None:
    config = build_mtproto_telemt_config(
        listen_port=9443,
        tls_domain="2gis.ru",
        primary_secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
        issued_secrets=[
            MTProtoIssuedSecret(telegram_id=101, secret_hex="00112233445566778899aabbccddeeff"),
            MTProtoIssuedSecret(telegram_id=102, secret_hex="fedcba98765432100123456789abcdef"),
        ],
        mask_host="2gis.ru",
        public_host="proxy.example.org",
    )

    assert config.client_secret_hex.startswith("ee95f0d81f7539ecbe1bd880f48b6a739a")
    assert '[general.modes]' in config.config_text
    assert 'tls = true' in config.config_text
    assert 'listen_addr_ipv4 = "127.0.0.1"' in config.config_text
    assert 'proxy_protocol = true' in config.config_text
    assert 'proxy_protocol_trusted_cidrs = ["127.0.0.1/32", "::1/128"]' in config.config_text
    assert 'tls_domain = "2gis.ru"' in config.config_text
    assert 'mask_host = "2gis.ru"' in config.config_text
    assert 'tls_emulation = true' in config.config_text
    assert '"bootstrap" = "95f0d81f7539ecbe1bd880f48b6a739a"' in config.config_text
    assert '"tg_101" = "00112233445566778899aabbccddeeff"' in config.config_text
    assert '"tg_102" = "fedcba98765432100123456789abcdef"' in config.config_text


def test_build_mtproto_telemt_config_is_fail_closed_through_socks5() -> None:
    config = build_mtproto_telemt_config(
        listen_port=9443,
        tls_domain="tracegate.test",
        primary_secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
        socks5_proxy="socks5://127.0.0.1:11084",
        mask_host="tracegate.test",
    )

    assert config.client_secret_hex.startswith("ee95f0d81f7539ecbe1bd880f48b6a739a")
    assert "use_middle_proxy = false" in config.config_text
    assert "[[upstreams]]" in config.config_text
    assert 'type = "socks5"' in config.config_text
    assert 'address = "127.0.0.1:11084"' in config.config_text
    assert "enabled = true" in config.config_text


def test_build_mtproto_telemt_config_rejects_invalid_proxy_scheme() -> None:
    with pytest.raises(MTProtoConfigError, match="socks5"):
        build_mtproto_telemt_config(
            listen_port=9443,
            tls_domain="tracegate.test",
            primary_secret_hex="95f0d81f7539ecbe1bd880f48b6a739a",
            socks5_proxy="http://127.0.0.1:11084",
            mask_host="tracegate.test",
        )


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
