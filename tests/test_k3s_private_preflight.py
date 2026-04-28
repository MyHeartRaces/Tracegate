from __future__ import annotations

from pathlib import Path

import pytest

from tracegate.cli.k3s_private_preflight import K3sPrivatePreflightError, main, validate_private_mount


PRIVATE_PREFLIGHT_SECRET_CANARIES = (
    "real-private-key",
    "real-hysteria-auth",
    "server-private-key",
    "mieru-secret",
    "ss2022-secret",
    "shadowtls-secret",
    "00112233445566778899aabbccddeeff",
    "TRACEGATE_ZAPRET_SCOPE=scoped-egress",
    "TRACEGATE_ZAPRET_NFQUEUE=false",
)


def _assert_no_private_canaries(text: str) -> None:
    for canary in PRIVATE_PREFLIGHT_SECRET_CANARIES:
        assert canary not in text


def _write(root: Path, rel_path: str, content: str) -> None:
    path = root / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def test_k3s_private_preflight_accepts_role_scoped_secret_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write(tmp_path, "reality/transit-private-key", "real-private-key\n")
    _write(tmp_path, "hysteria/transit-auth", "real-hysteria-auth\n")
    _write(tmp_path, "mieru/server.json", '{"profiles": [{"name": "entry-transit", "password": "mieru-secret"}]}\n')
    _write(
        tmp_path,
        "shadowsocks2022/transit-server.json",
        '{"server": "127.0.0.1", "server_port": 18443, "method": "2022-blake3-aes-128-gcm", "password": "ss2022-secret"}\n',
    )
    _write(
        tmp_path,
        "shadowtls/transit-config.yaml",
        "version: 3\nserverName: cdn.tracegate.test\npassword: shadowtls-secret\n",
    )
    _write(
        tmp_path,
        "wireguard/wg.conf",
        "\n".join(
            [
                "[Interface]",
                "PrivateKey = server-private-key",
                "Address = 10.7.0.1/24",
                "ListenPort = 51820",
                "",
            ]
        ),
    )
    _write(tmp_path, "mtproto/secret.txt", "00112233445566778899aabbccddeeff\n")
    _write(tmp_path, "zapret/transit.env", "TRACEGATE_ZAPRET_SCOPE=scoped-egress\n")
    _write(tmp_path, "zapret/entry-transit.env", "TRACEGATE_ZAPRET_NFQUEUE=false\n")

    main(
        [
            "--root",
            str(tmp_path),
            "--role",
            "TRANSIT",
            "--required-file",
            "reality/transit-private-key",
            "--required-file",
            "hysteria/transit-auth",
            "--required-file",
            "mieru/server.json",
            "--required-file",
            "shadowsocks2022/transit-server.json",
            "--required-file",
            "shadowtls/transit-config.yaml",
            "--required-file",
            "wireguard/wg.conf",
            "--required-file",
            "mtproto/secret.txt",
            "--zapret-file",
            "zapret/transit.env",
            "--zapret-file",
            "zapret/entry-transit.env",
        ]
    )

    out = capsys.readouterr().out
    assert "OK k3s private preflight role=TRANSIT" in out
    _assert_no_private_canaries(out)


def test_k3s_private_preflight_rejects_mieru_without_private_credentials(tmp_path: Path) -> None:
    _write(tmp_path, "mieru/server.json", '{"profiles": [{"name": "entry-transit"}]}\n')

    with pytest.raises(K3sPrivatePreflightError, match="credential material"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["mieru/server.json"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_mieru_anonymous_auth(tmp_path: Path) -> None:
    _write(tmp_path, "mieru/server.json", '{"profiles": [{"name": "entry-transit", "password": "secret", "auth": "none"}]}\n')

    with pytest.raises(K3sPrivatePreflightError, match="anonymous/no-auth"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["mieru/server.json"],
            zapret_files=[],
        )


def test_k3s_private_preflight_accepts_tuic_lab_config_without_0rtt(tmp_path: Path) -> None:
    _write(tmp_path, "lab/tuic-transit.json", '{"server": "0.0.0.0", "users": [{"uuid": "user-uuid", "password": "secret"}]}\n')

    report = validate_private_mount(
        root=tmp_path,
        role="TRANSIT",
        required_files=["lab/tuic-transit.json"],
        zapret_files=[],
    )

    assert report["requiredFiles"] == 1


def test_k3s_private_preflight_rejects_tuic_lab_0rtt(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "lab/tuic-transit.json",
        '{"users": [{"uuid": "user-uuid", "password": "secret"}], "zero_rtt_handshake": true}\n',
    )

    with pytest.raises(K3sPrivatePreflightError, match="0-RTT"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["lab/tuic-transit.json"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_tuic_lab_without_credentials(tmp_path: Path) -> None:
    _write(tmp_path, "lab/tuic-transit.json", '{"server": "0.0.0.0"}\n')

    with pytest.raises(K3sPrivatePreflightError, match="credential material"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["lab/tuic-transit.json"],
            zapret_files=[],
        )


def test_k3s_private_preflight_accepts_restls_lab_config_with_credentials(tmp_path: Path) -> None:
    _write(tmp_path, "lab/restls-direct.yaml", "server: transit.example.com\npassword: restls-secret\n")

    report = validate_private_mount(
        root=tmp_path,
        role="TRANSIT",
        required_files=["lab/restls-direct.yaml"],
        zapret_files=[],
    )

    assert report["requiredFiles"] == 1


def test_k3s_private_preflight_rejects_restls_lab_without_credentials(tmp_path: Path) -> None:
    _write(tmp_path, "lab/restls-direct.yaml", "server: transit.example.com\n")

    with pytest.raises(K3sPrivatePreflightError, match="credential material"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["lab/restls-direct.yaml"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_restls_insecure_tls(tmp_path: Path) -> None:
    _write(tmp_path, "lab/restls-direct.yaml", "server: transit.example.com\npassword: secret\nskip_cert_verify: true\n")

    with pytest.raises(K3sPrivatePreflightError, match="TLS verification"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["lab/restls-direct.yaml"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_wireguard_hooks(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "wireguard/wg.conf",
        "\n".join(
            [
                "[Interface]",
                "PrivateKey = server-private-key",
                "Address = 10.7.0.1/24",
                "PostUp = iptables -F",
                "",
            ]
        ),
    )

    with pytest.raises(K3sPrivatePreflightError, match="host-network side effects"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["wireguard/wg.conf"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_incomplete_wireguard_config(tmp_path: Path) -> None:
    _write(tmp_path, "wireguard/wg.conf", "[Interface]\nAddress = 10.7.0.1/24\n")

    with pytest.raises(K3sPrivatePreflightError, match="PrivateKey"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["wireguard/wg.conf"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_wireguard_default_route(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "wireguard/wg.conf",
        "\n".join(
            [
                "[Interface]",
                "PrivateKey = server-private-key",
                "Address = 10.7.0.1/24",
                "ListenPort = 51820",
                "",
                "[Peer]",
                "PublicKey = peer-public-key",
                "AllowedIPs = 0.0.0.0/0, ::/0",
                "",
            ]
        ),
    )

    with pytest.raises(K3sPrivatePreflightError, match="default or split-default routes"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["wireguard/wg.conf"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_wireguard_split_default_route(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "wireguard/wg.conf",
        "\n".join(
            [
                "[Interface]",
                "PrivateKey = server-private-key",
                "Address = 10.7.0.1/24",
                "ListenPort = 51820",
                "",
                "[Peer]",
                "PublicKey = peer-public-key",
                "AllowedIPs = 0.0.0.0/1, 128.0.0.0/1",
                "",
            ]
        ),
    )

    with pytest.raises(K3sPrivatePreflightError, match="default or split-default routes"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["wireguard/wg.conf"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_wireguard_dns_side_effect(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "wireguard/wg.conf",
        "\n".join(
            [
                "[Interface]",
                "PrivateKey = server-private-key",
                "Address = 10.7.0.1/24",
                "ListenPort = 51820",
                "DNS = 1.1.1.1",
                "",
            ]
        ),
    )

    with pytest.raises(K3sPrivatePreflightError, match="host-network side effects"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["wireguard/wg.conf"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_wireguard_unsafe_mtu(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "wireguard/wg.conf",
        "\n".join(
            [
                "[Interface]",
                "PrivateKey = server-private-key",
                "Address = 10.7.0.1/24",
                "ListenPort = 51820",
                "MTU = 1500",
                "",
                "[Peer]",
                "PublicKey = peer-public-key",
                "AllowedIPs = 10.7.0.2/32",
                "PersistentKeepalive = 90",
                "",
            ]
        ),
    )

    with pytest.raises(K3sPrivatePreflightError, match="MTU"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["wireguard/wg.conf"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_wireguard_unsafe_keepalive(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "wireguard/wg.conf",
        "\n".join(
            [
                "[Interface]",
                "PrivateKey = server-private-key",
                "Address = 10.7.0.1/24",
                "ListenPort = 51820",
                "MTU = 1280",
                "",
                "[Peer]",
                "PublicKey = peer-public-key",
                "AllowedIPs = 10.7.0.2/32",
                "PersistentKeepalive = 90",
                "",
            ]
        ),
    )

    with pytest.raises(K3sPrivatePreflightError, match="PersistentKeepalive"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["wireguard/wg.conf"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_legacy_shadowsocks_config(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "shadowsocks2022/server.json",
        '{"server": "127.0.0.1", "server_port": 18443, "method": "chacha20-ietf-poly1305", "password": "secret"}\n',
    )

    with pytest.raises(K3sPrivatePreflightError, match="2022-"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["shadowsocks2022/server.json"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_shadowsocks2022_without_secret(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "shadowsocks2022/server.json",
        '{"server": "127.0.0.1", "server_port": 18443, "method": "2022-blake3-aes-128-gcm"}\n',
    )

    with pytest.raises(K3sPrivatePreflightError, match="key/password"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["shadowsocks2022/server.json"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_shadowtls_v2_config(tmp_path: Path) -> None:
    _write(tmp_path, "shadowtls/config.yaml", "version: 2\npassword: shadowtls-secret\n")

    with pytest.raises(K3sPrivatePreflightError, match="version 3"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["shadowtls/config.yaml"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_shadowtls_without_password(tmp_path: Path) -> None:
    _write(tmp_path, "shadowtls/config.yaml", "version: 3\nserverName: cdn.tracegate.test\n")

    with pytest.raises(K3sPrivatePreflightError, match="password"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["shadowtls/config.yaml"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_weak_mtproto_secret(tmp_path: Path) -> None:
    _write(tmp_path, "mtproto/secret.txt", "short-secret\n")

    with pytest.raises(K3sPrivatePreflightError, match="raw 32-hex-character"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["mtproto/secret.txt"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_mtproto_client_secret(tmp_path: Path) -> None:
    _write(tmp_path, "mtproto/secret.txt", "ee00112233445566778899aabbccddeeff\n")

    with pytest.raises(K3sPrivatePreflightError, match="raw 32-hex-character"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["mtproto/secret.txt"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_multiple_mtproto_secrets(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "mtproto/secret.txt",
        "00112233445566778899aabbccddeeff\nffeeddccbbaa99887766554433221100\n",
    )

    with pytest.raises(K3sPrivatePreflightError, match="exactly one"):
        validate_private_mount(
            root=tmp_path,
            role="TRANSIT",
            required_files=["mtproto/secret.txt"],
            zapret_files=[],
        )


def test_k3s_private_preflight_accepts_mtproto_inline_comment(tmp_path: Path) -> None:
    _write(tmp_path, "mtproto/secret.txt", "00112233445566778899aabbccddeeff # raw server secret\n")

    report = validate_private_mount(
        root=tmp_path,
        role="TRANSIT",
        required_files=["mtproto/secret.txt"],
        zapret_files=[],
    )

    assert report["requiredFiles"] == 1


def test_k3s_private_preflight_rejects_missing_required_file(tmp_path: Path) -> None:
    with pytest.raises(K3sPrivatePreflightError, match="private file is missing"):
        validate_private_mount(
            root=tmp_path,
            role="ENTRY",
            required_files=["reality/entry-private-key"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_placeholders(tmp_path: Path) -> None:
    _write(tmp_path, "reality/entry-private-key", "REPLACE_ENTRY_PLACEHOLDER_PRIVATE_KEY\n")

    with pytest.raises(K3sPrivatePreflightError, match="placeholder"):
        validate_private_mount(
            root=tmp_path,
            role="ENTRY",
            required_files=["reality/entry-private-key"],
            zapret_files=[],
        )


def test_k3s_private_preflight_rejects_world_accessible_private_files(tmp_path: Path) -> None:
    _write(tmp_path, "reality/entry-private-key", "real-private-key\n")
    (tmp_path / "reality/entry-private-key").chmod(0o604)

    with pytest.raises(K3sPrivatePreflightError, match="world permissions"):
        validate_private_mount(
            root=tmp_path,
            role="ENTRY",
            required_files=["reality/entry-private-key"],
            zapret_files=[],
        )


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("TRACEGATE_ZAPRET_SCOPE=host-wide\n", "host-wide scope"),
        ("TRACEGATE_ZAPRET_HOST_WIDE_INTERCEPTION=true\n", "host-wide interception"),
        ("TRACEGATE_ZAPRET_TARGET_SURFACES=all\n", "broad host traffic"),
        ("TRACEGATE_ZAPRET_APPLY_TO=vless_reality,all\n", "broad host traffic"),
        ("TRACEGATE_ZAPRET_APPLY_MODE=all-flows\n", "broad host traffic"),
        ("TRACEGATE_ZAPRET_NFQUEUE=1\n", "broad NFQUEUE"),
    ],
)
def test_k3s_private_preflight_rejects_hostwide_and_nfqueue_zapret(tmp_path: Path, content: str, message: str) -> None:
    _write(tmp_path, "zapret/entry-transit.env", content)

    with pytest.raises(K3sPrivatePreflightError, match=message):
        validate_private_mount(
            root=tmp_path,
            role="ENTRY",
            required_files=[],
            zapret_files=["zapret/entry-transit.env"],
        )


def test_k3s_private_preflight_rejects_path_escape(tmp_path: Path) -> None:
    with pytest.raises(K3sPrivatePreflightError, match="under private root"):
        validate_private_mount(
            root=tmp_path,
            role="ENTRY",
            required_files=["/etc/passwd"],
            zapret_files=[],
        )
