from tracegate.agent import xray_api


def test_build_shadowsocks2022_user_uses_xray_account_type() -> None:
    user = xray_api._build_shadowsocks2022_user(email="V3 - 1 - conn", key="user-key")

    assert user.email == "V3 - 1 - conn"
    assert user.account.type == "xray.proxy.shadowsocks_2022.Account"
    assert user.account.value == b"\x0a\x08user-key"

