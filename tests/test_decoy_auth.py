import json

import pytest

from tracegate.services.decoy_auth import (
    build_decoy_session_cookie,
    DecoyAuthConfigError,
    decoy_auth_is_configured,
    load_decoy_session,
    load_github_repo_frame_html,
    load_mtproto_public_profile,
    sanitize_github_repo_html,
    verify_decoy_credentials,
)
from tracegate.settings import Settings


def test_decoy_auth_config_requires_login_and_password() -> None:
    assert decoy_auth_is_configured(Settings(transit_decoy_auth_login="", transit_decoy_auth_password="secret")) is False
    assert decoy_auth_is_configured(Settings(transit_decoy_auth_login="operator", transit_decoy_auth_password="")) is False
    assert decoy_auth_is_configured(Settings(transit_decoy_auth_login="operator", transit_decoy_auth_password="secret")) is True


def test_verify_decoy_credentials_uses_exact_match() -> None:
    settings = Settings(transit_decoy_auth_login="operator", transit_decoy_auth_password="secret-pass")

    assert verify_decoy_credentials(settings, login="operator", password="secret-pass") is True
    assert verify_decoy_credentials(settings, login="operator ", password="secret-pass") is True
    assert verify_decoy_credentials(settings, login="operator", password="wrong") is False
    assert verify_decoy_credentials(settings, login="wrong", password="secret-pass") is False


def test_decoy_session_cookie_roundtrip() -> None:
    settings = Settings(
        transit_decoy_auth_login="vault-operator",
        transit_decoy_auth_password="vault-passphrase",
        api_internal_token="internal-secret",
    )
    cookie = build_decoy_session_cookie(settings)
    payload = load_decoy_session(settings, cookie)

    assert payload is not None
    assert payload["login"] == "vault-operator"
    assert int(payload["exp"]) > 0


def test_decoy_session_cookie_rejects_other_login() -> None:
    source = Settings(
        transit_decoy_auth_login="vault-operator",
        transit_decoy_auth_password="vault-passphrase",
        api_internal_token="internal-secret",
    )
    target = Settings(
        transit_decoy_auth_login="Other",
        transit_decoy_auth_password="vault-passphrase",
        api_internal_token="internal-secret",
    )
    cookie = build_decoy_session_cookie(source)
    assert load_decoy_session(target, cookie) is None


def test_load_mtproto_public_profile_returns_sanitized_payload(tmp_path) -> None:
    profile_path = tmp_path / "public-profile.json"
    profile_path.write_text(
        json.dumps(
            {
                "protocol": "mtproto",
                "server": "proxied.tracegate.test",
                "port": 443,
                "transport": "tls",
                "domain": "proxied.tracegate.test",
                "secret": "00112233445566778899aabbccddeeff",
                "clientSecretHex": "ee00112233445566778899aabbccddeeff70726f786965642e7472616365676174652e7375",
                "tgUri": "tg://proxy?server=proxied.tracegate.test&port=443&secret=ee0011",
                "httpsUrl": "https://t.me/proxy?server=proxied.tracegate.test&port=443&secret=ee0011",
            },
            ensure_ascii=True,
            indent=2,
        ),
        encoding="utf-8",
    )

    settings = Settings(mtproto_public_profile_file=str(profile_path))
    profile = load_mtproto_public_profile(settings)

    assert profile == {
        "protocol": "mtproto",
        "server": "proxied.tracegate.test",
        "port": 443,
        "transport": "tls",
        "profile": "MTProto-FakeTLS-Direct",
        "domain": "proxied.tracegate.test",
        "clientSecretHex": "ee00112233445566778899aabbccddeeff70726f786965642e7472616365676174652e7375",
        "tgUri": "tg://proxy?server=proxied.tracegate.test&port=443&secret=ee0011",
        "httpsUrl": "https://t.me/proxy?server=proxied.tracegate.test&port=443&secret=ee0011",
    }
    assert "secret" not in profile


def test_load_mtproto_public_profile_rejects_invalid_payload(tmp_path) -> None:
    profile_path = tmp_path / "public-profile.json"
    profile_path.write_text(
        json.dumps({"protocol": "mtproto", "server": "proxied.tracegate.test", "port": 443}, ensure_ascii=True),
        encoding="utf-8",
    )
    settings = Settings(mtproto_public_profile_file=str(profile_path))

    with pytest.raises(DecoyAuthConfigError):
        load_mtproto_public_profile(settings)


def test_sanitize_github_repo_html_injects_base_and_click_script() -> None:
    html = sanitize_github_repo_html(
        "<html data-color-mode=\"auto\" data-dark-theme=\"dark\"><head><script>alert(1)</script></head><body><a href=\"/MyHeartRaces/Tracegate\">repo</a></body></html>",
        repo_url="https://github.com/MyHeartRaces/Tracegate",
    )

    assert "<base href=\"https://github.com/\" />" in html
    assert "window.top.location.href" in html
    assert "alert(1)" not in html
    assert "color-scheme:light" in html
    assert 'data-color-mode="light"' in html
    assert 'data-dark-theme="light"' in html


@pytest.mark.asyncio
async def test_load_github_repo_frame_html_uses_cache(monkeypatch) -> None:
    calls = []

    class _Response:
        text = "<html><head></head><body><div>Tracegate</div></body></html>"

        def raise_for_status(self) -> None:
            return None

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, headers=None):
            calls.append((url, headers))
            return _Response()

    monkeypatch.setattr("tracegate.services.decoy_auth.httpx.AsyncClient", lambda **_: _Client())
    settings = Settings(
        transit_decoy_github_repo_url="https://github.com/MyHeartRaces/Tracegate",
        transit_decoy_github_cache_ttl_seconds=300,
    )

    first = await load_github_repo_frame_html(settings)
    second = await load_github_repo_frame_html(settings)

    assert "Tracegate" in first
    assert second == first
    assert len(calls) == 1
