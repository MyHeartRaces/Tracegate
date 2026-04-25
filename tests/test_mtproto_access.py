import json

from tracegate.services.mtproto_access import (
    issue_mtproto_access_profile,
    load_mtproto_access_entries,
    revoke_mtproto_access,
)
from tracegate.settings import Settings


def _write_profile(path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "protocol": "mtproto",
                "server": "proxied.tracegate.su",
                "port": 443,
                "transport": "tls",
                "domain": "proxied.tracegate.su",
                "clientSecretHex": "ee00112233445566778899aabbccddeeff70726f786965642e7472616365676174652e7375",
                "tgUri": "tg://proxy?server=proxied.tracegate.su&port=443&secret=ee0011",
                "httpsUrl": "https://t.me/proxy?server=proxied.tracegate.su&port=443&secret=ee0011",
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def test_issue_mtproto_access_profile_persists_user_bound_secret(tmp_path) -> None:
    profile_path = tmp_path / "public-profile.json"
    access_state_path = tmp_path / "issued.json"
    _write_profile(profile_path)

    settings = Settings(
        mtproto_public_profile_file=str(profile_path),
        mtproto_issued_state_file=str(access_state_path),
    )

    profile, previous_entries, next_entries, changed = issue_mtproto_access_profile(
        settings,
        telegram_id=123456,
        label="@operator",
        issued_by="bot",
    )

    assert previous_entries == []
    assert changed is True
    assert profile["ephemeral"] is False
    assert profile["profile"] == "MTProto-FakeTLS-Direct"
    assert profile["telegramId"] == 123456
    assert profile["reused"] is False
    assert profile["label"] == "@operator"
    assert profile["issuedBy"] == "bot"
    assert len(next_entries) == 1
    assert next_entries[0]["telegramId"] == 123456
    assert next_entries[0]["secretHex"]


def test_issue_mtproto_access_profile_reuses_existing_secret_without_rotation(tmp_path) -> None:
    profile_path = tmp_path / "public-profile.json"
    access_state_path = tmp_path / "issued.json"
    _write_profile(profile_path)

    settings = Settings(
        mtproto_public_profile_file=str(profile_path),
        mtproto_issued_state_file=str(access_state_path),
    )

    first, _prev1, _next1, changed1 = issue_mtproto_access_profile(settings, telegram_id=100)
    second, previous_entries, next_entries, changed2 = issue_mtproto_access_profile(settings, telegram_id=100)

    assert changed1 is True
    assert changed2 is False
    assert first["clientSecretHex"] == second["clientSecretHex"]
    assert second["reused"] is True
    assert previous_entries == next_entries


def test_issue_mtproto_access_profile_rotates_existing_secret(tmp_path) -> None:
    profile_path = tmp_path / "public-profile.json"
    access_state_path = tmp_path / "issued.json"
    _write_profile(profile_path)

    settings = Settings(
        mtproto_public_profile_file=str(profile_path),
        mtproto_issued_state_file=str(access_state_path),
    )

    first, _prev1, _next1, _changed1 = issue_mtproto_access_profile(settings, telegram_id=100)
    second, _prev2, next_entries, changed2 = issue_mtproto_access_profile(settings, telegram_id=100, rotate=True)

    assert changed2 is True
    assert first["clientSecretHex"] != second["clientSecretHex"]
    assert len(next_entries) == 1
    assert load_mtproto_access_entries(settings)[0]["telegramId"] == 100


def test_revoke_mtproto_access_removes_entry(tmp_path) -> None:
    profile_path = tmp_path / "public-profile.json"
    access_state_path = tmp_path / "issued.json"
    _write_profile(profile_path)

    settings = Settings(
        mtproto_public_profile_file=str(profile_path),
        mtproto_issued_state_file=str(access_state_path),
    )

    issue_mtproto_access_profile(settings, telegram_id=100)
    removed, previous_entries, next_entries = revoke_mtproto_access(settings, telegram_id=100)

    assert removed is not None
    assert len(previous_entries) == 1
    assert next_entries == []
    assert load_mtproto_access_entries(settings) == []
