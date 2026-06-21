from datetime import timezone

from tracegate.bot.admin_tools import (
    build_admin_mtproto_report,
    build_admin_users_report,
    build_feedback_admin_text,
    format_role_label,
    parse_user_block_request,
)
from tracegate.services.bot_blocks import PERMANENT_BOT_BLOCK_UNTIL


def test_parse_user_block_request_supports_generic_admin_flow() -> None:
    target_id, hours, reason = parse_user_block_request("123456789 72 abuse report")
    assert target_id == 123456789
    assert hours == 72
    assert reason == "abuse report"


def test_parse_user_block_request_supports_targeted_feedback_flow() -> None:
    target_id, hours, reason = parse_user_block_request("9999 spam links", default_target_id=555)
    assert target_id == 555
    assert hours == 9999
    assert reason == "spam links"


def test_build_feedback_admin_text_includes_author_and_clips_body() -> None:
    text = build_feedback_admin_text(
        author={
            "telegram_id": 42,
            "telegram_username": "alice",
            "role": "user",
        },
        feedback_text="x" * 5000,
        sent_at=PERMANENT_BOT_BLOCK_UNTIL.astimezone(timezone.utc),
    )
    assert "Автор: @alice (42)" in text
    assert "Роль: Пользователь" in text
    assert len(text) <= 4096


def test_build_admin_users_report_shows_all_active_and_blocked_sections() -> None:
    report = build_admin_users_report(
        all_users=[
            {"telegram_id": 1, "telegram_username": "all_user", "role": "user"},
            {"telegram_id": 2, "telegram_username": "blocked_user", "role": "user"},
        ],
        active_users=[
            {"telegram_id": 1, "telegram_username": "all_user", "role": "user"},
        ],
        blocked_users=[
            {
                "telegram_id": 2,
                "telegram_username": "blocked_user",
                "role": "user",
                "bot_blocked_until": PERMANENT_BOT_BLOCK_UNTIL.isoformat(),
            }
        ],
        active_mtproto_grants=[
            {
                "telegram_id": 1,
                "display": "@all_user (1)",
                "role": "user",
                "label": "@all_user",
                "updated_at": "2026-04-18T10:00:00+00:00",
            }
        ],
    )
    assert "👥 Пользователи Tracegate: 2" in report
    assert "🔌 Активные подключения: 1" in report
    assert "🔐 Активные Telegram Proxy: 1" in report
    assert "⛔ Активные блокировки: 1" in report
    assert "@all_user (1)" in report
    assert "@blocked_user (2)" in report
    assert "Пользователь" in report
    assert "Блок: перманентно" in report


def test_build_admin_mtproto_report_lists_active_grants() -> None:
    report = build_admin_mtproto_report(
        grants=[
            {
                "telegram_id": 42,
                "display": "@alice (42)",
                "role": "user",
                "label": "@alice",
                "issued_by": "bot",
                "updated_at": "2026-04-18T10:00:00+00:00",
            }
        ]
    )
    assert "🔐 Постоянные Telegram Proxy-доступы: 1" in report
    assert "@alice (42)" in report
    assert "Источник: bot" in report


def test_format_role_label_translates_known_roles() -> None:
    assert format_role_label("user") == "Пользователь"
    assert format_role_label("admin") == "Администратор"
    assert format_role_label("superadmin") == "Суперадмин"
