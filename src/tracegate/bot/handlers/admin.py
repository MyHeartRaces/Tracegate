"""Admin screens and flows. Every handler re-checks the actor's role."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from tracegate.bot import callbacks as cb
from tracegate.bot import context as ctx
from tracegate.bot import keyboards, nav, texts
from tracegate.bot.access import (
    bot_block_until,
    can_manage_block,
    can_manage_user_access,
    is_admin,
    is_superadmin,
    user_label,
)
from tracegate.bot.admin_tools import (
    build_admin_mtproto_report,
    build_admin_mtproto_rows,
    build_admin_users_report,
    parse_telegram_id,
    parse_user_block_request,
)
from tracegate.bot.client import ApiClientError
from tracegate.bot.delivery import cleanup_connection_messages
from tracegate.bot.handlers.feedback import send_with_retry
from tracegate.bot.states import AdminFlow

router = Router(name="admin")


async def _actor(telegram_id: int) -> dict | None:
    try:
        return await ctx.ensure_user(telegram_id)
    except Exception as exc:  # noqa: BLE001
        nav.log_error("admin_actor", exc)
        return None


async def require_admin(
    target: CallbackQuery | Message,
    state: FSMContext,
    *,
    superadmin: bool = False,
    new_message: bool = False,
) -> dict | None:
    """Return the actor when allowed; otherwise clear state and say why."""

    actor = await _actor(target.from_user.id)
    allowed = bool(actor) and (is_superadmin(actor) if superadmin else is_admin(actor))
    if allowed:
        return actor
    await state.clear()
    notice = texts.SUPERADMIN_ONLY if superadmin and actor and is_admin(actor) else texts.NO_RIGHTS
    if new_message or isinstance(target, Message):
        await nav.send(target, notice, keyboards.home_keyboard())
    else:
        await nav.show(target, notice, keyboards.home_keyboard())
    return None


async def _admin_error(target: CallbackQuery | Message, exc: BaseException, *, where: str) -> None:
    nav.log_error(where, exc)
    text = nav.user_error_text(exc, fallback=texts.ERR_ADMIN, admin=True)
    if isinstance(target, Message):
        await nav.send(target, text, keyboards.admin_back_keyboard())
    else:
        await nav.show(target, text, keyboards.admin_back_keyboard())


async def _prompt(callback: CallbackQuery, state: FSMContext, new_state, text: str) -> None:  # noqa: ANN001
    await state.clear()
    await state.set_state(new_state)
    await nav.show(callback, text, keyboards.admin_cancel_keyboard())


async def _read_target_id(message: Message) -> int | None:
    target_id = parse_telegram_id(message.text)
    if target_id is None:
        await nav.send(message, texts.ADMIN_BAD_ID, keyboards.admin_cancel_keyboard())
    return target_id


async def _get_target(message: Message, state: FSMContext, target_id: int) -> dict | None:
    try:
        return await ctx.api.get_user(target_id)
    except ApiClientError as exc:
        if exc.status_code == 404:
            await state.clear()
            await nav.send(message, texts.ADMIN_USER_NOT_FOUND, keyboards.admin_back_keyboard())
            return None
        raise


async def _notify(bot, chat_id: int, text: str) -> bool:  # noqa: ANN001
    return await send_with_retry(bot, chat_id, text)


# ------------------------------------------------------------------- menu ---


@router.callback_query(F.data == cb.ADMIN)
async def admin_menu(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    actor = await require_admin(callback, state)
    if actor is None:
        return
    await nav.show(callback, texts.ADMIN_MENU, keyboards.admin_menu_keyboard(is_superadmin=is_superadmin(actor)))


@router.callback_query(F.data == cb.ADMIN_USERS)
async def admin_users(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    if await require_admin(callback, state) is None:
        return
    try:
        now = datetime.now(timezone.utc)
        all_users = await ctx.api.list_users(limit=500, include_empty=True, prune_empty=False)
        active_users = await ctx.api.list_users(limit=500, include_empty=False, prune_empty=False)
        blocked_users = await ctx.api.list_users(limit=500, blocked_only=True, include_empty=True, prune_empty=False)
        grants = await ctx.api.list_mtproto_access()
    except Exception as exc:  # noqa: BLE001
        await _admin_error(callback, exc, where="admin_users")
        return
    active_blocked = [row for row in blocked_users if (bot_block_until(row) or now) > now]
    report = build_admin_users_report(
        all_users=all_users,
        active_users=active_users,
        blocked_users=active_blocked,
        active_mtproto_grants=build_admin_mtproto_rows(grants=grants, users=all_users),
        hidden_user_ids=set(ctx.settings.admin_users_report_hidden_ids or []),
    )
    await nav.show_chunks(callback, nav.split_text(report), keyboards.admin_back_keyboard())


@router.callback_query(F.data == cb.ADMIN_TGP)
async def admin_tgp(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    if await require_admin(callback, state) is None:
        return
    try:
        all_users = await ctx.api.list_users(limit=1000, include_empty=True, prune_empty=False)
        grants = await ctx.api.list_mtproto_access()
    except Exception as exc:  # noqa: BLE001
        await _admin_error(callback, exc, where="admin_tgp")
        return
    report = build_admin_mtproto_report(grants=build_admin_mtproto_rows(grants=grants, users=all_users))
    await nav.show_chunks(callback, nav.split_text(report), keyboards.admin_tgp_keyboard())


@router.callback_query(F.data == cb.ADMIN_LIST)
async def admin_list(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    if await require_admin(callback, state, superadmin=True) is None:
        return
    try:
        admins = await ctx.api.list_users(role="admin", limit=500)
        supers = await ctx.api.list_users(role="superadmin", limit=500)
    except Exception as exc:  # noqa: BLE001
        await _admin_error(callback, exc, where="admin_list")
        return
    text = (
        texts.admin_list([user_label(row) for row in supers], [user_label(row) for row in admins])
        if admins or supers
        else texts.ADMIN_LIST_EMPTY
    )
    await nav.show_chunks(callback, nav.split_text(text), keyboards.admin_back_keyboard())


# ---------------------------------------------------------- global revoke ---


@router.callback_query(F.data == cb.ADMIN_RESET_ASK)
async def admin_reset_ask(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    if await require_admin(callback, state) is None:
        return
    await nav.show(callback, texts.ADMIN_RESET_CONFIRM, keyboards.admin_reset_keyboard())


@router.callback_query(F.data == cb.ADMIN_RESET)
async def admin_reset(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    if await require_admin(callback, state) is None:
        return
    try:
        result = await ctx.api.reset_all_connections(actor_telegram_id=callback.from_user.id)
    except Exception as exc:  # noqa: BLE001
        await _admin_error(callback, exc, where="admin_reset")
        return
    await cleanup_connection_messages(callback, result.get("revoked_connection_ids"))
    await nav.show(
        callback,
        texts.admin_reset_done(
            connections=int(result.get("revoked_connections") or 0),
            tgp=int(result.get("revoked_mtproto_accesses") or 0),
        ),
        keyboards.admin_back_keyboard(),
    )


# ---------------------------------------------------------------- prompts ---


@router.callback_query(F.data == cb.ADMIN_GRANT)
async def admin_grant(callback: CallbackQuery, state: FSMContext) -> None:
    if await require_admin(callback, state, superadmin=True) is None:
        return
    await _prompt(callback, state, AdminFlow.waiting_for_grant_id, texts.ADMIN_PROMPT_GRANT)


@router.callback_query(F.data == cb.ADMIN_UNGRANT)
async def admin_ungrant(callback: CallbackQuery, state: FSMContext) -> None:
    if await require_admin(callback, state, superadmin=True) is None:
        return
    await _prompt(callback, state, AdminFlow.waiting_for_revoke_id, texts.ADMIN_PROMPT_UNGRANT)


@router.callback_query(F.data == cb.ADMIN_TGP_REVOKE)
async def admin_tgp_revoke(callback: CallbackQuery, state: FSMContext) -> None:
    if await require_admin(callback, state) is None:
        return
    await _prompt(callback, state, AdminFlow.waiting_for_mtproto_revoke_id, texts.ADMIN_PROMPT_TGP_REVOKE)


@router.callback_query(F.data == cb.ADMIN_REVOKE_ACCESS)
async def admin_revoke_access(callback: CallbackQuery, state: FSMContext) -> None:
    if await require_admin(callback, state) is None:
        return
    await _prompt(callback, state, AdminFlow.waiting_for_user_access_revoke_id, texts.ADMIN_PROMPT_REVOKE_ACCESS)


@router.callback_query(F.data == cb.ADMIN_BLOCK)
async def admin_block(callback: CallbackQuery, state: FSMContext) -> None:
    if await require_admin(callback, state) is None:
        return
    await _prompt(callback, state, AdminFlow.waiting_for_user_block, texts.ADMIN_PROMPT_BLOCK)


@router.callback_query(F.data == cb.ADMIN_UNBLOCK)
async def admin_unblock(callback: CallbackQuery, state: FSMContext) -> None:
    if await require_admin(callback, state) is None:
        return
    await _prompt(callback, state, AdminFlow.waiting_for_user_unblock, texts.ADMIN_PROMPT_UNBLOCK)


@router.callback_query(F.data.startswith(cb.FEEDBACK_BLOCK_P))
async def feedback_block(callback: CallbackQuery, state: FSMContext) -> None:
    actor = await require_admin(callback, state, new_message=True)
    if actor is None:
        return
    target_id = cb.parse_telegram_id(callback.data, cb.FEEDBACK_BLOCK_P)
    if target_id is None:
        await nav.send(callback, texts.ADMIN_BAD_ID, keyboards.admin_back_keyboard())
        return
    try:
        target = await ctx.api.get_or_create_user(target_id)
    except Exception as exc:  # noqa: BLE001
        nav.log_error("feedback_block", exc)
        await nav.send(callback, nav.user_error_text(exc, fallback=texts.ERR_ADMIN, admin=True))
        return
    if not can_manage_block(actor, target):
        await nav.send(callback, texts.ADMIN_CANT_MANAGE, keyboards.admin_back_keyboard())
        return
    await state.clear()
    await state.set_state(AdminFlow.waiting_for_user_block)
    await state.update_data(block_target_id=target_id, block_target_label=user_label(target))
    # A new message: the feedback notification itself stays intact.
    await nav.send(callback, texts.admin_block_targeted_prompt(user_label(target)), keyboards.admin_cancel_keyboard())


@router.message(Command("announce"))
async def announce(message: Message, state: FSMContext) -> None:
    await state.clear()
    if message.chat.type != "private":
        await message.answer(texts.PRIVATE_CHAT_ONLY)
        return
    if await require_admin(message, state) is None:
        return
    await state.set_state(AdminFlow.waiting_for_announce_text)
    await nav.send(message, texts.ADMIN_PROMPT_ANNOUNCE, keyboards.admin_cancel_keyboard())


# ------------------------------------------------------------ FSM inputs ---


@router.message(AdminFlow.waiting_for_grant_id)
async def receive_admin_grant_id(message: Message, state: FSMContext) -> None:
    if await require_admin(message, state, superadmin=True) is None:
        return
    target_id = await _read_target_id(message)
    if target_id is None:
        return
    await state.clear()
    try:
        await ctx.api.get_or_create_user(target_id)
        await ctx.api.set_user_role(target_id, "admin")
    except Exception as exc:  # noqa: BLE001
        await _admin_error(message, exc, where="admin_grant")
        return
    await nav.send(message, texts.admin_role_granted(target_id), keyboards.admin_back_keyboard())


@router.message(AdminFlow.waiting_for_revoke_id)
async def receive_admin_revoke_id(message: Message, state: FSMContext) -> None:
    if await require_admin(message, state, superadmin=True) is None:
        return
    target_id = await _read_target_id(message)
    if target_id is None:
        return
    await state.clear()
    if target_id in set(ctx.settings.superadmin_telegram_ids or []):
        await nav.send(message, texts.ADMIN_CANT_REVOKE_SUPERADMIN, keyboards.admin_back_keyboard())
        return
    try:
        await ctx.api.set_user_role(target_id, "user")
    except ApiClientError as exc:
        if exc.status_code == 404:
            await nav.send(message, texts.ADMIN_USER_NOT_FOUND, keyboards.admin_back_keyboard())
            return
        await _admin_error(message, exc, where="admin_ungrant")
        return
    except Exception as exc:  # noqa: BLE001
        await _admin_error(message, exc, where="admin_ungrant")
        return
    await nav.send(message, texts.admin_role_revoked(target_id), keyboards.admin_back_keyboard())


@router.message(AdminFlow.waiting_for_mtproto_revoke_id)
async def receive_mtproto_revoke_id(message: Message, state: FSMContext) -> None:
    actor = await require_admin(message, state)
    if actor is None:
        return
    target_id = await _read_target_id(message)
    if target_id is None:
        return
    try:
        target = await _get_target(message, state, target_id)
        if target is None:
            return
        await state.clear()
        if not can_manage_user_access(actor, target):
            await nav.send(message, texts.ADMIN_CANT_MANAGE, keyboards.admin_back_keyboard())
            return
        await ctx.api.revoke_mtproto_access(target_id)
    except ApiClientError as exc:
        await state.clear()
        if exc.status_code == 404:
            await nav.send(message, texts.ADMIN_TGP_NOT_FOUND, keyboards.admin_tgp_keyboard())
            return
        await _admin_error(message, exc, where="admin_tgp_revoke")
        return
    except Exception as exc:  # noqa: BLE001
        await state.clear()
        await _admin_error(message, exc, where="admin_tgp_revoke")
        return
    await nav.send(message, texts.admin_tgp_revoked(user_label(target)), keyboards.admin_tgp_keyboard())


@router.message(AdminFlow.waiting_for_user_access_revoke_id)
async def receive_user_access_revoke_id(message: Message, state: FSMContext) -> None:
    actor = await require_admin(message, state)
    if actor is None:
        return
    target_id = await _read_target_id(message)
    if target_id is None:
        return
    try:
        target = await _get_target(message, state, target_id)
    except Exception as exc:  # noqa: BLE001
        await state.clear()
        await _admin_error(message, exc, where="admin_revoke_access_lookup")
        return
    if target is None:
        return
    if not can_manage_user_access(actor, target):
        await state.clear()
        await nav.send(message, texts.ADMIN_CANT_MANAGE, keyboards.admin_back_keyboard())
        return
    await state.set_state(AdminFlow.waiting_for_user_access_revoke_notify)
    await state.update_data(revoke_access_target_id=target_id, revoke_access_target_label=user_label(target))
    await nav.send(message, texts.admin_revoke_notify_question(user_label(target)), keyboards.admin_notify_keyboard())


@router.callback_query(F.data.in_({cb.ADMIN_NOTIFY_YES, cb.ADMIN_NOTIFY_NO}))
async def admin_revoke_notify(callback: CallbackQuery, state: FSMContext) -> None:
    actor = await require_admin(callback, state)
    if actor is None:
        return
    data = await state.get_data()
    target_id = data.get("revoke_access_target_id")
    target_label = str(data.get("revoke_access_target_label") or "").strip()
    await state.clear()
    if target_id is None:
        await nav.show(callback, texts.ADMIN_SESSION_EXPIRED, keyboards.admin_back_keyboard())
        return
    target_id = int(target_id)
    try:
        target = await ctx.api.get_user(target_id)
        if not can_manage_user_access(actor, target):
            await nav.show(callback, texts.ADMIN_CANT_MANAGE, keyboards.admin_back_keyboard())
            return
        result = await ctx.api.revoke_user_access(actor_telegram_id=callback.from_user.id, target_telegram_id=target_id)
    except Exception as exc:  # noqa: BLE001
        await _admin_error(callback, exc, where="admin_revoke_access")
        return
    await cleanup_connection_messages(callback, result.get("revoked_connection_ids"))
    text = texts.admin_access_revoked(
        target_label or user_label(target),
        connections=int(result.get("revoked_connections") or 0),
        devices=int(result.get("revoked_devices") or 0),
        tgp=bool(result.get("revoked_mtproto_access")),
    )
    if callback.data == cb.ADMIN_NOTIFY_YES:
        notice = texts.access_revoked_notification(revoked_at=datetime.now(timezone.utc))
        if not await _notify(callback.bot, target_id, notice):
            text = f"{text}\n\n{texts.ADMIN_NOTIFY_FAILED}"
    await nav.show(callback, text, keyboards.admin_back_keyboard())


@router.message(AdminFlow.waiting_for_user_block)
async def receive_user_block(message: Message, state: FSMContext) -> None:
    actor = await require_admin(message, state)
    if actor is None:
        return
    data = await state.get_data()
    default_target_id = data.get("block_target_id")
    try:
        target_id, hours, reason = parse_user_block_request(
            message.text or "",
            default_target_id=int(default_target_id) if default_target_id is not None else None,
        )
    except ValueError as exc:
        # parse_user_block_request raises Russian, user-presentable messages.
        await nav.send(message, str(exc), keyboards.admin_cancel_keyboard())
        return
    await state.clear()
    try:
        target = await ctx.api.get_or_create_user(target_id)
        if not can_manage_block(actor, target):
            await nav.send(message, texts.ADMIN_CANT_MANAGE, keyboards.admin_back_keyboard())
            return
        blocked = await ctx.api.block_user_bot(target_id, hours=hours, reason=reason, revoke_access=True)
    except Exception as exc:  # noqa: BLE001
        await _admin_error(message, exc, where="admin_block")
        return
    until = bot_block_until(blocked)
    reason_from_api = str(blocked.get("bot_block_reason") or "").strip() or reason
    text = texts.admin_blocked(user_label(target), until)
    notice = texts.block_notification(
        blocked_at=datetime.now(timezone.utc),
        hours=hours,
        until=until,
        reason=reason_from_api,
    )
    if not await _notify(message.bot, target_id, notice):
        text = f"{text}\n\n{texts.ADMIN_NOTIFY_FAILED}"
    await nav.send(message, text, keyboards.admin_back_keyboard())


@router.message(AdminFlow.waiting_for_user_unblock)
async def receive_user_unblock(message: Message, state: FSMContext) -> None:
    actor = await require_admin(message, state)
    if actor is None:
        return
    target_id = await _read_target_id(message)
    if target_id is None:
        return
    try:
        target = await _get_target(message, state, target_id)
        if target is None:
            return
        await state.clear()
        if not can_manage_block(actor, target):
            await nav.send(message, texts.ADMIN_CANT_MANAGE, keyboards.admin_back_keyboard())
            return
        await ctx.api.unblock_user_bot(target_id)
    except Exception as exc:  # noqa: BLE001
        await state.clear()
        await _admin_error(message, exc, where="admin_unblock")
        return
    text = texts.admin_unblocked(user_label(target))
    if not await _notify(message.bot, target_id, texts.unblock_notification(unblocked_at=datetime.now(timezone.utc))):
        text = f"{text}\n\n{texts.ADMIN_NOTIFY_FAILED}"
    await nav.send(message, text, keyboards.admin_back_keyboard())


@router.message(AdminFlow.waiting_for_announce_text)
async def announce_text(message: Message, state: FSMContext) -> None:
    if await require_admin(message, state) is None:
        return
    text = (message.text or "").strip()
    if not text:
        await nav.send(message, texts.ADMIN_ANNOUNCE_EMPTY, keyboards.admin_cancel_keyboard())
        return
    await state.clear()
    try:
        users = await ctx.api.list_users(limit=1000, include_empty=True, prune_empty=False)
    except Exception as exc:  # noqa: BLE001
        await _admin_error(message, exc, where="admin_announce")
        return
    sent = 0
    failed = 0
    for user in users:
        telegram_id = int(user.get("telegram_id") or 0)
        if not telegram_id:
            continue
        if await send_with_retry(message.bot, telegram_id, text):
            sent += 1
        else:
            failed += 1
        await asyncio.sleep(0.04)
    await nav.send(message, texts.admin_announce_done(sent=sent, failed=failed), keyboards.admin_back_keyboard())
