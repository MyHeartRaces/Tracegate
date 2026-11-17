"""Telegram Proxy (MTProto) screen: show link, rotate, revoke."""

from __future__ import annotations

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery
from aiogram.types.input_file import BufferedInputFile

from tracegate.bot import callbacks as cb
from tracegate.bot import context as ctx
from tracegate.bot import keyboards, nav, texts
from tracegate.bot.client import ApiClientError
from tracegate.bot.delivery import build_qr_png
from tracegate.bot.handlers.start import current_user, show_error

router = Router(name="mtproto")


def mtproto_access_label(user: dict) -> str | None:
    username = str(user.get("telegram_username") or "").strip()
    if username:
        return f"@{username.lstrip('@')}"
    first = str(user.get("telegram_first_name") or "").strip()
    last = str(user.get("telegram_last_name") or "").strip()
    return " ".join(part for part in [first, last] if part).strip() or None


def mtproto_qr_links(profile: dict) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if isinstance(profile.get("links"), list):
        for index, row in enumerate(profile["links"]):
            if not isinstance(row, dict):
                continue
            https_url = str(row.get("httpsUrl") or "").strip()
            if not https_url:
                continue
            label = str(row.get("label") or "").strip() or texts.mtproto_route_label(index + 1)
            rows.append((label, https_url))
    if rows:
        return rows
    https_url = str(profile.get("httpsUrl") or "").strip()
    return [(texts.MTPROTO_MAIN_ROUTE, https_url)] if https_url else []


async def _has_access(telegram_id: int) -> bool | None:
    try:
        await ctx.api.get_mtproto_access(int(telegram_id))
    except ApiClientError as exc:
        if exc.status_code == 404:
            return False
        nav.log_error("tgp_status", exc)
        return None
    except Exception as exc:  # noqa: BLE001
        nav.log_error("tgp_status", exc)
        return None
    return True


async def show_tgp(callback: CallbackQuery, *, status: str | None = None, has_access: bool | None = None) -> None:
    if has_access is None and status is None:
        has_access = await _has_access(callback.from_user.id)
    text = texts.with_status(status, texts.tgp_screen(has_access=has_access))
    await nav.show(callback, text, keyboards.tgp_keyboard())


@router.callback_query(F.data == cb.TGP)
async def tgp_open(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await show_tgp(callback)


async def _issue(callback: CallbackQuery, *, rotate: bool, user: dict | None) -> None:
    try:
        user = await current_user(callback.from_user.id, user)
        result = await ctx.api.issue_mtproto_access(
            telegram_id=int(user["telegram_id"]),
            label=mtproto_access_label(user),
            rotate=rotate,
            issued_by="bot",
        )
        profile = result.get("profile") if isinstance(result.get("profile"), dict) else {}
        qr_links = mtproto_qr_links(profile)
        if not qr_links:
            raise ValueError("API returned no Telegram Proxy link")
    except Exception as exc:  # noqa: BLE001
        await show_error(callback, exc, where="tgp_issue", fallback=texts.ERR_TGP, user=user, back_callback=cb.TGP)
        return

    if rotate:
        status = texts.TGP_ROTATED
    elif profile.get("reused"):
        status = texts.TGP_SENT_AGAIN
    else:
        status = texts.TGP_SENT_NEW
    await show_tgp(callback, status=status, has_access=True)
    await callback.message.answer(texts.format_mtproto_link_message(profile), disable_web_page_preview=True)
    for index, (label, https_url) in enumerate(qr_links, start=1):
        await callback.message.answer_photo(
            BufferedInputFile(build_qr_png(https_url), filename=f"tracegate-mtproto-{index}-qr.png"),
            caption=texts.mtproto_qr_caption(label),
        )


@router.callback_query(F.data == cb.TGP_SHOW)
async def tgp_show(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    await _issue(callback, rotate=False, user=tracegate_user)


@router.callback_query(F.data == cb.TGP_ROTATE)
async def tgp_rotate(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    await _issue(callback, rotate=True, user=tracegate_user)


@router.callback_query(F.data == cb.TGP_REVOKE_ASK)
async def tgp_revoke_ask(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await nav.show(
        callback,
        texts.TGP_REVOKE_CONFIRM,
        keyboards.confirm_keyboard(
            confirm_text=texts.BTN_TGP_CONFIRM_REVOKE,
            confirm_callback=cb.TGP_REVOKE,
            back_callback=cb.TGP,
        ),
    )


@router.callback_query(F.data == cb.TGP_REVOKE)
async def tgp_revoke(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    try:
        await ctx.api.revoke_mtproto_access(callback.from_user.id)
    except ApiClientError as exc:
        if exc.status_code == 404:
            await show_tgp(callback, status=texts.TGP_NOT_FOUND, has_access=False)
            return
        await show_error(
            callback, exc, where="tgp_revoke", fallback=texts.ERR_TGP_REVOKE, user=tracegate_user, back_callback=cb.TGP
        )
        return
    except Exception as exc:  # noqa: BLE001
        await show_error(
            callback, exc, where="tgp_revoke", fallback=texts.ERR_TGP_REVOKE, user=tracegate_user, back_callback=cb.TGP
        )
        return
    await show_tgp(callback, status=texts.TGP_REVOKED, has_access=False)
