"""Guide screens: /guide, the menu button and per-section pages."""

from __future__ import annotations

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from tracegate.bot import callbacks as cb
from tracegate.bot import keyboards, nav, texts
from tracegate.bot.guide import Guide, GuideSection, telegram_html_ok, try_load_guide

router = Router(name="guide")


def _render(guide: Guide, text: str) -> tuple[tuple[str, ...], str | None]:
    """Chunks and parse mode for a page; invalid HTML falls back to plain text."""

    if guide.html and telegram_html_ok(text):
        return nav.split_text(text), nav.HTML
    return nav.split_text(nav.strip_html(text) if guide.html else text), None


async def show_guide_root(target: CallbackQuery | Message) -> None:
    guide = try_load_guide()
    if guide is None:
        await nav.show(target, texts.GUIDE_UNAVAILABLE, keyboards.home_keyboard())
        return
    chunks, parse_mode = _render(guide, guide.root_text())
    children = [(section.button, section.callback) for section in guide.sections]
    await nav.show_chunks(target, chunks, keyboards.guide_keyboard(children, back_callback=None), parse_mode=parse_mode)


async def show_guide_page(target: CallbackQuery | Message, path: str) -> None:
    guide = try_load_guide()
    if guide is None:
        await nav.show(target, texts.GUIDE_UNAVAILABLE, keyboards.home_keyboard())
        return
    section: GuideSection | None = guide.find(path)
    if section is None:
        # The page was removed from the guide since this button was sent.
        await show_guide_root(target)
        return
    chunks, parse_mode = _render(guide, guide.page_text(section))
    children = [(child.button, child.callback) for child in section.children]
    back = cb.guide_page(section.parent_path) if section.parent_path else cb.GUIDE
    await nav.show_chunks(target, chunks, keyboards.guide_keyboard(children, back_callback=back), parse_mode=parse_mode)


@router.message(Command("guide"))
async def guide_command(message: Message, state: FSMContext) -> None:
    await state.clear()
    await show_guide_root(message)


@router.callback_query(F.data == cb.GUIDE)
async def guide_root(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await show_guide_root(callback)


@router.callback_query(F.data.startswith(cb.GUIDE_PAGE_P))
async def guide_page(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await show_guide_page(callback, str(callback.data or "")[len(cb.GUIDE_PAGE_P) :])
