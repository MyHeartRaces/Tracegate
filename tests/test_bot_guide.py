from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from aiogram.exceptions import TelegramBadRequest

import test_bot_support  # noqa: F401
from test_bot_support import DummyCallback, DummyMessage, DummyState, callback_datas
from tracegate.bot import context as ctx
from tracegate.bot import guide, nav, texts
from tracegate.bot.handlers import guide as guide_handlers
from tracegate.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "deploy" / "examples" / "bot-guide.example.yaml"


def _guide_data(**overrides) -> dict:  # noqa: ANN003
    data = {
        "version": 1,
        "title": "📖 Инструкция",
        "intro": "Вступление <b>жирным</b>.",
        "sections": [
            {"id": "quick", "button": "🚀 Быстрый старт", "text": "Шаги."},
            {
                "id": "apps",
                "button": "📲 Приложения",
                "text": "Выбери устройство:",
                "sections": [{"id": "ios", "button": "iPhone / iPad", "text": "Текст для iPhone."}],
            },
        ],
        "footer": "Подвал.",
    }
    data.update(overrides)
    return data


def _use_guide_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(ctx.settings, "bot_guide_path", str(path))
    return path


# ------------------------------------------------------------- parsing ---


def test_shipped_example_is_valid_and_generic() -> None:
    parsed = guide.parse_structured(yaml.safe_load(EXAMPLE.read_text(encoding="utf-8")))
    assert [section.id for section in parsed.sections] == ["quick", "apps", "fragment"]
    assert [child.path for child in parsed.find("apps").children] == ["apps.ios", "apps.android", "apps.desktop"]
    assert parsed.howto_callback() == "g:apps"
    raw = EXAMPLE.read_text(encoding="utf-8")
    for needle in ("Karing", "INCY", "Shadowrocket", "Throne", "Happ", "apps.apple.com"):
        assert needle not in raw


def test_parse_structured_builds_paths_and_callbacks() -> None:
    parsed = guide.parse_structured(_guide_data())
    ios = parsed.find("apps.ios")
    assert ios is not None
    assert ios.callback == "g:apps.ios"
    assert ios.parent_path == "apps"
    assert parsed.find("quick").parent_path is None
    assert parsed.find("missing") is None


def test_parse_rejects_nesting_deeper_than_two() -> None:
    data = _guide_data()
    data["sections"][1]["sections"][0]["sections"] = [{"id": "deep", "button": "x", "text": "y"}]
    with pytest.raises(guide.GuideError, match="nesting"):
        guide.parse_structured(data)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda d: d.update(version=2), "version"),
        (lambda d: d.update(version=True), "version"),
        (lambda d: d.update(extra="x"), "unknown top-level"),
        (lambda d: d["sections"][0].update(id="Bad Id"), "id must match"),
        (lambda d: d["sections"][0].update(id="apps"), "not unique"),
        (lambda d: d["sections"][1]["sections"][0].update(id="quick"), "not unique"),
        (lambda d: d["sections"][0].update(button=""), "button"),
        (lambda d: d["sections"][0].update(button="x" * 65), "longer"),
        (lambda d: d["sections"][0].update(colour="red"), "unknown keys"),
        (lambda d: d["sections"][0].update(text=""), "needs text or sections"),
        (lambda d: d.update(sections="nope"), "must be a list"),
    ],
)
def test_parse_rejects_invalid_guides(mutate, match: str) -> None:  # noqa: ANN001
    data = _guide_data()
    mutate(data)
    with pytest.raises(guide.GuideError, match=match):
        guide.parse_structured(data)


def test_parse_rejects_paths_over_callback_limit() -> None:
    data = _guide_data()
    data["sections"][1]["id"] = "a" * 32
    data["sections"][1]["sections"][0]["id"] = "b" * 32
    with pytest.raises(guide.GuideError, match="64 bytes"):
        guide.parse_structured(data)


def test_parse_rejects_non_mapping() -> None:
    with pytest.raises(guide.GuideError):
        guide.parse_structured(["not", "a", "mapping"])


def test_howto_callback_falls_back_to_root_without_apps_section() -> None:
    data = _guide_data()
    data["sections"] = data["sections"][:1]
    assert guide.parse_structured(data).howto_callback() == "g"


def test_page_text_escapes_button_and_appends_footer() -> None:
    data = _guide_data()
    data["sections"][0]["button"] = "A & <B>"
    parsed = guide.parse_structured(data)
    text = parsed.page_text(parsed.find("quick"))
    assert text.startswith("<b>A &amp; &lt;B&gt;</b>")
    assert text.endswith("Подвал.")


def test_telegram_html_whitelist() -> None:
    assert guide.telegram_html_ok("<b>ok</b> <a href='https://example.com'>x</a>")
    assert not guide.telegram_html_ok("<div>no</div>")
    assert not guide.telegram_html_ok("<b>unclosed")
    assert not guide.telegram_html_ok("line<br/>break")
    assert nav.strip_html("a<br>b <b>c</b> &amp; d") == "a\nb c & d"


# ------------------------------------------------------------- loading ---


def test_load_yaml_json_and_plain_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_guide_file(monkeypatch, tmp_path, "guide.yaml", yaml.safe_dump(_guide_data(), allow_unicode=True))
    assert guide.load_guide().html is True
    _use_guide_file(monkeypatch, tmp_path, "guide.json", json.dumps(_guide_data(), ensure_ascii=False))
    assert guide.load_guide().find("apps.ios") is not None
    _use_guide_file(monkeypatch, tmp_path, "guide.txt", "Простой текст <b>без</b> разметки.")
    plain = guide.load_guide()
    assert plain.html is False
    assert plain.root_text() == "Простой текст <b>без</b> разметки."


def test_invalid_or_missing_file_is_logged_not_raised(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_guide_file(monkeypatch, tmp_path, "guide.yaml", "version: [unclosed")
    assert guide.try_load_guide() is None
    monkeypatch.setattr(ctx.settings, "bot_guide_path", str(tmp_path / "missing.yaml"))
    assert guide.try_load_guide() is None
    assert guide.howto_callback() == "g"


def test_reload_on_file_change(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _use_guide_file(monkeypatch, tmp_path, "guide.yaml", yaml.safe_dump(_guide_data(), allow_unicode=True))
    assert guide.load_guide().intro == "Вступление <b>жирным</b>."
    path.write_text(yaml.safe_dump(_guide_data(intro="Новый текст, заметно длиннее."), allow_unicode=True), encoding="utf-8")
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    assert guide.load_guide().intro == "Новый текст, заметно длиннее."


@pytest.mark.parametrize("placeholder", ["", "[TRACEGATE_BOT_GUIDE_PLACEHOLDER]", "REPLACE_WITH_PRIVATE_GUIDE_MESSAGE"])
def test_default_message_used_without_path(monkeypatch: pytest.MonkeyPatch, placeholder: str) -> None:
    monkeypatch.setattr(ctx.settings, "bot_guide_path", "")
    monkeypatch.setattr(ctx.settings, "bot_guide_message", placeholder)
    assert guide.load_guide().root_text() == str(Settings.model_fields["bot_guide_message"].default).strip()


def test_configured_message_used_without_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctx.settings, "bot_guide_path", "")
    monkeypatch.setattr(ctx.settings, "bot_guide_message", "[частный гайд]")
    assert guide.load_guide().root_text() == "[частный гайд]"


# ------------------------------------------------------------ handlers ---


@pytest.mark.asyncio
async def test_guide_root_screen_edits_in_place_with_section_buttons(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_guide_file(monkeypatch, tmp_path, "guide.yaml", yaml.safe_dump(_guide_data(), allow_unicode=True))
    callback = DummyCallback("g")
    await guide_handlers.guide_root(callback, DummyState())
    (text, kwargs), = callback.message.edits
    assert text.startswith("<b>📖 Инструкция</b>")
    assert kwargs["parse_mode"] == "HTML"
    assert callback_datas(kwargs["reply_markup"]) == ["g:quick", "g:apps", "menu"]


@pytest.mark.asyncio
async def test_nested_page_back_goes_to_parent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_guide_file(monkeypatch, tmp_path, "guide.yaml", yaml.safe_dump(_guide_data(), allow_unicode=True))
    callback = DummyCallback("g:apps.ios")
    await guide_handlers.guide_page(callback, DummyState())
    text, kwargs = callback.message.edits[0]
    assert "Текст для iPhone." in text
    assert callback_datas(kwargs["reply_markup"]) == ["g:apps", "menu"]
    top = DummyCallback("g:apps")
    await guide_handlers.guide_page(top, DummyState())
    assert callback_datas(top.message.edits[0][1]["reply_markup"]) == ["g:apps.ios", "g", "menu"]


@pytest.mark.asyncio
async def test_unknown_page_opens_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_guide_file(monkeypatch, tmp_path, "guide.yaml", yaml.safe_dump(_guide_data(), allow_unicode=True))
    callback = DummyCallback("g:removed")
    await guide_handlers.guide_page(callback, DummyState())
    assert callback.message.edits[0][0].startswith("<b>📖 Инструкция</b>")


@pytest.mark.asyncio
async def test_invalid_guide_shows_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_guide_file(monkeypatch, tmp_path, "guide.json", "{not json")
    callback = DummyCallback("g")
    await guide_handlers.guide_root(callback, DummyState())
    assert callback.message.edits[0][0] == texts.GUIDE_UNAVAILABLE


@pytest.mark.asyncio
async def test_long_page_is_chunked_first_edited_rest_sent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    long_text = "\n\n".join(f"Абзац {index}. " + "текст " * 120 for index in range(20))
    data = _guide_data()
    data["sections"][0]["text"] = long_text
    _use_guide_file(monkeypatch, tmp_path, "guide.yaml", yaml.safe_dump(data, allow_unicode=True))
    callback = DummyCallback("g:quick")
    await guide_handlers.guide_page(callback, DummyState())
    assert len(callback.message.edits) == 1
    assert callback.message.answers
    chunks = [callback.message.edits[0][0]] + callback.message.sent_texts
    assert all(len(chunk) <= nav.TELEGRAM_TEXT_CHUNK_LIMIT for chunk in chunks)
    assert "reply_markup" not in callback.message.edits[0][1]
    assert callback_datas(callback.message.answers[-1][1]["reply_markup"]) == ["g", "menu"]


@pytest.mark.asyncio
async def test_plain_default_guide_is_plain_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctx.settings, "bot_guide_path", "")
    monkeypatch.setattr(ctx.settings, "bot_guide_message", "A" * 4100)
    message = DummyMessage("/guide")
    await guide_handlers.guide_command(message, DummyState())
    assert len(message.answers) == 2
    assert all("parse_mode" not in kwargs for _text, kwargs in message.answers)
    assert callback_datas(message.answers[-1][1]["reply_markup"]) == ["menu"]


@pytest.mark.asyncio
async def test_unsupported_html_falls_back_to_plain(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    data = _guide_data()
    data["sections"][0]["text"] = "<div>Блок</div> и <b>жирный</b>"
    _use_guide_file(monkeypatch, tmp_path, "guide.yaml", yaml.safe_dump(data, allow_unicode=True))
    callback = DummyCallback("g:quick")
    await guide_handlers.guide_page(callback, DummyState())
    text, kwargs = callback.message.edits[0]
    assert "parse_mode" not in kwargs
    assert "<" not in text
    assert "Блок и жирный" in text


@pytest.mark.asyncio
async def test_telegram_parse_error_falls_back_to_plain() -> None:
    message = DummyMessage()
    message.edit_error = TelegramBadRequest(
        method=SimpleNamespace(), message="Bad Request: can't parse entities: unexpected end tag"
    )
    edits: list[tuple[str, dict]] = []

    async def _edit(text: str, **kwargs) -> None:  # noqa: ANN003
        edits.append((text, kwargs))
        if kwargs.get("parse_mode"):
            raise message.edit_error

    message.edit_text = _edit
    callback = DummyCallback("g", message=message)
    await nav.show(callback, "<b>bold</b> &amp; more", None, parse_mode=nav.HTML)
    assert edits[-1] == ("bold & more", {"disable_web_page_preview": True})
