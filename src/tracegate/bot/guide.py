"""Bot guide loader: structured YAML/JSON guide or a plain-text page.

``BOT_GUIDE_PATH`` may point to a ``.yaml``/``.yml``/``.json`` file with the
structured format documented in ``docs/bot-guide.md``; any other file is shown
as plain text. Without a path the ``bot_guide_message`` setting is used.
"""

from __future__ import annotations

import html
import json
import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import yaml

from tracegate.bot import callbacks as cb
from tracegate.bot import context as ctx
from tracegate.bot import texts
from tracegate.settings import Settings

logger = logging.getLogger("tracegate.bot.guide")

GUIDE_VERSION = 1
MAX_DEPTH = 2
MAX_GUIDE_BYTES = 1024 * 1024
MAX_BUTTON_LENGTH = 64
SECTION_ID_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
STRUCTURED_SUFFIXES = {".yaml", ".yml", ".json"}
HOWTO_SECTION_ID = "apps"

_TOP_KEYS = {"version", "title", "intro", "sections", "footer"}
_SECTION_KEYS = {"id", "button", "text", "sections"}
_PLACEHOLDER_MESSAGES = {
    "",
    "[TRACEGATE_BOT_GUIDE_PLACEHOLDER]",
    "REPLACE_WITH_PRIVATE_GUIDE_MESSAGE",
    "Tracegate profile guide.",
}

# Tags Telegram accepts with parse_mode=HTML.
_ALLOWED_TAGS = {
    "b",
    "strong",
    "i",
    "em",
    "u",
    "ins",
    "s",
    "strike",
    "del",
    "a",
    "code",
    "pre",
    "span",
    "tg-spoiler",
    "tg-emoji",
    "blockquote",
}


class GuideError(ValueError):
    """The guide file is missing or invalid."""


@dataclass(frozen=True)
class GuideSection:
    id: str
    path: str
    button: str
    text: str
    children: tuple["GuideSection", ...] = ()

    @property
    def callback(self) -> str:
        return cb.guide_page(self.path)

    @property
    def parent_path(self) -> str | None:
        head, sep, _tail = self.path.rpartition(".")
        return head if sep else None


@dataclass(frozen=True)
class Guide:
    title: str
    intro: str
    sections: tuple[GuideSection, ...] = ()
    footer: str = ""
    html: bool = True
    _index: dict[str, GuideSection] = field(default_factory=dict, compare=False, repr=False)

    def find(self, path: str) -> GuideSection | None:
        return self._index.get(str(path or ""))

    def howto_callback(self) -> str:
        if any(section.id == HOWTO_SECTION_ID for section in self.sections):
            return cb.guide_page(HOWTO_SECTION_ID)
        return cb.GUIDE

    def root_text(self) -> str:
        parts = [self.title, self.intro]
        if self.html:
            parts[0] = f"<b>{html.escape(self.title)}</b>" if self.title else ""
        return self._with_footer("\n\n".join(part for part in parts if part.strip()))

    def page_text(self, section: GuideSection) -> str:
        header = f"<b>{html.escape(section.button)}</b>" if self.html else section.button
        return self._with_footer("\n\n".join(part for part in [header, section.text] if part.strip()))

    def _with_footer(self, body: str) -> str:
        if not self.footer.strip():
            return body
        return f"{body}\n\n{self.footer}"


def _index_sections(sections: tuple[GuideSection, ...]) -> dict[str, GuideSection]:
    index: dict[str, GuideSection] = {}
    for section in sections:
        index[section.path] = section
        index.update(_index_sections(section.children))
    return index


def _make_guide(**kwargs: Any) -> Guide:
    sections = kwargs.get("sections", ())
    return Guide(**kwargs, _index=_index_sections(sections))


# ------------------------------------------------------------- validation ---


def _optional_text(data: dict, key: str, where: str) -> str:
    value = data.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise GuideError(f"{where}.{key} must be a string")
    return value.strip()


def _parse_sections(raw: object, *, depth: int, parent_path: str, seen: set[str], where: str) -> tuple[GuideSection, ...]:
    if raw is None:
        return ()
    if depth > MAX_DEPTH:
        raise GuideError(f"{where}: nesting deeper than {MAX_DEPTH} levels is not allowed")
    if not isinstance(raw, list):
        raise GuideError(f"{where} must be a list")

    sections: list[GuideSection] = []
    for index, item in enumerate(raw):
        item_where = f"{where}[{index}]"
        if not isinstance(item, dict):
            raise GuideError(f"{item_where} must be a mapping")
        unknown = set(item) - _SECTION_KEYS
        if unknown:
            raise GuideError(f"{item_where}: unknown keys {sorted(unknown)}")
        section_id = item.get("id")
        if not isinstance(section_id, str) or not SECTION_ID_RE.fullmatch(section_id):
            raise GuideError(f"{item_where}.id must match [a-z0-9_-]{{1,32}}")
        if section_id in seen:
            raise GuideError(f"{item_where}.id {section_id!r} is not unique")
        seen.add(section_id)
        button = item.get("button")
        if not isinstance(button, str) or not button.strip():
            raise GuideError(f"{item_where}.button must be a non-empty string")
        if len(button.strip()) > MAX_BUTTON_LENGTH:
            raise GuideError(f"{item_where}.button is longer than {MAX_BUTTON_LENGTH} characters")
        path = f"{parent_path}.{section_id}" if parent_path else section_id
        if not cb.fits(cb.guide_page(path)):
            raise GuideError(f"{item_where}: callback for path {path!r} exceeds {cb.CALLBACK_DATA_LIMIT} bytes")
        text = _optional_text(item, "text", item_where)
        children = _parse_sections(
            item.get("sections"),
            depth=depth + 1,
            parent_path=path,
            seen=seen,
            where=f"{item_where}.sections",
        )
        if not text and not children:
            raise GuideError(f"{item_where} needs text or sections")
        sections.append(GuideSection(id=section_id, path=path, button=button.strip(), text=text, children=children))
    return tuple(sections)


def parse_structured(data: object) -> Guide:
    if not isinstance(data, dict):
        raise GuideError("guide must be a mapping")
    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise GuideError(f"unknown top-level keys {sorted(unknown)}")
    version = data.get("version")
    if version != GUIDE_VERSION or isinstance(version, bool):
        raise GuideError(f"version must be {GUIDE_VERSION}")
    title = _optional_text(data, "title", "guide") or texts.GUIDE_DEFAULT_TITLE
    intro = _optional_text(data, "intro", "guide")
    footer = _optional_text(data, "footer", "guide")
    sections = _parse_sections(data.get("sections"), depth=1, parent_path="", seen=set(), where="sections")
    if not intro and not sections:
        raise GuideError("guide needs an intro or sections")
    return _make_guide(title=title, intro=intro, sections=sections, footer=footer, html=True)


def plain_guide(text: str) -> Guide:
    body = str(text or "").strip() or texts.GUIDE_EMPTY
    return _make_guide(title="", intro=body, sections=(), footer="", html=False)


def telegram_html_ok(text: str) -> bool:
    """True when ``text`` uses only Telegram-supported, balanced HTML tags."""

    class _Checker(HTMLParser):
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self.stack: list[str] = []
            self.ok = True

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            if tag not in _ALLOWED_TAGS:
                self.ok = False
            self.stack.append(tag)

        def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            self.ok = False

        def handle_endtag(self, tag: str) -> None:
            if not self.stack or self.stack[-1] != tag:
                self.ok = False
                return
            self.stack.pop()

    checker = _Checker()
    try:
        checker.feed(str(text or ""))
        checker.close()
    except Exception:  # noqa: BLE001
        return False
    return checker.ok and not checker.stack


# ---------------------------------------------------------------- loading ---


def default_guide_text() -> str:
    configured = str(ctx.settings.bot_guide_message or "").strip()
    if configured in _PLACEHOLDER_MESSAGES:
        return str(Settings.model_fields["bot_guide_message"].default).strip()
    return configured


_cache: dict[str, tuple[tuple[int, int], Guide]] = {}


def _read_file(path: Path) -> str:
    try:
        stat = path.stat()
    except FileNotFoundError as exc:
        raise GuideError(f"guide file not found: {path}") from exc
    if stat.st_size > MAX_GUIDE_BYTES:
        raise GuideError(f"guide file is larger than {MAX_GUIDE_BYTES} bytes")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise GuideError(f"cannot read guide file: {type(exc).__name__}") from exc


def _parse_file(path: Path) -> Guide:
    raw = _read_file(path)
    suffix = path.suffix.lower()
    if suffix not in STRUCTURED_SUFFIXES:
        return plain_guide(raw)
    try:
        data = json.loads(raw) if suffix == ".json" else yaml.safe_load(raw)
    except (ValueError, yaml.YAMLError) as exc:
        raise GuideError(f"cannot parse guide file: {type(exc).__name__}") from exc
    return parse_structured(data)


def load_guide() -> Guide:
    """Load the configured guide. Raises GuideError on a missing/invalid file."""

    configured_path = str(ctx.settings.bot_guide_path or "").strip()
    if not configured_path:
        return plain_guide(default_guide_text())
    path = Path(configured_path)
    try:
        stat = path.stat()
        key = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        key = None
    cached = _cache.get(configured_path)
    if key is not None and cached is not None and cached[0] == key:
        return cached[1]
    guide = _parse_file(path)
    if key is not None:
        _cache[configured_path] = (key, guide)
    return guide


def try_load_guide() -> Guide | None:
    try:
        return load_guide()
    except GuideError as exc:
        logger.error("bot_guide_invalid error=%s", exc)
        return None


def howto_callback() -> str:
    guide = try_load_guide()
    return guide.howto_callback() if guide is not None else cb.GUIDE
