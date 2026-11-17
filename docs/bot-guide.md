# Bot guide

The bot shows a guide from the "📖 Инструкция" menu button and the `/guide`
command. Guide content is private: keep it in runtime storage on the server and
point `BOT_GUIDE_PATH` at it. The repository ships only a generic example,
[`deploy/examples/bot-guide.example.yaml`](../deploy/examples/bot-guide.example.yaml).

## Sources

`BOT_GUIDE_PATH` decides the format:

| Value | Result |
| --- | --- |
| empty | the `bot_guide_message` setting (built-in Russian default), one plain-text page |
| `*.yaml`, `*.yml`, `*.json` | structured guide with a page per section (below) |
| any other file | the file as one plain-text page |

The file is re-read when its modification time or size changes, so edits apply
without a restart. A missing or invalid file never crashes the bot: the error
is logged (`bot_guide_invalid`) and users see "Инструкция временно недоступна".

## Structured format

```yaml
version: 1                      # required, must be 1
title: "📖 Инструкция"          # optional, root page title
intro: "Вступление (HTML)."     # optional, root page text
sections:                       # top-level pages, shown as buttons on the root
  - id: quick                   # [a-z0-9_-]{1,32}, unique across the file
    button: "🚀 Быстрый старт"  # button text, plain, up to 64 characters
    text: "Текст страницы (HTML)."
  - id: apps
    button: "📲 Приложения"
    text: "Выбери своё устройство:"
    sections:                   # optional sub-pages; only one level of nesting
      - id: ios
        button: "iPhone / iPad"
        text: "..."
footer: "Строка внизу каждой страницы."  # optional
```

Rules:

- Nesting depth is at most 2: top-level sections may have `sections`, their
  children may not.
- Every section needs `text`, `sections`, or both.
- Section ids are unique in the whole file. A page is addressed by its path,
  for example `apps.ios`, and its button carries `g:<path>`; the whole value
  must fit Telegram's 64-byte callback limit, so keep nested ids short.
- Unknown keys are rejected so typos surface in the log instead of silently
  hiding content.
- A top-level section with id `apps` is special: the "📖 Как подключить" button
  sent with every set of connection settings opens it directly. Without it the
  button opens the guide root.

## Rendering

- `title`, `intro`, `text` and `footer` are owner-authored HTML in Telegram's
  subset (`b`, `i`, `u`, `s`, `a`, `code`, `pre`, `blockquote`, `tg-spoiler`, ...).
  Button text is escaped. A page with unsupported or unbalanced tags, or one
  Telegram rejects, is shown as plain text with the tags removed.
- Pages longer than 3900 characters are split: the first part replaces the
  current screen, the rest arrive as new messages; the buttons are attached to
  the last part.
- Every page has "↩️ Назад" (parent page or the guide root) and "🏠 Меню".

## Welcome text

The two-step welcome keeps its version gate (`BOT_WELCOME_VERSION`). Release
4.2.0 rewords the built-in welcome and the rules screen for Tracegate 4 but does
not add obligations (the obsolete "active device" rule is dropped), so the
default version stays `tracegate-3.0.0-ui-v1` and users who already accepted
are not asked again. Bump `BOT_WELCOME_VERSION` in the private environment to
force everyone through the welcome once more.
