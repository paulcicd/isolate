"""Web SSH and replay page builders; authorization stays at their route boundary.

Only public resource labels and a CSRF token enter the page. Bearer credentials,
one-use connection tickets and terminal contents never enter persisted UI state.
"""

import html
import json
import re


_WORDS = {
    "ru": {
        "terminal": "Рабочий терминал", "eyebrow": "ISOLATE · SSH",
        "description": "Несколько подключений в одном пространстве. Каждый канал проверяет ваши актуальные права.",
        "new_tab": "Новая вкладка", "split_columns": "Разделить рядом", "split_rows": "Разделить сверху и снизу",
        "search": "Поиск в выводе", "settings": "Настройки", "shortcuts": "Горячие клавиши",
        "empty_title": "Выберите ресурс для подключения", "empty_text": "Откройте новую вкладку или разделите экран для работы с несколькими серверами.",
        "resources": "Подключиться к ресурсу", "resource_search": "Имя, проект или ID ресурса", "cancel": "Отмена", "close": "Закрыть",
        "find": "Найти в терминале", "previous": "Предыдущее", "next": "Следующее",
        "font_size": "Размер шрифта", "font_family": "Шрифт", "theme": "Тема", "dark": "Тёмная", "light": "Светлая",
        "scrollback": "Строк в истории", "save": "Сохранить", "paste_title": "Проверка перед вставкой",
        "paste_explanation": "Многострочный или большой текст может сразу выполнить команды. Проверьте содержимое и подтвердите вставку в выбранный терминал.",
        "paste_confirm": "Вставить в терминал", "paste_preview": "Текст для вставки",
        "welcome": "Терминал готов", "privacy": "Содержимое терминала и билеты подключения не сохраняются в браузере.",
        "shortcut_help": "Ctrl/⌘ + Shift + T — вкладка · Ctrl/⌘ + Shift + D — разделение · Ctrl/⌘ + Shift + F — поиск · Alt + 1…8 — вкладка. Escape закрывает окно. Ctrl + C остаётся командой терминала.",
        "replay": "Запись сессии", "replay_description": "Просматривайте вывод, переходите к моментам записи и сохраняйте личные закладки.",
        "play": "Воспроизвести", "pause": "Пауза", "reset": "В начало", "speed": "Скорость", "timeline": "Позиция в записи",
        "details": "История сессий", "download": "Скачать JSON", "bookmarks": "Закладки", "add_bookmark": "Добавить закладку",
        "bookmark_label": "Название закладки", "bookmark_placeholder": "Что происходит в этот момент?", "readable": "Текстовый вид",
    },
    "en": {
        "terminal": "Terminal workspace", "eyebrow": "ISOLATE · SSH",
        "description": "Keep several connections together. Every channel checks your current access.",
        "new_tab": "New tab", "split_columns": "Split side by side", "split_rows": "Split top and bottom",
        "search": "Search output", "settings": "Settings", "shortcuts": "Keyboard shortcuts",
        "empty_title": "Choose a resource to connect", "empty_text": "Open a tab or split the screen to work with several servers.",
        "resources": "Connect to a resource", "resource_search": "Resource name, project or ID", "cancel": "Cancel", "close": "Close",
        "find": "Find in terminal", "previous": "Previous", "next": "Next", "font_size": "Font size", "font_family": "Font",
        "theme": "Theme", "dark": "Dark", "light": "Light", "scrollback": "Scrollback lines", "save": "Save",
        "paste_title": "Review before pasting", "paste_explanation": "Multiline or large text can execute commands immediately. Review it and confirm the paste into the selected terminal.",
        "paste_confirm": "Paste into terminal", "paste_preview": "Text to paste", "welcome": "Terminal ready",
        "privacy": "Terminal contents and connection tickets are not saved in the browser.",
        "shortcut_help": "Ctrl/⌘ + Shift + T — tab · Ctrl/⌘ + Shift + D — split · Ctrl/⌘ + Shift + F — find · Alt + 1…8 — tab. Escape closes dialogs. Ctrl + C remains a terminal command.",
        "replay": "Session recording", "replay_description": "Review output, jump through the recording and keep personal bookmarks.",
        "play": "Play", "pause": "Pause", "reset": "Start", "speed": "Speed", "timeline": "Recording position",
        "details": "Session history", "download": "Download JSON", "bookmarks": "Bookmarks", "add_bookmark": "Add bookmark",
        "bookmark_label": "Bookmark label", "bookmark_placeholder": "What happens at this moment?", "readable": "Readable text",
    },
}


def _language(language):
    return "ru" if str(language).lower().startswith("ru") else "en"


def _json(value):
    # A label containing </script> must remain inert even in a JSON script.
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _public_resource(resource):
    if not resource:
        return None
    identifier = resource.get("id") or resource.get("host_id") or resource.get("server_id")
    if type(identifier) not in (str, int) or not re.fullmatch(r"[0-9]{1,32}", str(identifier)):
        raise ValueError("a numeric resource ID is required")
    return {"id": str(identifier), "name": str(resource.get("name") or resource.get("server_name") or identifier)[:200],
            "project": str(resource.get("project") or resource.get("project_name") or "")[:200], "protocol": "ssh"}


def _asset_header():
    return '<link rel="stylesheet" href="/static/vendor/xterm/xterm.css"><link rel="stylesheet" href="/static/terminal-workspace.css">'


def render_terminal_workspace(initial_resource=None, csrf_token="", language="ru", preferences=None):
    language = _language(language)
    w = {key: html.escape(value, quote=True) for key, value in _WORDS[language].items()}
    resource = _public_resource(initial_resource)
    # Restrict data passed into the page even if a caller supplies a full profile.
    terminal = (preferences or {}).get("terminal") or {}
    settings = {key: terminal[key] for key in ("font_size", "font_family", "theme", "scrollback", "paste_threshold") if key in terminal}
    config = {"language": language, "csrf": str(csrf_token), "initialResource": resource, "preferences": settings}
    body = """
<section id="terminal-workspace" class="terminal-workspace" aria-labelledby="terminal-title">
  <header class="tw-header"><div><p class="tw-eyebrow">{eyebrow}</p><h1 id="terminal-title">{terminal}</h1><p class="tw-description">{description}</p></div>
    <a class="tw-back" href="/workspace">← {resources}</a></header>
  <div class="tw-toolbar" role="toolbar" aria-label="{terminal}">
    <button type="button" class="tw-primary" data-action="new-tab">＋ {new_tab}</button>
    <button type="button" data-action="split-columns" title="Ctrl/⌘ + Shift + D">▥ {split_columns}</button>
    <button type="button" data-action="split-rows">▤ {split_rows}</button>
    <span class="tw-toolbar-spacer"></span><button type="button" data-action="search">⌕ {search}</button>
    <button type="button" data-action="settings">{settings}</button><button type="button" data-action="shortcuts" aria-label="{shortcuts}">?</button>
  </div>
  <div class="tw-tabs" role="tablist" aria-label="{terminal}" id="tw-tabs"></div>
  <div id="tw-search" class="tw-search" hidden><label for="tw-search-input">{find}</label><input id="tw-search-input" type="search" autocomplete="off" maxlength="200">
    <button type="button" data-action="find-previous" aria-label="{previous}">↑</button><button type="button" data-action="find-next" aria-label="{next}">↓</button>
    <output id="tw-search-count" aria-live="polite"></output><button type="button" data-action="hide-search" aria-label="{close}">×</button></div>
  <p id="tw-notice" class="tw-notice" role="status" aria-live="polite"></p>
  <div id="tw-stage" class="tw-stage"><div class="tw-empty"><span class="tw-empty-icon" aria-hidden="true">⌘</span><h2>{empty_title}</h2><p>{empty_text}</p><button type="button" class="tw-primary" data-action="new-tab">{new_tab}</button></div></div>
  <footer class="tw-footer"><span>Ctrl/⌘ + Shift + T · Ctrl/⌘ + Shift + F</span><span>{privacy}</span></footer>
  <dialog id="tw-resource-dialog" class="tw-dialog"><form method="dialog"><header><h2>{resources}</h2><button value="cancel" aria-label="{close}">×</button></header></form>
    <label class="tw-sr-only" for="tw-resource-search">{resource_search}</label><input id="tw-resource-search" type="search" placeholder="{resource_search}" autocomplete="off" maxlength="200">
    <div id="tw-resource-list" class="tw-resource-list" role="list"></div><p id="tw-resource-state" role="status"></p></dialog>
  <dialog id="tw-settings-dialog" class="tw-dialog"><form id="tw-settings-form"><header><h2>{settings}</h2><button type="button" data-close-dialog aria-label="{close}">×</button></header>
    <label>{font_size}<input name="font_size" type="number" min="10" max="24" required value="14"></label>
    <label>{font_family}<select name="font_family"><option value="ui-monospace">System monospace</option><option value="monospace">Monospace</option><option value="Menlo">Menlo</option><option value="Consolas">Consolas</option></select></label>
    <label>{theme}<select name="theme"><option value="dark">{dark}</option><option value="light">{light}</option></select></label>
    <label>{scrollback}<input name="scrollback" type="number" min="1000" max="20000" step="1000" required value="5000"></label>
    <footer><button type="button" data-close-dialog>{cancel}</button><button class="tw-primary" type="submit">{save}</button></footer></form></dialog>
  <dialog id="tw-paste-dialog" class="tw-dialog"><form method="dialog"><header><h2>{paste_title}</h2><button value="cancel" aria-label="{close}">×</button></header>
    <p>{paste_explanation}</p><p id="tw-paste-target"></p><label class="tw-sr-only" for="tw-paste-preview">{paste_preview}</label><textarea id="tw-paste-preview" readonly spellcheck="false"></textarea>
    <footer><button value="cancel">{cancel}</button><button value="confirm" class="tw-primary">{paste_confirm}</button></footer></form></dialog>
  <dialog id="tw-shortcuts-dialog" class="tw-dialog"><form method="dialog"><header><h2>{shortcuts}</h2><button value="close" aria-label="{close}">×</button></header><p>{shortcut_help}</p></form></dialog>
</section>
""".format(**w)
    if resource:
        from isolate_explain_api import explanation_panel
        body += explanation_panel(resource['id'], 'ssh', russian=language == 'ru')
    return _asset_header() + body + '<script id="terminal-workspace-config" type="application/json">' + _json(config) + '</script><script type="module" src="/static/terminal-workspace.js"></script>'


def render_replay_workspace(connection_id, csrf_token="", language="ru", default_speed=1):
    identifier = str(connection_id)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier):
        raise ValueError("invalid recording ID")
    language = _language(language)
    w = {key: html.escape(value, quote=True) for key, value in _WORDS[language].items()}
    try:
        speed = float(default_speed)
    except (ValueError, TypeError):
        speed = 1
    if speed not in (0.5, 1, 2, 5):
        speed = 1
    body = """
<section id="terminal-replay" class="terminal-workspace tw-replay" aria-labelledby="replay-title">
  <header class="tw-header"><div><p class="tw-eyebrow">ISOLATE · REPLAY</p><h1 id="replay-title">{replay}</h1><p class="tw-description">{replay_description}</p></div><a class="tw-back" href="/me/history">{details} ↗</a></header>
  <div class="tw-toolbar" role="toolbar" aria-label="{replay}"><button id="tr-play" class="tw-primary">▶ {play}</button><button id="tr-pause">Ⅱ {pause}</button><button id="tr-reset">↺ {reset}</button>
    <label class="tw-inline-label">{speed}<select id="tr-speed"><option value="0.5">0.5×</option><option value="1">1×</option><option value="2">2×</option><option value="5">5×</option></select></label>
    <span class="tw-toolbar-spacer"></span><button id="tr-find-toggle">⌕ {search}</button><label class="tw-inline-label"><input id="tr-readable-toggle" type="checkbox">{readable}</label><a href="/replay/{identifier}.json" download>{download}</a></div>
  <div id="tr-find" class="tw-search" hidden><label for="tr-find-input">{find}</label><input id="tr-find-input" type="search" maxlength="200"><button id="tr-find-previous" aria-label="{previous}">↑</button><button id="tr-find-next" aria-label="{next}">↓</button><output id="tr-find-count" aria-live="polite"></output></div>
  <p id="tr-state" class="tw-notice" role="status" aria-live="polite"></p>
  <div class="tr-layout"><div class="tr-recording"><div id="tr-terminal" class="tw-emulator"></div><pre id="tr-readable" hidden></pre>
    <div class="tr-timeline"><label class="tw-sr-only" for="tr-scrubber">{timeline}</label><input id="tr-scrubber" type="range" min="0" max="0" step="0.01" value="0"><output id="tr-clock">0:00 / 0:00</output></div></div>
    <aside class="tr-bookmarks"><header><h2>{bookmarks}</h2></header><form id="tr-bookmark-form"><label for="tr-bookmark-label">{bookmark_label}</label><input id="tr-bookmark-label" type="text" maxlength="160" placeholder="{bookmark_placeholder}" required><button class="tw-primary" type="submit">＋ {add_bookmark}</button></form><ol id="tr-bookmark-list"></ol><p id="tr-bookmark-state" role="status"></p></aside></div>
</section>
""".format(identifier=identifier, **w)
    config = {"language": language, "csrf": str(csrf_token), "connectionId": identifier, "defaultSpeed": speed}
    return _asset_header() + body + '<script id="terminal-replay-config" type="application/json">' + _json(config) + '</script><script type="module" src="/static/terminal-replay.js"></script>'
