"""Boundary checks for the terminal page builders used by authorized routes."""

from html.parser import HTMLParser
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
from isolate_terminal_ui import render_replay_workspace, render_terminal_workspace


class PageParser(HTMLParser):
    def __init__(self, content):
        super().__init__()
        self.scripts, self.elements = [], []
        self.current_script = None
        self.feed(content)

    def handle_starttag(self, tag, attributes):
        values = dict(attributes)
        self.elements.append((tag, values))
        if tag == "script":
            self.current_script = {**values, "content": ""}
            self.scripts.append(self.current_script)

    def handle_endtag(self, tag):
        if tag == "script":
            self.current_script = None

    def handle_data(self, data):
        if self.current_script is not None:
            self.current_script["content"] += data

    def configuration(self, identifier):
        return json.loads(next(script["content"] for script in self.scripts if script.get("id") == identifier))


class TerminalWorkspaceTest(unittest.TestCase):
    def test_initial_resource_whitelist_excludes_credentials_and_unrelated_preferences(self):
        page = render_terminal_workspace({"server_id": "42", "server_name": "payments", "project_name": "prod",
            "password": "private-upstream-secret", "ssh_key": "private-key", "raw_claims": {"token": "private-bearer"}},
            csrf_token="csrf-fixture", preferences={"favorites": ["secret-name"], "raw_claims": {"token": "private-token"},
                "terminal": {"font_size": 16, "font_family": "Menlo", "token": "nested-private-token"}})
        config = PageParser(page).configuration("terminal-workspace-config")
        self.assertEqual(config["initialResource"], {"id": "42", "name": "payments", "project": "prod", "protocol": "ssh"})
        self.assertEqual(config["preferences"], {"font_size": 16, "font_family": "Menlo"})
        self.assertEqual(config["csrf"], "csrf-fixture")
        for private in ("private-upstream-secret", "private-key", "private-bearer", "secret-name", "private-token", "nested-private-token"):
            self.assertNotIn(private, page)

    def test_script_closing_labels_cannot_create_html_elements_or_scripts(self):
        attack = '</script><img src=x onerror="alert(1)"><script>'
        page = render_terminal_workspace({"id": "1", "name": attack, "project": attack}, csrf_token=attack)
        parser = PageParser(page)
        self.assertEqual(len(parser.scripts), 2)
        self.assertFalse(any(tag == "img" for tag, _ in parser.elements))
        config = parser.configuration("terminal-workspace-config")
        self.assertEqual(config["initialResource"]["name"], attack)
        self.assertEqual(config["csrf"], attack)
        self.assertFalse(any(key.startswith("on") for _, attributes in parser.elements for key in attributes))

    def test_invalid_host_cannot_be_encoded_in_workspace_configuration(self):
        for identifier in ("../../admin", "1?token=x", "<svg>", True, -1, "9" * 33):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                render_terminal_workspace({"id": identifier})

    def test_empty_workspace_does_not_authorize_or_create_a_ticket_in_html(self):
        page = render_terminal_workspace()
        config = PageParser(page).configuration("terminal-workspace-config")
        self.assertIsNone(config["initialResource"])
        self.assertNotIn('data-ticket=', page)
        self.assertNotIn('Bearer ', page)
        self.assertIn('data-action="new-tab"', page)
        self.assertIn('data-action="split-columns"', page)
        self.assertIn('data-action="split-rows"', page)

    def test_localized_controls_and_accessible_paste_review_are_present(self):
        russian = render_terminal_workspace(language="ru-RU")
        english = render_terminal_workspace(language="en")
        self.assertIn("Проверка перед вставкой", russian)
        self.assertIn("Review before pasting", english)
        parsed = PageParser(russian)
        preview = next(attrs for tag, attrs in parsed.elements if attrs.get("id") == "tw-paste-preview")
        self.assertIn("readonly", preview)
        self.assertTrue(any(attrs.get("role") == "tablist" for _, attrs in parsed.elements))
        self.assertIn("aria-live=\"polite\"", russian)

    def test_assets_exist_and_executable_code_is_external(self):
        for page in (render_terminal_workspace(), render_replay_workspace("connection-1")):
            parser = PageParser(page)
            for script in parser.scripts:
                if script.get("type") != "application/json":
                    self.assertEqual(script["type"], "module")
                    self.assertFalse(script["content"].strip())
                    path = Path(__file__).resolve().parents[1] / "shared" / script["src"].lstrip("/")
                    self.assertTrue(path.is_file(), path)

    def test_replay_uses_recording_identifier_and_personal_bookmark_controls(self):
        page = render_replay_workspace("recording_123", csrf_token="csrf", language="en", default_speed=2)
        config = PageParser(page).configuration("terminal-replay-config")
        self.assertEqual(config, {"language": "en", "csrf": "csrf", "connectionId": "recording_123", "defaultSpeed": 2.0})
        self.assertIn('href="/replay/recording_123.json"', page)
        self.assertIn('id="tr-bookmark-form"', page)
        self.assertIn('id="tr-scrubber"', page)
        self.assertIn('maxlength="160"', page)
        self.assertNotIn("connection tickets", page)

    def test_replay_rejects_path_injection_and_normalizes_speed(self):
        for identifier in ("../other", "id?token=x", "<script>", "x" * 129, ""):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                render_replay_workspace(identifier)
        for speed in (float("inf"), float("nan"), -1, "<script>"):
            page = render_replay_workspace("safe-id", default_speed=speed)
            self.assertEqual(PageParser(page).configuration("terminal-replay-config")["defaultSpeed"], 1)


if __name__ == "__main__":
    unittest.main()
