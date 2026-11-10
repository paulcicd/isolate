"""Workspace navigation/authentication and safe browser bootstrap boundaries."""

import copy
import json
from pathlib import Path
import re
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))

from flask import Flask, session
from isolate_config import DEFAULT_CONFIG
from isolate_workspace_ui import administration_links, register_workspace_routes, WORDS


class WorkspaceUITest(unittest.TestCase):
    def setUp(self):
        self.config = copy.deepcopy(DEFAULT_CONFIG)
        self.config["api"]["enabled"] = True
        self.config["dashboard"].update(self_service_enabled=True, admin_groups=["Platform"])
        self.current = {"username": "alice", "keycloak_sub": "stable-alice", "groups": ["Support"]}
        self.app = Flask(__name__, static_folder=str(ROOT / "shared" / "static"))
        self.app.config.update(TESTING=True, SECRET_KEY="workspace-test-only")

        @self.app.before_request
        def verified_session_fixture():
            if self.current:
                session["identity"] = dict(self.current)
            else:
                session.pop("identity", None)

        register_workspace_routes(self.app, self.config, lambda: self.current, lambda: "fixture-csrf")
        self.client = self.app.test_client()

    def bootstrap(self, response):
        text = response.get_data(as_text=True)
        payload = re.search(r'<script type="application/json" id="workspace-config">(.*?)</script>', text, re.S)
        self.assertIsNotNone(payload)
        return json.loads(payload.group(1))

    def test_signed_in_employee_gets_all_protocol_search_without_admin_tools(self):
        response = self.client.get("/workspace")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        for protocol in ("SSH", "HTTP", "Kubernetes", "PostgreSQL", "MySQL"):
            self.assertIn(protocol, text)
        self.assertIn('href="/static/workspace-catalog.css"', text)
        self.assertIn('src="/static/workspace-catalog.js"', text)
        self.assertIn('id="workspace-query"', text)
        self.assertIn('aria-live="polite"', text)
        self.assertNotIn('href="/workspace/admin"', text)
        bootstrap = self.bootstrap(response)
        self.assertEqual(bootstrap["csrf"], "fixture-csrf")
        self.assertTrue(bootstrap["enabled"])
        self.assertEqual(bootstrap["resources_url"], "/api/v1/workspace/resources")
        self.assertNotIn("bearer", json.dumps(bootstrap).lower())

    def test_anonymous_and_unbound_identities_cannot_use_workspace(self):
        self.current = None
        for path in ("/workspace", "/workspace/admin"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["Location"], "/login")
        self.current = {"username": "alice", "groups": ["Support"]}
        self.assertEqual(self.client.get("/workspace").status_code, 403)

    def test_self_service_disable_and_group_scope_are_enforced(self):
        self.config["dashboard"]["self_service_groups"] = ["Engineers"]
        self.assertEqual(self.client.get("/workspace").status_code, 403)
        self.current["groups"] = ["Engineers"]
        self.assertEqual(self.client.get("/workspace").status_code, 200)
        self.config["dashboard"]["self_service_enabled"] = False
        self.assertEqual(self.client.get("/workspace").status_code, 403)

    def test_management_space_rechecks_current_role_and_limits_navigation(self):
        self.assertEqual(self.client.get("/workspace/admin").status_code, 403)
        self.config["dashboard"]["self_service_enabled"] = False
        self.config["dashboard"]["role_bindings"] = [{"group": "Support", "role": "inventory-operator", "projects": ["prod"]}]
        response = self.client.get("/workspace/admin")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn("Resource inventory", text)
        self.assertNotIn('href="/grants"', text)
        self.assertNotIn('href="/users"', text)
        self.assertNotIn('href="/history"', text)
        self.assertNotIn('href="/access"', text)
        self.config["dashboard"]["role_bindings"] = []
        self.assertEqual(self.client.get("/workspace/admin").status_code, 403)

    def test_platform_administrator_gets_management_tools(self):
        self.current["groups"] = ["Platform"]
        self.config["dashboard"]["self_service_enabled"] = False
        response = self.client.get("/workspace/admin")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        for path in ("/inventory", "/grants", "/packages", "/jobs", "/users", "/policy/gitops"):
            self.assertIn('href="' + path + '"', text)
        self.assertIn("Platform administrator", text)
        self.assertIn("Connection policies apply separately", text)

    def test_russian_locale_and_theme_use_the_existing_shared_shell(self):
        response = self.client.get("/workspace?lang=ru")
        text = response.get_data(as_text=True)
        self.assertIn('<html lang="ru">', text)
        self.assertIn("Куда подключимся?", text)
        self.assertIn("Избранное", text)
        self.assertIn('class="theme-switch"', text)
        self.assertEqual(self.bootstrap(response)["locale"], "ru")
        self.current["groups"] = ["Platform"]
        text = self.client.get("/workspace/admin").get_data(as_text=True)
        self.assertIn("Ваше пространство управления", text)

    def test_untrusted_filters_and_identity_cannot_escape_html_or_json_script(self):
        attack = '</script><script>alert("resource")</script>'
        self.current["username"] = attack
        response = self.client.get("/workspace", query_string={"q": attack, "project": attack})
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertNotIn(attack, text)
        self.assertIn("&lt;/script&gt;", text)
        bootstrap = self.bootstrap(response)
        self.assertEqual(bootstrap["initial"]["q"], attack)
        self.assertEqual(bootstrap["initial"]["project"], attack)

    def test_route_rendering_does_not_fetch_or_embed_inventory(self):
        with mock.patch("isolate_inventory.list_hosts", side_effect=AssertionError("page must not enumerate inventory")):
            response = self.client.get("/workspace")
        bootstrap = self.bootstrap(response)
        self.assertNotIn("resources", bootstrap)
        self.assertNotIn("identity", bootstrap)
        for path in ("/static/workspace-catalog.js", "/static/workspace-catalog.css"):
            with self.client.get(path) as asset:
                self.assertEqual(asset.status_code, 200)

    def test_disabled_api_is_explicit_in_bootstrap(self):
        self.config["api"]["enabled"] = False
        response = self.client.get("/workspace")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.bootstrap(response)["enabled"])
        self.assertIn("not enabled", self.bootstrap(response)["labels"]["no_api"])

    def test_navigation_entry_permissions_do_not_expand_a_scoped_role(self):
        self.config["dashboard"]["role_bindings"] = [{"group": "Support", "role": "approver", "projects": ["prod"]}]
        urls = {row["url"] for row in administration_links(self.current, self.config, WORDS["en"])}
        self.assertEqual(urls, {"/inventory", "/access", "/session-approvals", "/workspace/governance"})


if __name__ == "__main__":
    unittest.main()
