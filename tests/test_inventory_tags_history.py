import fnmatch
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "shared")))

from isolate_inventory import (
    HostValidationError,
    bulk_update_hosts,
    create_host,
    get_host,
    list_hosts,
    normalize_host,
    normalize_tags,
    update_host,
)
from isolate_service_discovery import (
    DISCOVERY_HISTORY_LIMIT,
    get_discovery,
    get_discovery_history,
    save_discovery,
)


class MemoryRedis:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    def incr(self, key):
        value = int(self.values.get(key, 0)) + 1
        self.values[key] = value
        return value

    def keys(self, pattern):
        return [key for key in self.values if fnmatch.fnmatchcase(key, pattern)]


class InventoryTagsTest(unittest.TestCase):
    def setUp(self):
        self.redis = MemoryRedis()
        self.host = create_host(self.redis, {
            "project_name": "payments-prod", "server_name": "api.example.org",
            "server_ip": "192.0.2.1", "server_user": "support",
            "tags": {"env": "prod", "owner": "payments"},
        })

    def test_tags_roundtrip_and_legacy_host_defaults(self):
        self.assertEqual(get_host(self.redis, self.host["server_id"])["tags"], {"env": "prod", "owner": "payments"})
        self.assertEqual(normalize_host({})["tags"], {})
        self.assertEqual(self.host["tags_display"], "env=prod, owner=payments")
        self.assertEqual(normalize_tags(self.host["tags_display"]), self.host["tags"])
        self.assertEqual(normalize_tags(" owner=payments, env=prod\nregion=nsk "),
                         {"env": "prod", "owner": "payments", "region": "nsk"})

    def test_exact_tag_selectors_are_combined_with_project_and_query(self):
        self.assertEqual(len(list_hosts(self.redis, tags=["env=prod", "owner=payments"])), 1)
        self.assertEqual(list_hosts(self.redis, tags=["env=pro"]), [])
        self.assertEqual(list_hosts(self.redis, tags=["env=prod", "region=nsk"]), [])
        self.assertEqual(list_hosts(self.redis, project="other", tags=["env=prod"]), [])
        self.assertEqual(len(list_hosts(self.redis, query="owner=payments")), 1)
        self.assertEqual(list_hosts(self.redis, query="other", tags=["env=prod"]), [])

    def test_tag_replacement_bulk_update_clear_and_revision(self):
        before = self.host["_revision"]
        updated = update_host(self.redis, self.host["server_id"], {"tags": ["region=nsk"]}, expected_revision=before)
        self.assertEqual(updated["tags"], {"region": "nsk"})
        self.assertNotEqual(updated["_revision"], before)
        with self.assertRaises(HostValidationError):
            update_host(self.redis, self.host["server_id"], {"tags": {}}, expected_revision=before)
        bulk_update_hosts(self.redis, [self.host["server_id"]], {"tags": {}})
        self.assertEqual(get_host(self.redis, self.host["server_id"])["tags"], {})

    def test_invalid_selectors_fail_instead_of_expanding_fleet(self):
        for invalid in (["env"], ["env=prod", "env=stage"], {"": "prod"}, {"env": ""},
                        {"env": "prod\x00"}, {"env": "prod,critical"}, {"env": 1}, {"x" * 65: "prod"}, {"env": "x" * 257}, 123):
            with self.subTest(invalid=invalid), self.assertRaises(HostValidationError):
                list_hosts(self.redis, tags=invalid)

    def test_invalid_bulk_tags_do_not_write_hosts(self):
        before = dict(self.redis.values)
        with self.assertRaises(HostValidationError):
            bulk_update_hosts(self.redis, [self.host["server_id"]], {"tags": ["env=prod", "env=stage"]})
        self.assertEqual(self.redis.values, before)


class ServiceChangeHistoryTest(unittest.TestCase):
    def setUp(self):
        self.redis = MemoryRedis()

    def save(self, services, checked_at):
        return save_discovery(self.redis, {
            "host_id": "10001", "ok": True, "services": services,
            "checked_at": checked_at, "attempted_at": checked_at,
        })

    def test_baseline_and_real_changes_are_distinct(self):
        self.save(["nginx.service", "ssh.service"], 100)
        baseline = get_discovery_history(self.redis, "10001")[0]
        self.assertTrue(baseline["baseline"])
        self.assertEqual(baseline["added"], [])
        self.assertEqual(baseline["removed"], [])
        self.save(["postgresql.service", "ssh.service"], 200)
        history = get_discovery_history(self.redis, "10001")
        self.assertEqual([event["checked_at"] for event in history], [200, 100])
        self.assertEqual(history[0]["added"], ["postgresql.service"])
        self.assertEqual(history[0]["removed"], ["nginx.service"])
        self.assertFalse(history[0]["baseline"])

    def test_unchanged_success_is_not_a_change_and_clears_failure(self):
        self.save(["ssh.service"], 100)
        save_discovery(self.redis, {"host_id": "10001", "ok": False, "error": "timeout", "attempted_at": 150})
        saved = self.save(["ssh.service"], 200)
        self.assertEqual(len(get_discovery_history(self.redis, "10001")), 1)
        self.assertEqual(saved["checked_at"], 200)
        self.assertNotIn("error", saved)

    def test_failure_cannot_replace_last_success_or_forge_changes(self):
        self.save(["ssh.service"], 100)
        saved = save_discovery(self.redis, {
            "host_id": "10001", "ok": False, "services": [], "checked_at": 200,
            "history": [], "attempted_at": 200, "error": "timeout",
        })
        self.assertEqual(saved["services"], ["ssh.service"])
        self.assertEqual(saved["checked_at"], 100)
        self.assertEqual(len(saved["history"]), 1)
        changed = self.save([], 300)
        self.assertEqual(changed["history"][-1]["removed"], ["ssh.service"])
        self.assertEqual(changed["history"][-1]["added"], [])

    def test_history_is_bounded_and_uses_existing_backup_key(self):
        for index in range(DISCOVERY_HISTORY_LIMIT + 8):
            self.save(["service{}.service".format(index)], index + 1)
        self.assertEqual(len(get_discovery_history(self.redis, "10001", limit=1000)), DISCOVERY_HISTORY_LIMIT)
        self.assertEqual(len(get_discovery_history(self.redis, "10001", limit=3)), 3)
        self.assertEqual(get_discovery_history(self.redis, "10001", limit=0), [])
        self.assertEqual(list(self.redis.values), ["host_services_10001"])
        self.assertEqual(len(json.loads(self.redis.values["host_services_10001"])["history"]), DISCOVERY_HISTORY_LIMIT)

    def test_upgrade_compares_against_legacy_snapshot(self):
        self.redis.set("host_services_10001", json.dumps({"host_id": "10001", "ok": True, "services": ["ssh.service"], "checked_at": 100}))
        self.save(["ssh.service", "nginx.service"], 200)
        event = get_discovery_history(self.redis, "10001")[0]
        self.assertFalse(event["baseline"])
        self.assertEqual(event["added"], ["nginx.service"])
        self.assertEqual(get_discovery(self.redis, "10001")["services"], ["nginx.service", "ssh.service"])


class SelfServiceLocaleTest(unittest.TestCase):
    def test_history_form_localizes_labels_without_changing_filters(self):
        from isolate_self_service import history_form
        args = {"q": '<script>"', "result": "failure", "limit": "15"}
        english = history_form(args, locale="en")
        russian = history_form(args, locale="ru")
        self.assertIn("All results", english)
        self.assertIn("Все результаты", russian)
        self.assertNotIn("All results", russian)
        for form in (english, russian):
            self.assertIn('name="since"', form)
            self.assertIn('name="until"', form)
            self.assertIn('value="failure" selected', form)
            self.assertIn('&lt;script&gt;&quot;', form)
        self.assertNotIn('name="user"', history_form(args, include_user=False, locale="ru"))

    def test_self_service_uses_session_locale_and_explicit_access_timezone(self):
        try:
            from flask import Flask
        except ImportError:
            self.skipTest("Flask is unavailable")
        import isolate_web as web
        from isolate_self_service import register_self_service
        redis = MemoryRedis()
        redis.set("access_request_1", json.dumps({
            "id": "1", "requester": "alice", "requester_sub": "alice-sub", "status": "approved",
            "project": "prod", "remote_user": "support", "starts_at": 1794016800, "expires_at": 1794020400,
        }))
        identity = {"username": "alice", "keycloak_sub": "alice-sub", "groups": []}
        with tempfile.TemporaryDirectory() as logs:
            config = {"dashboard": {"default_locale": "en", "self_service_enabled": True},
                      "logging": {"base_path": logs}}
            app = Flask(__name__)
            app.secret_key = "test-locale-session-key"
            register_self_service(app, config, lambda: identity, lambda: "csrf", lambda: None, mock.Mock(), mock.Mock())
            with mock.patch.object(web, "redis_client", return_value=redis), \
                 mock.patch.object(web, "_html", side_effect=lambda title, body, **kwargs: body):
                client = app.test_client()
                russian = client.get("/me/access?lang=ru").get_data(as_text=True)
                self.assertIn("<h1>Мои заявки</h1>", russian)
                self.assertIn("Запросить продление", russian)
                self.assertNotIn("My requests /", russian)
                self.assertIn(web._format_access_time(1794016800), russian)
                self.assertIn("+00:00", russian)
                self.assertIn('<input type="hidden" name="action" value="renew">', russian)
                for path, title in (("/me", "Мои серверы"), ("/me/sessions", "Мои сессии"), ("/me/history", "Моя история")):
                    response = client.get(path)
                    self.assertEqual(response.status_code, 200)
                    self.assertIn("<h1>{}</h1>".format(title), response.get_data(as_text=True))
                english = client.get("/me/access?lang=en").get_data(as_text=True)
                self.assertIn("<h1>My requests</h1>", english)
                self.assertIn("Request renewal", english)
                self.assertNotIn("Мои заявки", english)


if __name__ == "__main__":
    unittest.main()
