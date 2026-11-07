import json
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "shared")))

from isolate_inventory import HostValidationError, bulk_update_hosts, create_host, get_host, list_hosts, update_host
import test_self_service_history as existing


class ResourceCatalogTest(unittest.TestCase):
    def setUp(self):
        self.fixture = existing.SelfServiceHistoryTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.redis = self.fixture.redis
        self.client = self.fixture.client
        self.config = self.fixture.config
        self.host = create_host(self.redis, {"project_name": "prod", "server_name": "api-prod",
            "server_ip": "192.0.2.10", "server_user": "support", "tags": {"env": "prod", "owner": "payments"},
            "server_services": "nginx", "resource_owner": "Platform team", "environment": "Production",
            "privileged_access_url": "https://private-secret.example", "proxy_id": None})
        self.redis.set("grant_1", json.dumps({"subject": "group", "name": "Support", "project": "prod",
            "remote_user": "diagnostics", "sudo_mode": "none", "expires_at": int(time.time()) + 1800}))

    def test_metadata_fallback_search_revision_and_bulk_roundtrip(self):
        self.assertEqual(self.host["resource_owner"], "Platform team")
        self.assertEqual(self.host["environment"], "Production")
        updated = update_host(self.redis, self.host["server_id"], {"resource_owner": "", "environment": ""}, expected_revision=self.host["_revision"])
        self.assertEqual(updated["resource_owner"], "payments")
        self.assertEqual(updated["environment"], "prod")
        self.assertNotEqual(updated["_revision"], self.host["_revision"])
        bulk_update_hosts(self.redis, [self.host["server_id"]], {"resource_owner": "DB Operations", "environment": "canary"})
        self.assertEqual(len(list_hosts(self.redis, query="db operations")), 1)
        self.assertEqual(get_host(self.redis, self.host["server_id"])["environment"], "canary")

    def test_invalid_metadata_does_not_modify_host(self):
        before = dict(self.redis.data)
        for field, value in (("resource_owner", ["user"]), ("environment", 1), ("resource_owner", "x" * 129),
                             ("environment", "x" * 65), ("environment", "prod\x00test")):
            with self.subTest(field=field, value=value), self.assertRaises(HostValidationError):
                update_host(self.redis, self.host["server_id"], {field: value})
        self.assertEqual(self.redis.data, before)

    def test_catalogue_and_details_show_effective_access_and_no_internal_metadata(self):
        for path in ("/me", "/me/resources/" + self.host["server_id"]):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            text = response.get_data(as_text=True)
            for value in ("Platform team", "Production", "diagnostics", "nginx", "Copy command", "g " + self.host["server_id"]):
                self.assertIn(value, text)
            self.assertNotIn("private-secret.example", text)
            self.assertNotIn("proxy_id", text)
        self.assertIn('href="/me/access?project=prod&amp;host=' + self.host["server_id"], text)

    def test_auditor_sees_only_scoped_resources_without_ssh_permission(self):
        self.config["dashboard"]["role_bindings"] = [{"group": "Reviewers", "role": "auditor", "projects": ["prod"]}]
        self.config["dashboard"]["self_service_enabled"] = False
        self.fixture.login(dict(self.fixture.identity, groups=["Reviewers"]))
        hidden = create_host(self.redis, {"project_name": "secret", "server_name": "secret-api", "server_ip": "192.0.2.20", "server_user": "root"})
        text = self.client.get("/me").get_data(as_text=True)
        self.assertIn("api-prod", text)
        self.assertNotIn("secret-api", text)
        self.assertIn("No SSH permission", text)
        self.assertNotIn("data-copy-command=", text)
        response = self.client.get("/me/resources/" + self.host["server_id"])
        self.assertEqual(response.status_code, 200)
        self.assertIn("requires a separate grant", response.get_data(as_text=True))
        self.assertEqual(self.client.get("/me/resources/" + hidden["server_id"]).status_code, 404)

    def test_detail_rechecks_grants_and_current_project(self):
        path = "/me/resources/" + self.host["server_id"]
        self.assertEqual(self.client.get(path).status_code, 200)
        self.redis.delete("grant_1")
        self.assertEqual(self.client.get(path).status_code, 404)
        self.config["dashboard"]["role_bindings"] = [{"group": "Support", "role": "auditor", "projects": ["prod"]}]
        self.assertEqual(self.client.get(path).status_code, 200)
        update_host(self.redis, self.host["server_id"], {"project_name": "other"})
        self.assertEqual(self.client.get(path).status_code, 404)

    def test_non_inventory_redis_keys_are_not_resource_identifiers(self):
        self.redis.set("server_private", json.dumps({"project_name": "prod", "server_name": "sensitive", "server_ip": "private-value"}))
        self.assertEqual(self.client.get("/me/resources/private").status_code, 404)
        text = self.client.get("/me/access?host=private").get_data(as_text=True)
        self.assertNotIn("private-value", text)
        self.assertIn('name="host" value=""', text)

    def test_cache_health_never_probes_and_ignores_changed_routing_or_stale_results(self):
        check = {"address": self.host["server_ip"], "port": 22, "project": "prod", "ok": True, "checked_at": int(time.time())}
        self.redis.set("host_check_" + self.host["server_id"], json.dumps(check))
        path = "/me/resources/" + self.host["server_id"]
        with mock.patch("isolate_connectivity.check_host", side_effect=AssertionError("GET must not probe")):
            text = self.client.get(path).get_data(as_text=True)
            self.assertIn("Reachable (cached)", text)
            check["checked_at"] -= 7200
            self.redis.set("host_check_" + self.host["server_id"], json.dumps(check))
            self.assertIn("Check expired", self.client.get(path).get_data(as_text=True))
            update_host(self.redis, self.host["server_id"], {"server_ip": "192.0.2.99"})
            self.assertIn("Unknown", self.client.get(path).get_data(as_text=True))

    def test_metadata_is_escaped_and_russian_catalogue_preserves_labels(self):
        update_host(self.redis, self.host["server_id"], {"resource_owner": '<script>alert("owner")</script>', "environment": '<img src=x>'})
        text = self.client.get("/me?lang=ru").get_data(as_text=True)
        self.assertIn("Владелец", text)
        self.assertIn("Окружение", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertNotIn('<script>alert("owner")</script>', text)

    def test_prefill_is_visible_host_bound_and_get_has_no_side_effects(self):
        before = dict(self.redis.data)
        response = self.client.get("/me/access?project=prod&host=" + self.host["server_id"])
        text = response.get_data(as_text=True)
        self.assertIn('name="project" value="prod"', text)
        self.assertIn('name="host" value="' + self.host["server_id"] + '"', text)
        self.assertIn('name="remote_user" value="diagnostics"', text)
        self.assertEqual(before, self.redis.data)
        for query in ("project=other&host=" + self.host["server_id"], "host=99999", "project=%3Cscript%3E&host=99999"):
            text = self.client.get("/me/access?" + query).get_data(as_text=True)
            self.assertIn('name="project" value=""', text)
            self.assertIn('name="host" value=""', text)
        self.redis.delete("grant_1")
        text = self.client.get("/me/access?host=" + self.host["server_id"]).get_data(as_text=True)
        self.assertIn('name="host" value=""', text)

    def test_fresh_authorization_callback_blocks_single_and_bulk_scope_change(self):
        def authorize(current, proposed):
            if current["project_name"] != "prod" or proposed["project_name"] != "prod":
                raise HostValidationError("project scope denied")
        before = dict(self.redis.data)
        with self.assertRaises(HostValidationError):
            update_host(self.redis, self.host["server_id"], {"project_name": "secret"}, authorize=authorize)
        self.assertEqual(before, self.redis.data)
        update_host(self.redis, self.host["server_id"], {"project_name": "secret"})
        with self.assertRaises(HostValidationError):
            bulk_update_hosts(self.redis, [self.host["server_id"]], {"resource_owner": "oops"}, authorize=authorize)


class WatchedHostMutationTest(unittest.TestCase):
    def test_conflicting_move_is_rechecked_before_commit(self):
        from redis.exceptions import WatchError
        redis = existing.MemoryRedis()
        host = create_host(redis, {"project_name": "prod", "server_name": "api", "server_ip": "192.0.2.10", "server_user": "support"})
        key = "server_" + host["server_id"]
        calls = []

        class Pipeline:
            def __init__(self):
                self.writes = []
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def watch(self, *keys):
                pass
            def get(self, item):
                return redis.get(item)
            def multi(self):
                pass
            def set(self, item, value):
                self.writes.append((item, value))
            def execute(self):
                if not getattr(redis, "conflicted", False):
                    redis.conflicted = True
                    moved = json.loads(redis.get(key))
                    moved["project_name"] = "secret"
                    redis.set(key, json.dumps(moved))
                    raise WatchError("concurrent project move")
                for item, value in self.writes:
                    redis.set(item, value)
        redis.pipeline = lambda transaction=True: Pipeline()

        def authorize(current, proposed):
            calls.append(current["project_name"])
            if current["project_name"] != "prod":
                raise HostValidationError("project scope denied")
        with self.assertRaisesRegex(HostValidationError, "scope"):
            update_host(redis, host["server_id"], {"resource_owner": "new owner"}, authorize=authorize)
        self.assertEqual(calls, ["prod", "secret"])
        stored = json.loads(redis.get(key))
        self.assertEqual(stored["project_name"], "secret")
        self.assertNotEqual(stored.get("resource_owner"), "new owner")


if __name__ == "__main__":
    unittest.main()
