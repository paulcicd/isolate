import concurrent.futures
import copy
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
import fakeredis
from joserfc import jwt
from joserfc.jwk import RSAKey

import isolate_web
from isolate_api import register_api_routes
from isolate_audit_index import AuditIndex, AuditIndexError
from isolate_client import APIClient, console
from isolate_cluster import Lease, OwnershipError
from isolate_config import _deep_merge, DEFAULT_CONFIG
from isolate_identity import IdentityError
from isolate_policy import PolicyDenied
from isolate_replay import parse_raw_replay
from isolate_runtime import Runtime, RuntimeDenied
from isolate_sessions import request_session_termination


class RuntimeTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.redis = fakeredis.FakeRedis()
        self.config = _deep_merge(copy.deepcopy(DEFAULT_CONFIG), {"keycloak": {"issuer": "https://id.example/realms/test", "client_id": "isolate",
            "expected_audience": "isolate", "jwks_cache_path": None}, "gateway": {"enabled": True, "public_web_url": "https://bastion.example/gateway"},
            "api": {"enabled": True}, "logging": {"base_path": self.directory.name},
            "dashboard": {"self_service_enabled": True}})
        self.key = RSAKey.generate_key(2048, parameters={"kid": "test-key"})
        self.claims = {"iss": self.config["keycloak"]["issuer"], "aud": "isolate", "sub": "alice-stable",
            "preferred_username": "alice", "groups": ["Support"], "exp": int(time.time()) + 900,
            "iat": int(time.time()) - 5, "sid": "idp-session-1"}
        self.token = self.sign(self.claims)
        self.jwks = mock.patch("isolate_identity.load_jwks", return_value={"keys": [self.key.as_dict(private=False)]})
        self.jwks.start()
        self.addCleanup(self.jwks.stop)
        self.redis.set("server_1", json.dumps({"server_id": "1", "project_name": "prod", "server_ip": "127.0.0.1",
            "server_name": "database", "server_port": 22, "password": "do-not-leak"}))
        self.redis.set("grant_1", json.dumps({"subject": "group", "name": "Support", "project": "prod",
            "remote_user": "support", "sudo_mode": "none", "allowed_actions": ["ssh"]}))
        self.runtime = Runtime(self.config, self.redis)

    def sign(self, claims):
        return jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, self.key)

    def context(self):
        ticket = self.runtime.create_ticket(self.token, "1")
        return self.runtime.consume_ticket(ticket["ticket"])

    def test_signed_api_identity_needs_no_personal_unix_account(self):
        with mock.patch("isolate_connection_auth.invoking_user", side_effect=AssertionError("must not use Unix identity")):
            context = self.context()
            self.assertEqual(context["identity"]["keycloak_sub"], "alice-stable")
            self.assertEqual(context["decision"]["remote_user"], "support")

    def test_ticket_can_be_used_once_across_two_nodes(self):
        ticket = self.runtime.create_ticket(self.token, "1")["ticket"]
        def attempt(_):
            try:
                return Runtime(self.config, self.redis).consume_ticket(ticket)["connection_id"]
            except RuntimeDenied:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        self.assertEqual(sum(value is not None for value in results), 1)

    def test_ticket_protocol_mismatch_burns_the_ticket(self):
        ticket = self.runtime.create_ticket(self.token, "1")["ticket"]
        with self.assertRaises(RuntimeDenied):
            self.runtime.consume_ticket(ticket, "webssh")
        with self.assertRaises(RuntimeDenied):
            self.runtime.consume_ticket(ticket)

    def test_wrong_audience_signature_and_expired_token_fail(self):
        cases = [dict(self.claims, aud="wrong"), dict(self.claims, exp=int(time.time()) - 1),
            dict(self.claims, iss="https://wrong.example")]
        for claims in cases:
            with self.subTest(claims=claims):
                with self.assertRaises(IdentityError):
                    self.runtime.create_ticket(self.sign(claims), "1")
        other_key = RSAKey.generate_key(2048)
        with self.assertRaises(IdentityError):
            self.runtime.create_ticket(jwt.encode({"alg": "RS256"}, self.claims, other_key), "1")

    def test_http_issuer_or_disabled_verification_are_refused(self):
        for change in ({"issuer": "http://id.example"}, {"verify_tokens": False}, {"tls_verify": False}):
            config = _deep_merge(self.config, {"keycloak": change})
            with self.assertRaises(RuntimeDenied):
                Runtime(config, self.redis).authenticate(self.token)

    def test_live_policy_revoke_route_change_and_termination_close(self):
        for mutation in (lambda: self.redis.delete("grant_1"),
                         lambda: self.redis.set("server_1", json.dumps({"server_id": "1", "project_name": "prod", "server_ip": "127.0.0.2"})),
                         lambda: request_session_termination(self.redis, context["connection_id"], {"username": "admin"})):
            self.setUp_data()
            context = self.context()
            self.runtime.prepare(context)
            self.runtime.start(context)
            mutation()
            with self.assertRaises((RuntimeDenied, PolicyDenied)):
                self.runtime.recheck(context)
            self.runtime.finish(context, 143)

    def setUp_data(self):
        self.redis.set("server_1", json.dumps({"server_id": "1", "project_name": "prod", "server_ip": "127.0.0.1", "server_name": "database"}))
        self.redis.set("grant_1", json.dumps({"subject": "group", "name": "Support", "project": "prod", "remote_user": "support", "sudo_mode": "none"}))

    def test_lease_loss_fails_closed_and_cannot_release_new_owner(self):
        context = self.context()
        self.runtime.prepare(context)
        key = context["_lease"].key
        self.redis.set(key, "successor")
        with self.assertRaises(OwnershipError):
            self.runtime.recheck(context)
        self.runtime.finish(context)
        self.assertEqual(self.redis.get(key), b"successor")

    def test_replay_uses_existing_terminal_parser(self):
        context = self.context()
        self.runtime.prepare(context)
        self.runtime.start(context)
        self.runtime.record_output(context, b"hello\r\n")
        self.runtime.finish(context, 0)
        result = parse_raw_replay(context["_raw_log_path"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["plain"], "hello\r\n")

    def test_inventory_excludes_accidental_secret_fields(self):
        rows = self.runtime.resources(self.token)
        self.assertEqual(len(rows), 1)
        self.assertNotIn("password", rows[0])

    def test_ssh_grant_does_not_grant_database_protocol(self):
        self.config["protocols"] = {"enabled": True, "targets": {"1": {"protocol": "postgresql", "project": "prod",
            "upstream": "postgresql://127.0.0.1:5432", "database_native_auth": True}}}
        with self.assertRaises(PolicyDenied):
            self.runtime.authorize(self.token, "1", "postgresql")

    def test_draining_rejects_new_tickets_but_existing_session_survives(self):
        context = self.context()
        self.runtime.prepare(context)
        self.runtime.start(context)
        self.redis.set("isolate_cluster_draining", "1")
        with self.assertRaises(RuntimeDenied):
            self.runtime.create_ticket(self.token, "1")
        self.runtime.recheck(context)
        self.runtime.finish(context)

    def test_gateway_waits_for_two_approvers_and_obeys_live_approval_revocation(self):
        from isolate_session_approvals import (SessionApprovalDenied, decide_session_approval,
            list_session_approvals, revoke_session_approval)
        self.config["session_approval"].update(enabled=True, required_projects=["prod"],
            minimum_approvals=2, poll_interval_seconds=1)
        self.config["dashboard"]["role_bindings"] = [{"group": "Reviewers", "role": "approver", "projects": ["prod"]}]
        context = self.context()
        actors = [{"keycloak_sub": "reviewer-" + str(n), "username": "reviewer" + str(n), "groups": ["Reviewers"]} for n in (1, 2)]
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = pool.submit(self.runtime.prepare, context)
        try:
            deadline = time.monotonic() + 5
            pending = []
            while not pending and time.monotonic() < deadline:
                pending = list_session_approvals(self.redis, status="pending")
                time.sleep(0.01)
            self.assertEqual(len(pending), 1)
            request_id = pending[0]["id"]
            first = decide_session_approval(self.redis, self.config, request_id, actors[0])
            self.assertEqual(first["status"], "pending")
            self.assertFalse(future.done())
            decide_session_approval(self.redis, self.config, request_id, actors[1])
            self.assertIs(future.result(timeout=5), context)
            self.runtime.start(context)
            revoke_session_approval(self.redis, self.config, request_id, actors[0])
            with self.assertRaises(SessionApprovalDenied):
                self.runtime.recheck(context)
        finally:
            self.runtime.finish(context)
            pool.shutdown(wait=True)

    def test_runtime_config_rejects_short_lease_and_insecure_identity(self):
        from isolate_runtime_config import validate_runtime_config
        config = _deep_merge(self.config, {"cluster": {"lease_ttl": 10}, "gateway": {"recheck_interval": 10}})
        self.assertTrue(any("lease_ttl" in item for item in validate_runtime_config(config)["errors"]))
        config["keycloak"]["issuer"] = "http://id.example"
        self.assertTrue(any("HTTPS" in item for item in validate_runtime_config(config)["errors"]))

    def test_loaded_configs_do_not_share_mutable_defaults(self):
        from isolate_config import load_config
        one = load_config(path=os.path.join(self.directory.name, "missing.yml"), use_env=False)
        two = load_config(path=os.path.join(self.directory.name, "missing.yml"), use_env=False)
        one["session_approval"]["required_projects"].append("must-not-leak")
        self.assertNotIn("must-not-leak", two["session_approval"]["required_projects"])

    def test_sentinel_master_receives_database_acl_and_tls_options(self):
        from isolate_redis import create_redis_client
        config = {"redis": {"db": 2, "username": "service", "password": "fixture-password", "ssl": True,
            "ssl_ca_certs": "/ca.pem", "sentinel": {"enabled": True, "master_name": "isolate", "nodes": [["sentinel", 26379]],
                "username": "sentinel-reader", "password": "fixture-sentinel-password", "ssl": True}}}
        with mock.patch("redis.sentinel.Sentinel") as sentinel:
            create_redis_client(config)
            options = sentinel.call_args.kwargs
            self.assertEqual(options["db"], 2)
            self.assertEqual(options["username"], "service")
            self.assertTrue(options["ssl"])
            self.assertEqual(options["sentinel_kwargs"]["username"], "sentinel-reader")
            sentinel.return_value.master_for.assert_called_once_with("isolate")

    def app(self):
        patcher = mock.patch.object(isolate_web, "redis_client", return_value=self.redis)
        patcher.start()
        self.addCleanup(patcher.stop)
        app = isolate_web.create_app(self.config)
        app.config.update(TESTING=True, SECRET_KEY="test-session-secret")
        return app

    def test_api_is_bearer_authenticated_and_cannot_override_identity_or_route(self):
        client = self.app().test_client()
        self.assertEqual(client.get("/api/v1/resources").status_code, 401)
        headers = {"Authorization": "Bearer " + self.token}
        self.assertEqual(client.get("/api/v1/resources", headers=headers).status_code, 200)
        self.assertEqual(client.post("/api/v1/connections", headers=headers, json={"host_id": "1", "remote_user": "root"}).status_code, 400)
        response = client.post("/api/v1/connections", headers=headers, json={"host_id": "1", "protocol": "webssh"})
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json["websocket_url"].endswith("/ssh"))
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_browser_ticket_requires_csrf_and_server_side_token(self):
        client = self.app().test_client()
        with client.session_transaction() as session:
            session["identity"] = self.runtime.authenticate(self.token)
            session["runtime_session"] = "opaque"
            session["csrf_token"] = "test-csrf"
        self.redis.set("isolate_browser_opaque", json.dumps({"token": self.token, "sub": "alice-stable"}))
        body = {"host_id": "1", "protocol": "webssh"}
        self.assertEqual(client.post("/api/v1/connections", json=body).status_code, 403)
        response = client.post("/api/v1/connections", json=body, headers={"X-CSRF-Token": "test-csrf"})
        self.assertEqual(response.status_code, 201)
        terminal = client.get("/me/terminal/1")
        self.assertEqual(terminal.status_code, 200)
        self.assertIn(b"terminal-workspace.js", terminal.data)
        self.assertNotIn(self.token.encode(), terminal.data)
        client.get("/logout")
        self.assertIsNone(self.redis.get("isolate_browser_opaque"))

    def test_audit_api_filters_projects_before_pagination_and_escapes_event_html(self):
        self.config["audit_index"] = {"enabled": True, "path": os.path.join(self.directory.name, "search.db")}
        self.config["dashboard"]["role_bindings"] = [{"group": "Support", "role": "auditor", "projects": ["prod"]}]
        index = AuditIndex(self.config["audit_index"])
        index.initialize()
        for identifier, timestamp, subject, project in (("own", 1, "alice-stable", "other"),
                ("scoped", 2, "bob", "prod"), ("hidden", 3, "bob", "stage")):
            index.ingest({"event_id": identifier, "ts": timestamp, "event": "command", "keycloak_sub": subject,
                "project": project, "command": "<script>alert(1)</script>"})
        client = self.app().test_client()
        headers = {"Authorization": "Bearer " + self.token}
        page = client.get("/api/v1/audit?limit=1", headers=headers)
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.json["events"][0]["event_id"], "scoped")
        from urllib.parse import urlencode
        following = client.get("/api/v1/audit?" + urlencode({"limit": 1, "before": json.dumps(page.json["next"])}), headers=headers)
        self.assertEqual(following.json["events"][0]["event_id"], "own")
        browser_page = client.get("/audit/search", headers=headers)
        self.assertEqual(browser_page.status_code, 200)
        self.assertNotIn(b"<script>alert(1)</script>", browser_page.data)
        self.assertIn(b"&lt;script&gt;", browser_page.data)

    def test_console_api_mode_keeps_search_projects_and_callback_without_redis(self):
        rows = self.runtime.resources(self.token)
        config = _deep_merge(self.config, {"api": {"client_url": "https://bastion.example"}})
        with mock.patch.object(APIClient, "resources", return_value=rows), mock.patch("isolate_redis.create_redis_client", side_effect=AssertionError("no direct Redis")):
            for action, selectors in (("projects", []), ("search", ["database"])):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(console(SimpleNamespace(action=[action], sargs=selectors), [], config), 0)
                self.assertIn("prod" if action == "projects" else "database", output.getvalue())
            session_path = os.path.join(self.directory.name, "callback")
            with mock.patch.dict(os.environ, {"ISOLATE_SESSION": session_path}):
                console(SimpleNamespace(action=["go"], sargs=["1"]), [], config)
            with open(session_path) as source:
                callback = source.read()
            self.assertIn("isolate_client.py", callback)
            self.assertNotIn(self.token, callback)


class AuditIndexTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.index = AuditIndex({"path": os.path.join(self.directory.name, "audit.db")})
        self.index.initialize()
        for number, project, subject in ((1, "prod", "alice"), (2, "stage", "bob"), (3, "prod", "bob")):
            self.index.ingest({"event_id": str(number), "ts": 100 + number, "event": "ssh_start", "project": project,
                "keycloak_sub": subject, "connection_id": "conn-" + str(number), "command": "systemctl status nginx"})

    def test_visibility_is_applied_before_limit_and_pagination(self):
        page = self.index.search(subject="alice", projects=["stage"], limit=1)
        self.assertEqual(page["events"][0]["event_id"], "2")
        following = self.index.search(subject="alice", projects=["stage"], limit=1, before=page["next"])
        self.assertEqual(following["events"][0]["event_id"], "1")
        self.assertIsNone(following["next"])
        self.assertEqual(self.index.search(projects=[])["events"], [])

    def test_fulltext_search_and_structured_filter(self):
        result = self.index.search(query="systemctl nginx", projects=["prod"], connection_id="conn-3")
        self.assertEqual([row["event_id"] for row in result["events"]], ["3"])
        self.assertEqual(self.index.search(query="missing")["events"], [])

    def test_idempotent_ingest_and_collision_detection(self):
        record = {"event_id": "durable", "ts": 200, "event": "ssh_end", "token": "do-not-index"}
        self.assertTrue(self.index.ingest(record))
        self.assertFalse(self.index.ingest(record))
        with self.assertRaises(AuditIndexError):
            self.index.ingest(dict(record, event="tampered"))
        self.assertEqual(self.index.search(event="ssh_end")["events"][0]["token"], "[redacted]")

    def test_reimport_jsonl_deduplicates(self):
        path = os.path.join(self.directory.name, "spool.jsonl")
        with open(path, "w") as output:
            output.write(json.dumps({"event_id": "reimport", "event": "grant_revoked", "ts": 300}) + "\n")
        self.assertEqual(self.index.import_jsonl(path), 1)
        self.assertEqual(self.index.import_jsonl(path), 0)


if __name__ == "__main__":
    unittest.main()
