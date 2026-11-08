import datetime
import fnmatch
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "shared")))

import isolate_web
from isolate_access import approve_access_request, create_access_request, get_access_request, list_access_requests
from isolate_history import read_history
from isolate_inventory import create_host
from isolate_jobs import JobError, create_command_job, retry_job
from isolate_policy import PolicyDenied, resolve_grant
from isolate_service_discovery import save_discovery


class MemoryRedis:
    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value, **kwargs):
        if kwargs.get("nx") and key in self.data:
            return False
        self.data[key] = value
        return True

    def delete(self, key):
        return self.data.pop(key, None) is not None

    def keys(self, pattern):
        return [key for key in self.data if fnmatch.fnmatchcase(key, pattern)]

    def incr(self, key):
        value = int(self.data.get(key, 0)) + 1
        self.data[key] = str(value)
        return value


class SelfServiceHistoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.redis = MemoryRedis()
        self.identity = {"username": "alice", "keycloak_sub": "sub-alice", "groups": ["Support"], "roles": [], "exp": int(time.time()) + 3600}
        self.admin = {"username": "admin", "keycloak_sub": "sub-admin", "groups": ["Admins"]}
        self.config = {
            "dashboard": {"admin_groups": ["Admins"], "self_service_enabled": True, "refresh_seconds": 0},
            "keycloak": {}, "logging": {"base_path": self.tmp.name, "sinks": []},
            "access": {"admin_groups": ["Admins"], "default_ttl": "2h", "max_ttl": "24h"},
            "ssh": {}, "policy": {},
        }
        self.app = isolate_web.create_app(self.config)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.login(self.identity)
        patcher = mock.patch.object(isolate_web, "redis_client", return_value=self.redis)
        patcher.start()
        self.addCleanup(patcher.stop)
        audit = mock.patch.object(isolate_web, "prepare_and_dispatch")
        audit.start()
        self.addCleanup(audit.stop)

    def login(self, identity):
        with self.client.session_transaction() as sess:
            sess["identity"] = dict(identity)
            sess["csrf_token"] = "csrf"

    def event(self, username, connection, ts, exit_code=0, subject=None):
        path = os.path.join(self.tmp.name, username, connection)
        os.makedirs(path, exist_ok=True)
        events = [{"event": "ssh_start", "ts": ts, "username": username, "keycloak_sub": subject,
                   "connection_id": connection, "project": "prod", "host_id": "10001", "raw_log_path": "/private/secret.log"}]
        if exit_code is not None:
            events.append(dict(events[0], event="ssh_end", ts=ts + 1, exit_code=exit_code))
        with open(os.path.join(path, "session.jsonl"), "w", encoding="utf-8") as output:
            output.writelines(json.dumps(event) + "\n" for event in events)

    def test_history_filters_dates_results_offsets_and_ownership(self):
        ts = datetime.datetime(2026, 11, 6, 12, tzinfo=datetime.timezone.utc).timestamp()
        self.event("alice", "good", ts, subject="sub-alice")
        self.event("alice", "bad", ts + 60, exit_code=1, subject="sub-alice")
        self.event("bob", "foreign", ts, subject="sub-bob")
        rows = read_history(self.tmp.name, self.identity, since="2026-11-06", until="2026-11-06", result="failure")
        self.assertEqual([row["connection_id"] for row in rows], ["bad"])
        rows = read_history(self.tmp.name, self.identity, since="2026-11-06T19:00:00+07:00", until=str(ts), result="success")
        self.assertEqual([row["connection_id"] for row in rows], ["good"])
        for kwargs in ({"since": "2026-11-06T12:00:00"}, {"since": "nan"}, {"since": "2026-11-07", "until": "2026-11-06"}, {"result": "garbage"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                read_history(self.tmp.name, self.identity, **kwargs)

    def test_history_stable_subject_prevents_recycled_username_and_survives_rename(self):
        self.event("alice", "predecessor", 100, subject="sub-former-alice")
        self.event("old-alice", "renamed", 200, subject="sub-alice")
        self.event("alice", "legacy", 300)
        rows = read_history(self.tmp.name, self.identity)
        self.assertEqual({r["connection_id"] for r in rows}, {"renamed", "legacy"})

    def test_portal_routes_deny_all_admin_surfaces_and_foreign_export(self):
        for url in ("/inventory", "/access", "/history", "/jobs", "/grants", "/packages", "/policy/matrix", "/export/history", "/session/foreign", "/raw/bob/foreign", "/inventory/10001/services"):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 403)
        self.assertEqual(self.client.get("/replay/foreign").status_code, 404)
        self.event("alice", "mine", 100, subject="sub-alice")
        self.event("bob", "theirs", 100, subject="sub-bob")
        response = self.client.get("/me/history/export?format=json&user=bob")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json), 1)
        self.assertNotIn("raw_log_path", response.json[0])
        self.assertNotIn("private", response.get_data(as_text=True))

    def test_portal_inventory_filters_grants_and_tags_without_admin_navigation(self):
        for name, project in (("allowed", "prod"), ("hidden", "secret")):
            create_host(self.redis, {"project_name": project, "server_name": name, "server_ip": "192.0.2.1", "server_user": "support", "tags": {"env": "prod"}})
        self.redis.set("grant_1", json.dumps({"subject": "group", "name": "Support", "project": "prod", "remote_user": "support"}))
        response = self.client.get("/me?tags=env%3Dprod")
        text = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(">allowed<", text)
        self.assertNotIn(">hidden<", text)
        self.assertNotIn('href="/grants"', text)
        self.assertIn('href="/me/access"', text)
        self.assertEqual(self.client.get("/").headers["Location"], "/me")

    def test_sessions_are_subject_scoped(self):
        for conn, name, subject in (("mine", "alice", "sub-alice"), ("former", "alice", "sub-old"), ("other", "bob", "sub-bob")):
            self.redis.set("active_session_" + conn, json.dumps({"connection_id": conn, "username": name, "keycloak_sub": subject, "status": "active"}))
        text = self.client.get("/me/sessions").get_data(as_text=True)
        self.assertIn("mine", text)
        self.assertNotIn("former", text)
        self.assertNotIn("other", text)

    def test_csrf_missing_bad_or_absent_session_token_never_mutates(self):
        for token in (None, "bad"):
            data = {"action": "create", "project": "prod", "reason": "check", "confirm": "true"}
            if token:
                data["csrf_token"] = token
            self.assertEqual(self.client.post("/me/access", data=data).status_code, 403)
        with self.client.session_transaction() as sess:
            sess.pop("csrf_token")
        self.assertEqual(self.client.post("/me/access", data={"action": "create"}).status_code, 403)
        self.assertEqual(list_access_requests(self.redis), [])

    def test_foreign_request_and_approval_cannot_be_mutated(self):
        record = create_access_request(self.redis, {"username": "bob", "keycloak_sub": "sub-bob"}, "prod", reason="other")
        for action, status in (("cancel", 404), ("comment", 404), ("renew", 404), ("approve", 403), ("revoke", 403)):
            response = self.client.post("/me/access", data={"csrf_token": "csrf", "id": record["id"], "action": action, "confirm": "true"})
            self.assertEqual(response.status_code, status)
        self.assertEqual(get_access_request(self.redis, record["id"])["status"], "pending")

    def test_request_flow_future_approval_renewal_and_revocation(self):
        start = int(time.time()) + 600
        end = start + 1800
        response = self.client.post("/me/access", data={"csrf_token": "csrf", "action": "create", "confirm": "true", "project": "prod", "remote_user": "support", "reason": "incident", "starts_at": str(start), "ends_at": str(end)})
        self.assertEqual(response.status_code, 302)
        record = list_access_requests(self.redis)[0]
        self.login(self.admin)
        response = self.client.post("/access", data={"csrf_token": "csrf", "action": "approve", "id": record["id"], "ttl": "2h"})
        self.assertEqual(response.status_code, 200)
        approved = get_access_request(self.redis, record["id"])
        grant = json.loads(self.redis.get("grant_" + approved["grant_id"]))
        self.assertEqual(grant["expires_at"], end)
        with self.assertRaises(PolicyDenied):
            resolve_grant(self.identity, project="prod", grants=[grant])
        with mock.patch("isolate_policy.time.time", return_value=start):
            self.assertEqual(resolve_grant(self.identity, project="prod", grants=[grant])["remote_user"], "support")
        self.login(self.identity)
        response = self.client.post("/me/access", data={"csrf_token": "csrf", "action": "renew", "id": record["id"], "reason": "continue", "confirm": "true"})
        self.assertEqual(response.status_code, 302)
        renewed = list_access_requests(self.redis)[0]
        self.assertEqual(renewed["status"], "pending")
        self.assertEqual(renewed["renewal_of"], record["id"])
        self.login(self.admin)
        response = self.client.post("/access", data={"csrf_token": "csrf", "action": "revoke", "id": record["id"], "reason": "done", "confirm": "true"})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.redis.get("grant_" + approved["grant_id"]))
        self.assertEqual(get_access_request(self.redis, record["id"])["status"], "revoked")

    def test_renamed_owner_can_list_and_cancel_old_request(self):
        record = create_access_request(self.redis, dict(self.identity, username="old-alice"), "prod", reason="rename")
        text = self.client.get("/me/access").get_data(as_text=True)
        self.assertIn('name="id" value="{}"'.format(record["id"]), text)
        response = self.client.post("/me/access", data={"csrf_token": "csrf", "action": "cancel", "id": record["id"], "confirm": "true"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(get_access_request(self.redis, record["id"])["status"], "cancelled")

    def test_history_table_and_export_apply_identical_filters(self):
        self.event("alice", "ok", 100, subject="sub-alice")
        self.event("alice", "bad", 200, exit_code=2, subject="sub-alice")
        self.login(self.admin)
        response = self.client.get("/history?since=150&result=failure")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn("since=150&amp;result=failure&amp;format=csv", text)
        rows = self.client.get("/export/history?since=150&result=failure&format=json").json
        self.assertEqual([row["connection_id"] for row in rows], ["bad"])
        self.assertEqual(self.client.get("/history?since=garbage").status_code, 400)
        self.assertEqual(self.client.get("/export/history?limit=nan").status_code, 400)

    def test_inventory_tags_and_service_change_routes(self):
        self.login(self.admin)
        host = create_host(self.redis, {"project_name": "prod", "server_name": "api", "server_ip": "192.0.2.10", "server_user": "support", "tags": {"env": "prod"}})
        for ts, services in ((100, ["ssh.service"]), (200, ["ssh.service", "nginx.service"])):
            save_discovery(self.redis, {"host_id": host["server_id"], "ok": True, "services": services, "checked_at": ts})
        response = self.client.get("/inventory/{}/services".format(host["server_id"]))
        self.assertEqual(response.status_code, 200)
        self.assertIn("nginx.service", response.get_data(as_text=True))
        self.assertIn("baseline", response.get_data(as_text=True))
        self.assertEqual(len(self.client.get("/export/inventory?tags=env%3Dstage&format=json").json), 0)

    def test_oidc_nonadmin_lands_in_portal_and_can_be_disabled_or_group_restricted(self):
        oauth = self.app.extensions["authlib.integrations.flask_client"].keycloak
        claims = {"preferred_username": "alice", "sub": "sub-alice", "groups": ["Support"], "exp": int(time.time()) + 3600}
        with mock.patch.object(oauth, "authorize_access_token", return_value={"userinfo": claims}):
            response = self.client.get("/auth/callback")
        self.assertEqual(response.headers["Location"], "/me")
        self.config["dashboard"]["self_service_groups"] = ["Different"]
        self.assertEqual(self.client.get("/me").status_code, 403)
        self.config["dashboard"]["self_service_enabled"] = False
        self.assertEqual(self.client.get("/me/history/export").status_code, 403)

    def test_expired_and_unauthenticated_portal_sessions_redirect_to_login(self):
        self.login(dict(self.identity, exp=int(time.time()) - 1))
        self.assertEqual(self.client.get("/me").headers["Location"], "/login")
        self.assertEqual(self.client.get("/me/history/export").headers["Location"], "/login")

    def test_dashboard_fleet_tag_selection_and_mixed_selector_rejection(self):
        self.login(self.admin)
        host = create_host(self.redis, {"project_name": "prod", "server_name": "api", "server_ip": "192.0.2.10", "server_user": "support", "tags": {"env": "prod"}})
        with mock.patch.object(isolate_web, "create_runbook_fleet", return_value={"fleet_id": "fleet-test", "count": 1}) as create:
            response = self.client.post("/jobs", data={"csrf_token": "csrf", "action": "queue_runbook", "runbook_id": "uptime", "tags": "env=prod", "confirm": "true"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(create.call_args.args[4], [host["server_id"]])
            create.reset_mock()
            response = self.client.post("/jobs", data={"csrf_token": "csrf", "action": "queue_runbook", "runbook_id": "uptime", "tags": "env=prod", "host_ids": host["server_id"], "confirm": "true"})
            self.assertIn("not both", response.get_data(as_text=True))
            create.assert_not_called()

    def test_retry_rechecks_current_claims_instead_of_reusing_submitter_groups(self):
        signing_key = os.path.join(self.tmp.name, "job.key")
        with open(signing_key, "wb") as output:
            output.write(b"test-signing-key-32-bytes-minimum!!")
        config = dict(self.config, command_execution={"enabled": True, "allowed_groups": ["Support"],
            "allowed_command_patterns": ["^true$"], "signing_key_file": signing_key, "jobs_path": self.tmp.name})
        host = create_host(self.redis, {"project_name": "prod", "server_name": "api", "server_ip": "192.0.2.10", "server_user": "support"})
        grant = {"subject": "group", "name": "Support", "project": "prod", "remote_user": "support", "sudo_mode": "none", "allowed_actions": ["command"]}
        self.redis.set("grant_1", json.dumps(grant))
        decision = resolve_grant(self.identity, project="prod", host=host, grants=[grant], action="command")
        job = create_command_job(self.redis, config, self.identity, host, decision, "true")
        job["status"] = "failed"
        self.redis.set("job_" + str(job["id"]), json.dumps(job))
        with self.assertRaisesRegex(JobError, "group"):
            retry_job(self.redis, config, job["id"], self.identity, current_identity=dict(self.identity, groups=[]))
        self.assertEqual(len(self.redis.keys("job_*")), 1)


if __name__ == "__main__":
    unittest.main()
