"""Real signed identities across browser SSH, SQL preferences and replay scopes."""

import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import test_runtime_api_index as fixtures
from isolate_runtime import Runtime, RuntimeDenied
from isolate_connection_auth import ConnectionDenied
from isolate_policy import PolicyDenied
from isolate_identity import IdentityError
from isolate_replay import find_session, parse_raw_replay
from isolate_recovery import rotate_authority_epoch
from isolate_state import SQLState, StateClient
from isolate_ssh_browser import begin, approve, poll
from isolate_workspace import preferences, update_preferences


class WorkspaceBackendTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RuntimeTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config = self.fixture.config
        options = {"backend": "sqlite", "sqlite_path": os.path.join(self.fixture.directory.name, "authority.db")}
        SQLState(options).initialize()
        self.store = StateClient(self.fixture.redis, options)
        for key in ("server_1", "grant_1"):
            self.store.set(key, self.fixture.redis.get(key))
        self.config["state"] = options
        self.fixture.redis = self.store
        self.runtime = Runtime(self.config, self.store)
        self.identity = self.runtime.authenticate(self.fixture.token)
        self.client = self.fixture.app().test_client()
        self.headers = {"Authorization": "Bearer " + self.fixture.token}
        self.config["gateway"]["browser_auth"]["enabled"] = True
        self.config["dashboard"]["public_url"] = "https://bastion.example"

    def login(self):
        with self.client.session_transaction() as session:
            session["identity"] = self.identity
            session["runtime_session"] = "test-browser"
            session["csrf_token"] = "test-csrf"
        self.store.set("isolate_browser_test-browser", json.dumps({"sub": self.identity["keycloak_sub"], "token": self.fixture.token}))

    def recording(self, identifier="own-1", subject="alice-stable", project="prod"):
        directory = Path(self.fixture.directory.name) / "alice" / identifier
        directory.mkdir(parents=True)
        (directory / "session.jsonl").write_text(json.dumps({"event": "ssh_start", "ts": 1000,
            "session_id": identifier, "connection_id": identifier, "keycloak_sub": subject,
            "username": "alice", "host_id": "1", "project": project}) + "\n", encoding="utf-8")

    def test_preferences_use_sql_and_stable_subject_and_reject_code_or_recents(self):
        response = self.client.patch("/api/v1/workspace/preferences", headers=self.headers,
            json={"favorites": ["1:ssh"], "terminal": {"font_size": 18, "font_family": "Menlo"}})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(preferences(self.store, dict(self.identity, username="renamed"))["favorites"], ["1:ssh"])
        self.assertEqual(preferences(self.store, dict(self.identity, keycloak_sub="other"))["favorites"], [])
        self.assertEqual(list(self.store.redis.scan_iter(match="user_preferences_*")), [])
        for body in ({"recent": ["1:ssh"]}, {"terminal": {"font_family": "url(https://evil)"}},
                     {"terminal": {"font_size": True}}, {"favorites": ["javascript:alert(1)"]}):
            self.assertEqual(self.client.patch("/api/v1/workspace/preferences", headers=self.headers, json=body).status_code, 403)
        self.login()
        self.assertEqual(self.client.patch("/api/v1/workspace/preferences", json={"favorites": []}).status_code, 403)
        self.assertEqual(self.client.patch("/api/v1/workspace/preferences", json={"favorites": []},
            headers={"X-CSRF-Token": "test-csrf"}).status_code, 200)

    def test_unified_catalogue_scopes_protocols_and_filters_favorites_before_paging(self):
        grant = json.loads(self.store.get("grant_1"))
        grant["allowed_actions"] = ["ssh", "http"]
        self.store.set("grant_1", json.dumps(grant))
        self.store.set("server_2", json.dumps({"server_id": "2", "project_name": "secret", "server_name": "never-expose", "server_ip": "192.0.2.2"}))
        self.config["protocols"].update(enabled=True, targets={"1": {"project": "prod", "protocol": "http", "upstream": "https://api.example"}})
        response = self.client.get("/api/v1/workspace/resources", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual({row["resource_id"] for row in response.json["resources"]}, {"1:ssh", "1:http"})
        self.assertNotIn("never-expose", response.text)
        self.assertNotIn("do-not-leak", response.text)
        update_preferences(self.store, self.identity, {"favorites": ["1:http", "2:ssh"]})
        response = self.client.get("/api/v1/workspace/resources?view=favorites&limit=1", headers=self.headers)
        self.assertEqual(response.json["total"], 1)
        self.assertEqual(response.json["resources"][0]["resource_id"], "1:http")
        self.assertIsNone(response.json["next_offset"])
        self.store.delete("grant_1")
        self.assertEqual(self.client.get("/api/v1/workspace/resources?view=favorites", headers=self.headers).json["resources"], [])

    def test_replay_and_bookmarks_are_subject_owned_and_reauthorize_each_mutation(self):
        self.recording()
        self.recording("another-1", subject="different-subject")
        self.login()
        self.assertEqual(self.client.get("/replay/own-1").status_code, 200)
        self.assertEqual(self.client.get("/replay/another-1").status_code, 404)
        route = "/api/v1/recordings/own-1/bookmarks"
        self.assertEqual(self.client.post(route, json={"seconds": 1.5, "label": "Investigate"}).status_code, 403)
        result = self.client.post(route, headers=self.headers, json={"seconds": 1.5, "label": "<script>safe label</script>"})
        self.assertEqual(result.status_code, 201)
        bookmark = result.json["bookmarks"][0]
        self.assertEqual(bookmark["seconds"], 1.5)
        self.assertEqual(self.client.get("/api/v1/recordings/another-1/bookmarks", headers=self.headers).status_code, 404)
        self.assertEqual(self.client.post(route, headers=self.headers, json={"seconds": float("nan"), "label": "bad"}).status_code, 400)
        self.assertEqual(self.client.delete(route + "/" + bookmark["id"], headers=self.headers).json["bookmarks"], [])

    def test_standard_ssh_browser_confirmation_needs_csrf_and_independent_transport_proof(self):
        challenge = begin(self.runtime, "1", "192.0.2.14")
        self.assertNotIn(challenge["proof"], challenge["verification_uri"])
        self.assertIsNone(poll(self.runtime, challenge["code"], challenge["proof"]))
        self.assertEqual(self.client.get("/ssh/authorize?code=" + challenge["code"]).status_code, 302)
        self.login()
        self.assertEqual(self.client.get("/ssh/authorize?code=" + challenge["code"]).status_code, 200)
        form = {"code": challenge["code"], "confirm": "yes"}
        self.assertEqual(self.client.post("/ssh/authorize", data=form).status_code, 403)
        form["csrf_token"] = "test-csrf"
        self.assertEqual(self.client.post("/ssh/authorize", data=form).status_code, 200)
        with self.assertRaises(RuntimeDenied):
            poll(self.runtime, challenge["code"], "wrong-transport-proof")
        context = poll(self.runtime, challenge["code"], challenge["proof"])
        self.assertEqual(context["identity"]["keycloak_sub"], "alice-stable")
        with self.assertRaises(RuntimeDenied):
            poll(self.runtime, challenge["code"], challenge["proof"])

    def test_browser_confirmation_cannot_cross_recovery_or_revoked_grant(self):
        challenge = begin(self.runtime, "1", "192.0.2.14")
        rotate_authority_epoch(self.store, self.config, "operator", "recovery-test")
        with self.assertRaises(RuntimeDenied):
            approve(self.runtime, challenge["code"], self.fixture.token)
        challenge = begin(self.runtime, "1", "192.0.2.14")
        approve(self.runtime, challenge["code"], self.fixture.token)
        self.store.delete("grant_1")
        with self.assertRaises(PolicyDenied):
            poll(self.runtime, challenge["code"], challenge["proof"])

    def test_proxy_hops_need_independent_grant_and_cycles_are_denied(self):
        target = json.loads(self.store.get("server_1"))
        target["proxy_id"] = "2"
        self.store.set("server_1", json.dumps(target))
        hop = {"server_id": "2", "server_name": "jump", "project_name": "jump-project", "server_ip": "127.0.0.2", "server_port": 22}
        self.store.set("server_2", json.dumps(hop))
        with self.assertRaises(ConnectionDenied):
            self.runtime.authorize(self.fixture.token, "1")
        self.config["gateway"]["ssh_features"]["proxy_hops"] = True
        self.config["connection_authorization"]["allow_proxy"] = True
        with self.assertRaises(PolicyDenied):
            self.runtime.authorize(self.fixture.token, "1")
        self.store.set("grant_2", json.dumps({"subject": "group", "name": "Support", "project": "jump-project", "remote_user": "jump-user", "sudo_mode": "none", "allowed_actions": ["ssh"]}))
        context = self.runtime.authorize(self.fixture.token, "1")
        self.assertEqual(context["proxy_chain"][0]["decision"]["remote_user"], "jump-user")
        self.store.delete("grant_2")
        with self.assertRaises(PolicyDenied):
            self.runtime._recheck_policy(context)
        self.store.set("grant_2", json.dumps({"subject": "group", "name": "Support", "project": "jump-project", "remote_user": "jump-user", "sudo_mode": "none"}))
        hop["proxy_id"] = "1"
        self.store.set("server_2", json.dumps(hop))
        with self.assertRaisesRegex(ConnectionDenied, "cycle"):
            self.runtime.authorize(self.fixture.token, "1")

    def test_channel_actions_require_separate_grant_and_pinned_destination(self):
        grant = json.loads(self.store.get("grant_1"))
        grant["allowed_actions"] += ["sftp", "forward"]
        self.store.set("grant_1", json.dumps(grant))
        self.config["gateway"]["ssh_features"].update(sftp=True, forwarding=True)
        self.config["gateway"]["forwarding_targets"] = {"1": [{"host": "database.internal", "port": 6000, "address": "127.0.0.8"}]}
        context = self.runtime.authorize(self.fixture.token, "1")
        self.runtime.prepare(context)
        self.runtime.start(context)
        try:
            self.assertEqual(self.runtime.authorize_channel(context, "sftp")["remote_user"], "support")
            self.assertEqual(self.runtime.authorize_channel(context, "forward", {"host": "database.internal", "port": 6000}), {"host": "127.0.0.8", "port": 6000})
            with self.assertRaises(ConnectionDenied):
                self.runtime.authorize_channel(context, "forward", {"host": "evil.internal", "port": 6000})
            self.assertEqual(preferences(self.store, self.identity)["recent"], ["1:ssh"])
        finally:
            self.runtime.finish(context)

    def test_completed_gateway_session_retains_its_start_recording_path(self):
        context = self.runtime.authorize(self.fixture.token, "1")
        self.runtime.prepare(context)
        self.runtime.start(context)
        self.runtime.record_output(context, b"gateway output\r\n")
        self.runtime.finish(context, 0)
        details = find_session(self.config["logging"]["base_path"], context["connection_id"])
        self.assertEqual(parse_raw_replay(details["raw_log_path"])["plain"], "gateway output\r\n")

    def test_workload_channel_cannot_exceed_registered_action_allowlist(self):
        context = self.runtime.authorize(self.fixture.token, "1")
        context["_started"] = True
        context["identity"] = dict(self.identity, principal_type="service", service_client_id="limited-workload")
        self.config["identity_security"]["workloads"]["clients"] = {"limited-workload": {"allowed_actions": ["ssh"]}}
        with mock.patch.object(self.runtime, "recheck"):
            for action in ("sftp", "forward"):
                with self.subTest(action=action), self.assertRaises(IdentityError):
                    self.runtime.authorize_channel(context, action, {"host": "127.0.0.1", "port": 1234} if action == "forward" else None)

    def test_proxy_and_target_approvals_are_consumed_independently(self):
        from isolate_session_approvals import (request_session_approval, decide_session_approval,
            revoke_session_approval, SessionApprovalDenied, get_session_approval)
        target = json.loads(self.store.get("server_1"))
        target["proxy_id"] = "2"
        self.store.set("server_1", json.dumps(target))
        self.store.set("server_2", json.dumps({"server_id": "2", "server_name": "jump", "project_name": "jump", "server_ip": "127.0.0.2"}))
        self.store.set("grant_2", json.dumps({"subject": "group", "name": "Support", "project": "jump", "remote_user": "support", "sudo_mode": "none"}))
        self.config["gateway"]["ssh_features"]["proxy_hops"] = True
        self.config["connection_authorization"]["allow_proxy"] = True
        self.config["dashboard"]["admin_groups"] = ["Admins"]
        self.config["session_approval"].update(enabled=True, required_projects=["prod", "jump"])
        actor = {"keycloak_sub": "approver-sub", "username": "approver", "groups": ["Admins"]}
        requested = []
        def approved(*args, **kwargs):
            record = request_session_approval(*args, **kwargs)
            requested.append(record["id"])
            decide_session_approval(self.store, self.config, record["id"], actor)
            return record
        context = self.runtime.authorize(self.fixture.token, "1")
        with mock.patch("isolate_runtime.request_session_approval", side_effect=approved):
            self.runtime.prepare(context)
        try:
            self.runtime.start(context)
            self.assertEqual(len(requested), 2)
            self.assertEqual({get_session_approval(self.store, i)["status"] for i in requested}, {"active"})
            hop_id = context["proxy_chain"][0]["session_approval_id"]
            revoke_session_approval(self.store, self.config, hop_id, actor)
            with self.assertRaises(SessionApprovalDenied):
                self.runtime.recheck(context)
        finally:
            self.runtime.finish(context)


if __name__ == "__main__":
    unittest.main()
