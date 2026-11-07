"""Object-level scope checks for management, recordings and approval routes."""

import json
import os
import re
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import test_self_service_history as fixtures
import isolate_jobs
from isolate_access import create_access_request, get_access_request
from isolate_health import validate_config
from isolate_inventory import create_host, get_host
from isolate_jobs import JobError, create_command_job, create_runbook_fleet, execute_job
from isolate_notifications import NotificationError, notify_session_approval_event
from isolate_policy import resolve_grant
from isolate_session_approvals import (
    consume_session_approval, get_session_approval, request_session_approval,
)


class ScopedDashboardTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SelfServiceHistoryTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.redis, self.config, self.client = self.fixture.redis, self.fixture.config, self.fixture.client
        self.config["dashboard"]["role_bindings"] = [
            {"group": "Operators", "role": "inventory-operator", "projects": ["prod"]},
            {"group": "Auditors", "role": "auditor", "projects": ["prod"]},
            {"group": "Approvers", "role": "approver", "projects": ["prod"]},
        ]
        self.alice = self.fixture.identity
        self.approver = {"username": "approver", "keycloak_sub": "sub-approver", "groups": ["Approvers"]}
        self.second = dict(self.approver, username="second", keycloak_sub="sub-second")
        self.auditor = {"username": "auditor", "keycloak_sub": "sub-auditor", "groups": ["Auditors"]}
        self.operator = {"username": "operator", "keycloak_sub": "sub-operator", "groups": ["Operators"]}
        self.host = create_host(self.redis, {"project_name": "prod", "server_name": "visible-host", "server_ip": "192.0.2.1", "server_user": "support"})
        self.foreign = create_host(self.redis, {"project_name": "secret", "server_name": "foreign-host", "server_ip": "192.0.2.2", "server_user": "support"})

    def login(self, identity):
        self.fixture.login(identity)

    def post(self, path, **data):
        return self.client.post(path, data=dict({"csrf_token": "csrf", "confirm": "true"}, **data))

    def record(self, connection, project, ts):
        self.fixture.event("alice", connection, ts, subject="sub-alice")
        path = os.path.join(self.fixture.tmp.name, "alice", connection, "session.jsonl")
        raw_path = os.path.join(os.path.dirname(path), "terminal.log")
        with open(raw_path, "w", encoding="utf-8") as output:
            output.write("1000.000000\nrecorded terminal\n")
        with open(path, encoding="utf-8") as source:
            events = [json.loads(line) for line in source]
        for event in events:
            event.update(project=project, raw_log_path=raw_path)
        with open(path, "w", encoding="utf-8") as output:
            output.writelines(json.dumps(event) + "\n" for event in events)

    def approval(self, root=False):
        self.config["session_approval"] = {"enabled": True, "required_projects": ["prod", "secret"]}
        decision = {"remote_user": "root" if root else "support", "sudo_mode": "none", "matched_rule": {"id": "grant1"}}
        record = request_session_approval(self.redis, self.config, self.alice, self.host, decision, "conn-approval")
        return record, decision

    def test_inventory_rows_exports_forms_and_mutations_are_scoped(self):
        self.login(self.auditor)
        response = self.client.get("/inventory")
        text = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("visible-host", text)
        self.assertNotIn("foreign-host", text)
        self.assertNotIn("<h2>Add host</h2>", text)
        self.assertNotIn("<h2>Bulk update</h2>", text)
        self.assertEqual(len(self.client.get("/export/inventory?format=json").json), 1)
        self.assertEqual(self.client.get("/export/grants").status_code, 403)
        self.assertEqual(self.client.get("/inventory/{}/edit".format(self.host["server_id"])).status_code, 403)
        self.login(self.operator)
        self.assertEqual(self.post("/inventory", action="add", project="prod").status_code, 403)
        response = self.post("/inventory", action="bulk_update", host_ids=self.host["server_id"] + "," + self.foreign["server_id"], note="unauthorized")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(get_host(self.redis, self.host["server_id"])["server_note"], "")
        self.assertEqual(self.client.get("/inventory/{}/services".format(self.foreign["server_id"])).status_code, 404)

    def test_inventory_operator_updates_metadata_but_cannot_reroute_or_move_outside_scope(self):
        self.login(self.operator)
        path = "/inventory/{}/edit".format(self.host["server_id"])
        self.assertIn('name="ip" disabled', self.client.get(path).get_data(as_text=True))
        response = self.post(path, owner="Payments", environment="production", note="metadata")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(get_host(self.redis, self.host["server_id"])["resource_owner"], "Payments")
        for data in ({"ip": "192.0.2.99"}, {"project": "secret"}, {"vip": "true"}):
            with self.subTest(data=data):
                response = self.post(path, **data)
                self.assertEqual(response.status_code, 200)
                self.assertIn("notice error", response.get_data(as_text=True))
        host = get_host(self.redis, self.host["server_id"])
        self.assertEqual(host["server_ip"], "192.0.2.1")
        self.assertEqual(host["project_name"], "prod")
        self.assertFalse(host["server_vip"])

    def test_scoped_history_filters_before_limit_and_all_recording_routes_check_object(self):
        self.record("ours", "prod", 1000)
        self.record("foreign", "secret", 2000)
        self.record("missing-project", "", 3000)
        self.login(self.auditor)
        rows = self.client.get("/export/history?format=json&limit=1&user=alice").json
        self.assertEqual([row["connection_id"] for row in rows], ["ours"])
        for template in ("/session/{}", "/session/{}/events.json", "/session/{}/live.json", "/session/{}/live", "/replay/{}", "/replay/{}.json", "/raw/alice/{}"):
            with self.subTest(template=template):
                with self.client.get(template.format("ours")) as response:
                    self.assertEqual(response.status_code, 200)
                self.assertEqual(self.client.get(template.format("foreign")).status_code, 404)
                self.assertEqual(self.client.get(template.format("missing-project")).status_code, 404)
        self.redis.set("active_session_foreign", json.dumps({"connection_id": "foreign", "project": "secret", "status": "active", "username": "alice"}))
        self.assertEqual(self.client.get("/session/foreign/live.json").status_code, 404)

    def test_scoped_access_decisions_and_read_only_auditor(self):
        own = create_access_request(self.redis, self.alice, "prod", reason="diagnosis", remote_user="support")
        foreign = create_access_request(self.redis, self.alice, "secret", reason="foreign", remote_user="support")
        self.login(self.auditor)
        text = self.client.get("/access").get_data(as_text=True)
        self.assertNotIn("Approve</button>", text)
        self.assertEqual(self.post("/access", action="approve", id=own["id"]).status_code, 404)
        self.login(self.approver)
        self.assertEqual(self.post("/access", action="approve", id=foreign["id"]).status_code, 404)
        self.assertEqual(self.post("/access", action="approve", id=own["id"], ttl="1h").status_code, 200)
        self.assertEqual(get_access_request(self.redis, own["id"])["status"], "approved")
        self.assertEqual(self.post("/access", action="revoke", id=own["id"], reason="done").status_code, 200)
        self.assertEqual(get_access_request(self.redis, own["id"])["status"], "revoked")

    def test_scoped_identity_can_enter_with_self_service_disabled_without_global_admin_links(self):
        self.config["dashboard"]["self_service_enabled"] = False
        self.login(self.operator)
        self.assertEqual(self.client.get("/").headers["Location"], "/me")
        text = self.client.get("/me").get_data(as_text=True)
        self.assertIn('href="/inventory"', text)
        self.assertNotIn('href="/grants"', text)
        self.assertEqual(self.client.get("/grants").status_code, 403)

    def test_session_approval_scope_quorum_owner_and_self_approval(self):
        record, decision = self.approval(root=True)
        self.assertEqual(self.client.get("/session-approvals").status_code, 403)
        self.assertIn(record["id"], self.client.get("/me/session-approvals").get_data(as_text=True))
        self.login(dict(self.approver, keycloak_sub="sub-alice"))
        self.post("/session-approvals", action="approve", id=record["id"])
        self.assertEqual(get_session_approval(self.redis, record["id"])["approvals"], [])
        self.login(self.approver)
        self.assertEqual(self.post("/session-approvals", action="approve", id=record["id"]).status_code, 302)
        self.assertEqual(get_session_approval(self.redis, record["id"])["status"], "pending")
        self.post("/session-approvals", action="approve", id=record["id"])
        self.assertEqual(len(get_session_approval(self.redis, record["id"])["approvals"]), 1)
        self.login(self.second)
        self.assertEqual(self.post("/session-approvals", action="approve", id=record["id"]).status_code, 302)
        self.assertEqual(get_session_approval(self.redis, record["id"])["status"], "approved")
        consume_session_approval(self.redis, self.config, record["id"], self.alice, self.host, decision, "conn-approval")
        self.assertEqual(self.post("/session-approvals", action="revoke", id=record["id"]).status_code, 302)
        self.assertEqual(get_session_approval(self.redis, record["id"])["status"], "revoked")

    def test_foreign_session_approval_hidden_and_cannot_decide(self):
        record, decision = self.approval()
        foreign = request_session_approval(self.redis, self.config, self.alice, self.foreign, decision, "conn-foreign")
        self.login(self.approver)
        text = self.client.get("/session-approvals").get_data(as_text=True)
        self.assertIn(record["id"], text)
        self.assertNotIn(foreign["id"], text)
        self.assertEqual(self.post("/session-approvals", action="approve", id=foreign["id"]).status_code, 404)
        self.assertEqual(self.post("/me/session-approvals", action="cancel", id=record["id"]).status_code, 404)
        self.login(self.alice)
        self.assertEqual(self.post("/me/session-approvals", action="cancel", id=record["id"]).status_code, 302)
        self.assertEqual(get_session_approval(self.redis, record["id"])["status"], "cancelled")

    def test_approval_routes_require_csrf_and_explicit_confirmation(self):
        record, _ = self.approval()
        self.login(self.approver)
        self.assertEqual(self.client.post("/session-approvals", data={"action": "approve", "id": record["id"]}).status_code, 403)
        self.client.post("/session-approvals", data={"csrf_token": "csrf", "action": "approve", "id": record["id"]})
        self.assertEqual(get_session_approval(self.redis, record["id"])["approvals"], [])
        self.login(self.auditor)
        self.assertEqual(self.post("/session-approvals", action="approve", id=record["id"]).status_code, 403)

    def test_configuration_rejects_invalid_scopes_and_approval_limits(self):
        config = dict(self.config, session_approval={"enabled": True, "minimum_approvals": 0})
        config["dashboard"] = dict(self.config["dashboard"], role_bindings=[{"group": "G", "role": "auditor"}])
        result = validate_config(config)
        self.assertFalse(result["valid"])
        self.assertTrue(any("explicit projects" in error for error in result["errors"]))
        self.assertTrue(any("minimum_approvals" in error for error in result["errors"]))

    def test_notification_failure_is_reported_and_action_remains_auditable(self):
        record, _ = self.approval()
        self.login(self.approver)
        with mock.patch("isolate_session_approval_web.notify_session_approval_event", side_effect=NotificationError("delivery failed")):
            response = self.post("/session-approvals", action="approve", id=record["id"])
        self.assertEqual(response.status_code, 200)
        current = get_session_approval(self.redis, record["id"])
        self.assertEqual(current["status"], "approved")
        self.assertFalse(current["notification_status"]["ok"])

    def test_old_queued_job_cannot_bypass_new_gate_and_fleet_rejects_before_writes(self):
        key_path = os.path.join(self.fixture.tmp.name, "jobs.key")
        with open(key_path, "wb") as output:
            output.write(b"test-job-signing-key-with-enough-bytes")
        config = dict(self.config, command_execution={"enabled": True, "allowed_groups": ["Support"], "allowed_command_patterns": ["^true$"], "signing_key_file": key_path, "jobs_path": self.fixture.tmp.name})
        grant = {"id": "1", "subject": "group", "name": "Support", "project": "prod", "remote_user": "support", "sudo_mode": "none", "allowed_actions": ["command", "runbook"]}
        self.redis.set("grant_1", json.dumps(grant))
        decision = resolve_grant(self.alice, project="prod", host=self.host, grants=[grant], action="command")
        job = create_command_job(self.redis, config, self.alice, self.host, decision, "true")
        config["session_approval"] = {"enabled": True, "required_projects": ["prod"]}
        with mock.patch.object(isolate_jobs.subprocess, "Popen") as process:
            result = execute_job(self.redis, config, job)
            self.assertEqual(result["status"], "failed")
            self.assertIn("human session approval", result["error"])
            process.assert_not_called()
        with self.assertRaisesRegex(JobError, "human session approval"):
            create_command_job(self.redis, config, self.alice, self.host, decision, "true")
        config["runbooks"] = {"enabled": True, "read_only": {"allowed_groups": ["Support"]}}
        with self.assertRaisesRegex(JobError, "human session approval"):
            create_runbook_fleet(self.redis, config, self.alice, "uptime", [self.host["server_id"]], confirmed=True)
        self.assertEqual(len([key for key in self.redis.keys("job_*") if re.fullmatch(r"job_\d+", key)]), 1)


if __name__ == "__main__":
    unittest.main()
