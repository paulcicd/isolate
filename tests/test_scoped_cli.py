"""Trusted CLI scope checks and single-session approval decisions."""

import fnmatch
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import isolate
from isolate_access import create_access_request, get_access_request
from isolate_session_approvals import get_session_approval, request_session_approval


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

    def keys(self, pattern):
        return [key for key in self.data if fnmatch.fnmatchcase(key, pattern)]

    def incr(self, key):
        value = int(self.data.get(key, 0)) + 1
        self.data[key] = value
        return value

    def delete(self, key):
        return self.data.pop(key, None) is not None


class ScopedCLITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.redis = MemoryRedis()
        self.config = {"dashboard": {"admin_groups": ["Admins"], "role_bindings": [
            {"group": "Operators", "role": "inventory-operator", "projects": ["payments"]},
            {"group": "Approvers", "role": "approver", "projects": ["payments"]},
            {"group": "Auditors", "role": "auditor", "projects": ["payments"]},
        ]}, "access": {"admin_groups": ["Admins"], "default_ttl": "1h", "max_ttl": "24h"},
            "history": {"max_limit": 100}, "logging": {"base_path": self.tmp.name},
            "session_approval": {"enabled": True, "required_projects": ["payments", "secret"]}}
        self.operator = self.identity("operator", ["Operators"])
        self.approver = self.identity("approver", ["Approvers"])
        self.auditor = self.identity("auditor", ["Auditors"])
        self.admin = self.identity("admin", ["Admins"])
        self.requester = self.identity("requester", ["Users"])
        for host_id, project in (("1", "payments"), ("2", "secret")):
            self.redis.set("server_" + host_id, json.dumps({"server_id": host_id, "project_name": project,
                "server_name": "host-" + host_id, "server_ip": "192.0.2." + host_id, "server_user": "support", "server_port": 22}))
        self.parser = isolate.build_parser()

    def identity(self, name, groups):
        return {"username": name, "keycloak_sub": "sub-" + name, "groups": groups, "exp": int(time.time()) + 3600}

    def invoke(self, argv, identity=None, passed_config=None):
        identity = identity or self.operator
        args = self.parser.parse_args(argv)
        stdout, stderr = StringIO(), StringIO()
        with mock.patch.object(isolate, "_management_context", return_value=(self.config, identity)), \
                mock.patch.object(isolate, "_job_context", return_value=(self.config, identity)), \
                mock.patch.object(isolate, "redis_client", return_value=self.redis), \
                mock.patch.object(isolate, "prepare_and_dispatch"), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = args.func(args, passed_config or self.config) or 0
        return code, stdout.getvalue(), stderr.getvalue()

    def request(self, project="payments"):
        return create_access_request(self.redis, self.requester, project, reason="incident", remote_user="support")

    def session_request(self, project="payments", privileged=False):
        host = json.loads(self.redis.get("server_1" if project == "payments" else "server_2"))
        return request_session_approval(self.redis, self.config, self.requester, host,
            {"remote_user": "root" if privileged else "support", "sudo_mode": "none", "matched_rule": {"id": "grant-1"}},
            "connection-" + project)

    def test_host_list_show_and_export_do_not_leak_other_projects(self):
        for argv in (["host", "list", "--json"], ["export", "inventory", "--format", "json"]):
            code, output, error = self.invoke(argv)
            self.assertEqual(code, 0, error)
            self.assertEqual([row["server_id"] for row in json.loads(output)], ["1"])
        self.assertEqual(self.invoke(["host", "show", "2"])[0], 2)
        self.assertEqual(self.invoke(["host", "services-history", "2"])[0], 2)

    def test_metadata_update_is_scoped_and_owner_environment_supported(self):
        code, output, error = self.invoke(["host", "update", "1", "--owner", "payments-team", "--environment", "prod"])
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["resource_owner"], "payments-team")
        self.assertEqual(json.loads(output)["environment"], "prod")
        self.assertEqual(self.invoke(["host", "update", "2", "--note", "forbidden"])[0], 2)
        self.assertNotIn("server_note", json.loads(self.redis.get("server_2")))

    def test_scope_operator_cannot_retarget_or_change_privilege_or_move_outside_scope(self):
        for flags in (["--ip", "192.0.2.99"], ["--user", "root"], ["--vip", "true"],
                      ["--proxy-id", "2"], ["--project", "secret"]):
            with self.subTest(flags=flags):
                self.assertEqual(self.invoke(["host", "update", "1"] + flags)[0], 2)
        host = json.loads(self.redis.get("server_1"))
        self.assertEqual(host["project_name"], "payments")
        self.assertEqual(host["server_ip"], "192.0.2.1")

    def test_only_authorized_global_admin_can_change_routing(self):
        code, output, error = self.invoke(["host", "update", "1", "--ip", "192.0.2.99"], self.admin)
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["server_ip"], "192.0.2.99")

    def test_auditor_cannot_modify_inventory_or_probe_ssh_credentials(self):
        self.assertEqual(self.invoke(["host", "update", "1", "--note", "write"], self.auditor)[0], 2)
        with mock.patch.object(isolate, "check_host") as check:
            self.assertEqual(self.invoke(["host", "check", "1", "--ssh"])[0], 2)
            self.assertEqual(self.invoke(["host", "check", "--project", "secret"])[0], 2)
            check.assert_not_called()

    def test_privileged_export_kinds_remain_global_admin_only(self):
        for kind in ("users", "grants", "access-matrix"):
            self.assertEqual(self.invoke(["export", kind, "--format", "json"], self.auditor)[0], 2)

    def test_access_list_show_and_approval_are_scoped_to_request_project(self):
        allowed, forbidden = self.request(), self.request("secret")
        code, output, error = self.invoke(["access", "list", "--json"], self.approver)
        self.assertEqual(code, 0, error)
        self.assertEqual([row["id"] for row in json.loads(output)], [allowed["id"]])
        self.assertEqual(self.invoke(["access", "show", "--id", forbidden["id"]], self.approver)[0], 2)
        self.assertEqual(self.invoke(["access", "approve", "--id", forbidden["id"]], self.approver)[0], 2)
        code, _, error = self.invoke(["access", "approve", "--id", allowed["id"]], self.approver)
        self.assertEqual(code, 0, error)
        self.assertEqual(get_access_request(self.redis, allowed["id"])["status"], "approved")
        self.assertEqual(get_access_request(self.redis, forbidden["id"])["status"], "pending")

    def test_scoped_approval_revoke_and_auditor_denial(self):
        record = self.request()
        self.assertEqual(self.invoke(["access", "approve", "--id", record["id"]], self.auditor)[0], 2)
        self.assertEqual(self.invoke(["access", "approve", "--id", record["id"]], self.approver)[0], 0)
        self.assertEqual(self.invoke(["access", "revoke", "--id", record["id"], "--reason", "finished", "--yes"], self.approver)[0], 0)
        self.assertEqual(get_access_request(self.redis, record["id"])["status"], "revoked")

    def test_user_owned_request_visibility_uses_stable_subject(self):
        record = self.request()
        renamed = dict(self.requester, username="renamed")
        self.assertEqual(self.invoke(["access", "show", "--id", record["id"]], renamed)[0], 0)
        reused = dict(self.requester, keycloak_sub="new-sub")
        self.assertEqual(self.invoke(["access", "show", "--id", record["id"]], reused)[0], 2)

    def test_session_list_and_decisions_require_project_and_explicit_confirmation(self):
        allowed, forbidden = self.session_request(), self.session_request("secret")
        code, output, error = self.invoke(["session", "approval", "list", "--json"], self.approver)
        self.assertEqual(code, 0, error)
        self.assertEqual([row["id"] for row in json.loads(output)], [allowed["id"]])
        self.assertEqual(self.invoke(["session", "approval", "approve", allowed["id"]], self.approver)[0], 2)
        self.assertEqual(self.invoke(["session", "approval", "approve", forbidden["id"], "--yes"], self.approver)[0], 2)
        code, _, error = self.invoke(["session", "approval", "approve", allowed["id"], "--yes"], self.approver)
        self.assertEqual(code, 0, error)
        self.assertEqual(get_session_approval(self.redis, allowed["id"])["status"], "approved")

    def test_session_privileged_quorum_distinct_subject_and_self_approval_rejected(self):
        record = self.session_request(privileged=True)
        self.assertEqual(self.invoke(["session", "approval", "approve", record["id"], "--yes"], self.requester)[0], 2)
        self.assertEqual(self.invoke(["session", "approval", "approve", record["id"], "--yes"], self.approver)[0], 0)
        self.assertEqual(get_session_approval(self.redis, record["id"])["status"], "pending")
        self.assertEqual(self.invoke(["session", "approval", "approve", record["id"], "--yes"], self.approver)[0], 2)
        second = self.identity("approver-two", ["Approvers"])
        self.assertEqual(self.invoke(["session", "approval", "approve", record["id"], "--yes"], second)[0], 0)
        self.assertEqual(get_session_approval(self.redis, record["id"])["status"], "approved")

    def test_session_decisions_never_use_local_root_shortcut(self):
        record = self.session_request()
        with mock.patch.object(isolate, "_management_context", return_value=(self.config, {"username": "root", "_local_root": True})), \
                mock.patch.object(isolate, "_job_context", side_effect=isolate.AccessDenied("human identity required")), \
                redirect_stderr(StringIO()):
            args = self.parser.parse_args(["session", "approval", "approve", record["id"], "--yes"])
            self.assertEqual(args.func(args, self.config), 2)
        self.assertEqual(get_session_approval(self.redis, record["id"])["status"], "pending")

    def test_delegated_mutations_ignore_untrusted_argument_configuration(self):
        malicious = {"dashboard": {"admin_groups": ["Auditors"]}, "redis": {"host": "attacker"}}
        self.assertEqual(self.invoke(["host", "update", "2", "--note", "no"], self.auditor, passed_config=malicious)[0], 2)

    def test_history_and_export_apply_scoped_visibility_before_limit(self):
        for connection, project, ts in (("allowed", "payments", 100), ("forbidden", "secret", 200)):
            directory = os.path.join(self.tmp.name, "bob", connection)
            os.makedirs(directory)
            with open(os.path.join(directory, "session.jsonl"), "w", encoding="utf-8") as output:
                output.write(json.dumps({"event": "ssh_start", "connection_id": connection,
                    "username": "bob", "keycloak_sub": "sub-bob", "project": project, "ts": ts}) + "\n")
        for argv in (["history", "--json", "--limit", "1"], ["export", "history", "--format", "json", "--limit", "1"]):
            code, output, error = self.invoke(argv, self.auditor)
            self.assertEqual(code, 0, error)
            self.assertEqual([row["connection_id"] for row in json.loads(output)], ["allowed"])

    def test_delegated_context_uses_trusted_binding_and_preserves_local_root_admin(self):
        with mock.patch.object(isolate.os, "name", "posix"), \
                mock.patch.object(isolate.os, "geteuid", return_value=1000, create=True), \
                mock.patch.object(isolate, "_job_context", return_value=(self.config, self.operator)) as context:
            self.assertEqual(isolate._management_context({"untrusted": True}), (self.config, self.operator))
            context.assert_called_once_with()
        with mock.patch.object(isolate.os, "name", "posix"), \
                mock.patch.object(isolate.os, "geteuid", return_value=0, create=True), \
                mock.patch.object(isolate, "_job_context") as context:
            config, identity = isolate._management_context(self.config)
            self.assertIs(config, self.config)
            self.assertTrue(isolate._management_admin(identity, config))
            context.assert_not_called()

    def test_session_event_search_denies_missing_and_foreign_projects(self):
        directory = os.path.join(self.tmp.name, "bob", "session")
        os.makedirs(directory)
        with open(os.path.join(directory, "session.jsonl"), "w", encoding="utf-8") as output:
            for event in ({"project": "payments", "event": "allowed"}, {"project": "secret", "event": "forbidden"}, {"event": "unscoped"}):
                output.write(json.dumps(event) + "\n")
        code, output, error = self.invoke(["session", "search"], self.auditor)
        self.assertEqual(code, 0, error)
        self.assertEqual([json.loads(line)["event"] for line in output.splitlines()], ["allowed"])


if __name__ == "__main__":
    unittest.main()
