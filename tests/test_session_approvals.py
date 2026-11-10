"""Regression tests for single-use session approvals at the SSH boundary."""

import copy
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import isolate_connection_auth as auth
import isolate_session_approvals as approvals
from test_access_lifecycle import MemoryPipeline, MemoryRedis, TransactionRedis
from test_ssh_wrapper import RecordingAudit, ssh_wrapper


class SessionApprovalsTest(unittest.TestCase):
    def setUp(self):
        self.redis = MemoryRedis()
        self.owner = {"username": "alice", "keycloak_sub": "alice-sub", "groups": ["Support"], "exp": 2000}
        self.approver = {"username": "manager", "keycloak_sub": "manager-sub", "groups": ["Prod-Approvers"]}
        self.second = {"username": "security", "keycloak_sub": "security-sub", "groups": ["Prod-Approvers"]}
        self.foreign = {"username": "foreign", "keycloak_sub": "foreign-sub", "groups": ["Stage-Approvers"]}
        self.config = {
            "dashboard": {"admin_groups": ["Admins"], "role_bindings": [
                {"group": "Prod-Approvers", "role": "approver", "projects": ["prod"]},
                {"group": "Stage-Approvers", "role": "approver", "projects": ["stage"]},
            ]},
            "session_approval": {"enabled": True, "required_projects": ["prod"], "max_session_seconds": 100},
            "connection_authorization": {"max_session_seconds": 600},
            "ssh": {"default_sudo_mode": "none"}, "session_control": {"enabled": False},
        }
        self.host = {"server_id": "10001", "project_name": "prod", "server_ip": "192.0.2.1", "server_port": 22}
        self.grant = {"id": "1", "subject": "group", "name": "Support", "project": "prod", "remote_user": "support", "sudo_mode": "none", "allowed_actions": ["ssh"]}
        self.decision = {"remote_user": "support", "sudo_mode": "none", "matched_rule": self.grant}
        self.args = SimpleNamespace(host_id="10001", hostname=["192.0.2.1"], user=["support"], port=22, nosudo=True,
            project="prod", human_user="alice", keycloak_sub="alice-sub", proxy_host=None, proxy_user=None, proxy_port=None)
        self.redis.set("server_10001", json.dumps(self.host))
        self.redis.set("grant_1", json.dumps(self.grant))
        self.clock = mock.patch("isolate_session_approvals.time.time", return_value=1000)
        self.time = self.clock.start()
        self.addCleanup(self.clock.stop)
        patcher = mock.patch.object(auth, "bind_identity", return_value=self.owner)
        patcher.start()
        self.addCleanup(patcher.stop)

    def request(self, **kwargs):
        return approvals.request_session_approval(self.redis, self.config, self.owner, self.host,
            self.decision, "conn-1", **kwargs)

    def approve(self, request, actor=None):
        return approvals.decide_session_approval(self.redis, self.config, request["id"], actor or self.approver)

    def consume(self, request, **kwargs):
        return approvals.consume_session_approval(self.redis, self.config, request["id"], self.owner,
            self.host, self.decision, "conn-1", **kwargs)

    def context(self):
        return auth.authorize_connection(self.args, "token", self.config, self.redis, "alice")

    def test_optin_selectors_and_privileged_requirement(self):
        self.assertTrue(approvals.session_approval_required(self.config, self.host, self.decision))
        self.assertFalse(approvals.session_approval_required({}, self.host, self.decision))
        config = {"session_approval": {"enabled": True}}
        self.assertFalse(approvals.session_approval_required(config, self.host, self.decision))
        config["session_approval"].update(required_project_globs=["pr*"])
        self.assertTrue(approvals.session_approval_required(config, self.host, self.decision))
        config["session_approval"].update(required_project_globs=[], require_privileged=True)
        self.assertFalse(approvals.session_approval_required(config, self.host, self.decision))
        self.assertTrue(approvals.session_approval_required(config, self.host, dict(self.decision, remote_user="root")))

    def test_pending_never_grants_access_and_consume_is_single_use(self):
        request = self.request()
        with self.assertRaises(approvals.SessionApprovalDenied):
            self.consume(request)
        self.approve(request)
        active = self.consume(request)
        self.assertEqual(active["status"], "active")
        self.assertEqual(active["session_expires_at"], 1100)
        with self.assertRaises(approvals.SessionApprovalDenied):
            self.consume(request)
        approvals.close_session_approval(self.redis, request["id"])
        self.assertEqual(approvals.get_session_approval(self.redis, request["id"])["status"], "closed")

    def test_privileged_requires_two_distinct_humans_and_no_self_approval(self):
        self.decision.update(remote_user="root")
        request = self.request()
        self.assertEqual(request["required_approvals"], 2)
        self.assertEqual(self.approve(request)["status"], "pending")
        with self.assertRaisesRegex(approvals.SessionApprovalDenied, "already approved"):
            self.approve(request)
        self.assertEqual(self.approve(request, self.second)["status"], "approved")
        own = self.request()
        with self.assertRaisesRegex(approvals.SessionApprovalDenied, "self-approval"):
            self.approve(own, dict(self.owner, username="renamed-alice", groups=["Admins"]))

    def test_approver_scope_and_stable_subject_are_required(self):
        request = self.request()
        for actor in (self.foreign, {"username": "manager", "groups": ["Admins"]}):
            with self.subTest(actor=actor), self.assertRaises(approvals.SessionApprovalDenied):
                self.approve(request, actor)

    def test_destination_policy_identity_connection_and_source_are_bound(self):
        request = self.request(source_ip="192.0.2.25")
        self.approve(request)
        variants = [
            {"identity": dict(self.owner, keycloak_sub="other")},
            {"host": dict(self.host, server_ip="192.0.2.2")},
            {"decision": dict(self.decision, remote_user="root")},
            {"decision": dict(self.decision, matched_rule=dict(self.grant, id="2"))},
            {"connection_id": "conn-2"}, {"source_ip": "192.0.2.99"},
        ]
        for variant in variants:
            values = {"identity": self.owner, "host": self.host, "decision": self.decision,
                      "connection_id": "conn-1", "source_ip": "192.0.2.25"}
            values.update(variant)
            with self.subTest(variant=variant), self.assertRaises(approvals.SessionApprovalDenied):
                approvals.consume_session_approval(self.redis, self.config, request["id"], **values)
        self.assertEqual(approvals.get_session_approval(self.redis, request["id"])["status"], "approved")

    def test_expiry_denial_cancel_and_revocation_fail_closed(self):
        request = self.request()
        self.time.return_value = 1300
        self.assertEqual(approvals.get_session_approval(self.redis, request["id"])["status"], "expired")
        with self.assertRaises(approvals.SessionApprovalDenied):
            self.approve(request)
        self.time.return_value = 1000
        denied = self.request()
        approvals.decide_session_approval(self.redis, self.config, denied["id"], self.approver, approve=False, reason="denied")
        with self.assertRaises(approvals.SessionApprovalDenied):
            self.consume(denied)
        cancelled = self.request()
        with self.assertRaises(approvals.SessionApprovalDenied):
            approvals.cancel_session_approval(self.redis, self.config, cancelled["id"], self.second)
        approvals.cancel_session_approval(self.redis, self.config, cancelled["id"], self.owner)
        self.assertEqual(approvals.get_session_approval(self.redis, cancelled["id"])["status"], "cancelled")
        active = self.request()
        self.approve(active)
        self.consume(active)
        approvals.revoke_session_approval(self.redis, self.config, active["id"], self.approver)
        with self.assertRaises(approvals.SessionApprovalDenied):
            approvals.validate_session_approval(self.redis, self.config, active["id"], self.owner, self.host, self.decision, "conn-1")

    def test_current_quorum_and_role_bindings_rechecked(self):
        request = self.request()
        self.approve(request)
        self.config["session_approval"]["minimum_approvals"] = 2
        with self.assertRaises(approvals.SessionApprovalDenied):
            self.consume(request)
        self.config["session_approval"]["minimum_approvals"] = 1
        self.config["dashboard"]["role_bindings"] = []
        with self.assertRaises(approvals.SessionApprovalDenied):
            self.consume(request)

    def test_approval_ttl_and_identity_grant_deadlines_bound_session(self):
        request = self.request()
        self.approve(request)
        self.time.return_value = 1300
        with self.assertRaises(approvals.SessionApprovalDenied):
            self.consume(request)
        self.time.return_value = 1000
        self.owner["exp"] = 1025
        self.grant["expires_at"] = 1020
        request = self.request()
        self.approve(request)
        self.assertEqual(self.consume(request)["session_expires_at"], 1020)

    def test_concurrent_approval_does_not_duplicate_votes(self):
        self.redis = TransactionRedis()
        self.config["session_approval"]["minimum_approvals"] = 2
        request = self.request()
        self.redis.before_execute = lambda: self.approve(request)
        with self.assertRaisesRegex(approvals.SessionApprovalDenied, "already approved"):
            self.approve(request)
        self.assertEqual(len(approvals.get_session_approval(self.redis, request["id"])["approvals"]), 1)

    def test_concurrent_consume_starts_at_most_one_session(self):
        self.redis = TransactionRedis()
        request = self.request()
        self.approve(request)
        self.redis.before_execute = lambda: self.consume(request)
        with self.assertRaises(approvals.SessionApprovalDenied):
            self.consume(request)
        self.assertEqual(approvals.get_session_approval(self.redis, request["id"])["status"], "active")

    def test_falsy_redis_pipeline_still_buffers_mutations_until_execute(self):
        class FalsyPipeline(MemoryPipeline):
            def __bool__(self):
                return False
        class Redis(TransactionRedis):
            def pipeline(self, transaction=True):
                return FalsyPipeline(self)
        self.redis = Redis()
        request = self.request()
        created_transactions = self.redis.executions
        self.approve(request)
        self.consume(request)
        self.assertEqual(self.redis.executions, created_transactions + 2)
        self.assertEqual(approvals.get_session_approval(self.redis, request["id"])["status"], "active")

    def test_missing_object_project_fails_closed_even_for_global_admin(self):
        request = self.request()
        record = copy.deepcopy(request)
        record["project"] = None
        self.redis.set("session_approval_" + request["id"], json.dumps(record))
        with self.assertRaisesRegex(approvals.SessionApprovalDenied, "scope"):
            self.approve(request, dict(self.approver, groups=["Admins"]))

    def test_wait_revalidates_policy_and_only_returns_after_approval(self):
        requested = []
        events = []
        def event(name, record):
            requested.append(record["id"])
            events.append(name)
        def decide(_interval):
            request = approvals.get_session_approval(self.redis, requested[0])
            self.assertEqual(request["status"], "pending")
            self.approve(request)
        result = auth.wait_for_connection_approval(self.context(), self.config, self.redis, "conn-1", on_event=event, sleeper=decide)
        self.assertEqual(result["session_approval_id"], requested[0])
        self.assertEqual(result["deadline"], 1100)
        self.assertEqual(events, ["session_approval_requested", "session_approval_consumed"])
        self.assertEqual(auth.recheck_connection(result, self.config, self.redis)["deadline"], 1100)
        approvals.revoke_session_approval(self.redis, self.config, requested[0], self.approver)
        with self.assertRaises(auth.ConnectionDenied):
            auth.recheck_connection(result, self.config, self.redis)

    def test_wait_aborts_if_grant_is_removed_before_decision(self):
        def remove(_interval):
            self.redis.delete("grant_1")
        with self.assertRaises(Exception):
            auth.wait_for_connection_approval(self.context(), self.config, self.redis, "conn-1", sleeper=remove)
        self.assertEqual(approvals.list_session_approvals(self.redis)[0]["status"], "cancelled")

    def test_wrapper_does_not_start_ssh_before_approval_and_closes_afterwards(self):
        audit = RecordingAudit()
        def decision(_interval):
            self.approve(approvals.list_session_approvals(self.redis)[0])
        def execute(argv, raw_log, control):
            self.assertEqual(approvals.list_session_approvals(self.redis)[0]["status"], "active")
            self.assertFalse(control())
            return 0
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ssh_wrapper, "_redis_client", return_value=self.redis), \
                mock.patch.object(ssh_wrapper, "trusted_config", return_value=self.config), \
                mock.patch.object(auth.time, "sleep", side_effect=decision), \
                mock.patch.object(ssh_wrapper, "_run_pipe_command", side_effect=execute) as run, \
                mock.patch.object(ssh_wrapper.sys.stdin, "isatty", return_value=False):
            result = ssh_wrapper.run_command(["ssh"], os.path.join(directory, "raw.log"), audit,
                {"connection_id": "conn-1"}, config=self.config, authorization=self.context())
        self.assertEqual(result, 0)
        run.assert_called_once()
        self.assertEqual([name for name, _ in audit.events], ["session_approval_requested", "session_approval_consumed", "ssh_start", "ssh_end"])
        self.assertEqual(approvals.list_session_approvals(self.redis)[0]["status"], "closed")

    def test_wrapper_denial_timeout_and_policy_change_start_no_subprocess(self):
        for outcome in ("denied", "timeout", "policy"):
            with self.subTest(outcome=outcome):
                self.redis = MemoryRedis()
                self.redis.set("server_10001", json.dumps(self.host))
                self.redis.set("grant_1", json.dumps(self.grant))
                self.time.return_value = 1000
                def decision(_interval):
                    request = approvals.list_session_approvals(self.redis)[0]
                    if outcome == "denied":
                        approvals.decide_session_approval(self.redis, self.config, request["id"], self.approver, approve=False)
                    elif outcome == "timeout":
                        self.time.return_value = 1400
                    else:
                        self.redis.delete("grant_1")
                with tempfile.TemporaryDirectory() as directory, \
                        mock.patch.object(ssh_wrapper, "_redis_client", return_value=self.redis), \
                        mock.patch.object(ssh_wrapper, "trusted_config", return_value=self.config), \
                        mock.patch.object(auth.time, "sleep", side_effect=decision), \
                        mock.patch.object(ssh_wrapper, "_run_pipe_command") as pipe, \
                        mock.patch.object(ssh_wrapper, "_run_pty_command") as pty:
                    result = ssh_wrapper.run_command(["ssh"], os.path.join(directory, "raw.log"), RecordingAudit(),
                        {"connection_id": "conn-1"}, config=self.config, authorization=self.context())
                self.assertEqual(result, 2)
                pipe.assert_not_called()
                pty.assert_not_called()

    def test_wrapper_fail_closed_notification_cancels_without_subprocess(self):
        self.config["notifications"] = {"enabled": True, "fail_closed": True}
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ssh_wrapper, "_redis_client", return_value=self.redis), \
                mock.patch.object(ssh_wrapper, "trusted_config", return_value=self.config), \
                mock.patch("isolate_notifications.notify_session_approval_event", create=True, side_effect=RuntimeError("sink down")), \
                mock.patch.object(ssh_wrapper, "_run_pipe_command") as pipe, \
                mock.patch.object(ssh_wrapper, "_run_pty_command") as pty:
            result = ssh_wrapper.run_command(["ssh"], os.path.join(directory, "raw.log"), RecordingAudit(),
                {"connection_id": "conn-1"}, config=self.config, authorization=self.context())
        self.assertEqual(result, 2)
        pipe.assert_not_called()
        pty.assert_not_called()
        record = approvals.list_session_approvals(self.redis)[0]
        self.assertEqual(record["status"], "cancelled")
        self.assertFalse(record["notification_status"]["ok"])

    def test_new_required_approval_is_enforced_on_an_existing_connection(self):
        context = self.context()
        with self.assertRaisesRegex(auth.ConnectionDenied, "requires administrator approval"):
            auth.recheck_connection(context, self.config, self.redis)

    def test_stricter_request_deadline_is_persisted_and_cannot_be_extended(self):
        request = self.request()
        self.time.return_value = 1010
        self.config["session_approval"]["request_timeout_seconds"] = 20
        self.assertEqual(approvals.get_session_approval(self.redis, request["id"], config=self.config)["request_expires_at"], 1020)
        self.config["session_approval"]["request_timeout_seconds"] = 300
        self.assertEqual(approvals.get_session_approval(self.redis, request["id"], config=self.config)["request_expires_at"], 1020)
        self.time.return_value = 1020
        with self.assertRaises(approvals.SessionApprovalDenied):
            self.approve(request)
        self.assertEqual(approvals.get_session_approval(self.redis, request["id"])["status"], "expired")

    def test_stricter_approval_and_active_lifetime_expire_before_launch_or_recheck(self):
        request = self.request()
        self.approve(request)
        self.config["session_approval"]["approval_ttl_seconds"] = 5
        self.time.return_value = 1005
        with self.assertRaises(approvals.SessionApprovalDenied):
            self.consume(request)
        self.assertEqual(approvals.get_session_approval(self.redis, request["id"])["approval_expires_at"], 1005)
        self.time.return_value = 1000
        self.config["session_approval"]["approval_ttl_seconds"] = 300
        active = self.request()
        self.approve(active)
        self.consume(active)
        self.time.return_value = 1010
        self.config["session_approval"]["max_session_seconds"] = 20
        result = approvals.validate_session_approval(self.redis, self.config, active["id"], self.owner, self.host, self.decision, "conn-1")
        self.assertEqual(result["session_expires_at"], 1020)
        self.config["session_approval"]["max_session_seconds"] = 1000
        self.assertEqual(approvals.validate_session_approval(self.redis, self.config, active["id"], self.owner, self.host, self.decision, "conn-1")["session_expires_at"], 1020)
        self.time.return_value = 1020
        with self.assertRaises(approvals.SessionApprovalDenied):
            approvals.validate_session_approval(self.redis, self.config, active["id"], self.owner, self.host, self.decision, "conn-1")

    def test_wait_observes_shortened_timeout_without_starting_ssh(self):
        def tighten(_interval):
            self.config["session_approval"]["request_timeout_seconds"] = 5
            self.time.return_value = 1005
        with self.assertRaisesRegex(auth.ConnectionDenied, "expired"):
            auth.wait_for_connection_approval(self.context(), self.config, self.redis, "conn-1", sleeper=tighten)

    def test_proxy_requiring_approval_cannot_bypass_via_unprotected_target(self):
        self.config["connection_authorization"]["allow_proxy"] = True
        self.host.update(project_name="stage", proxy_id="10002")
        self.grant["project"] = "stage"
        self.args.project = "stage"
        self.redis.set("server_10001", json.dumps(self.host))
        self.redis.set("grant_1", json.dumps(self.grant))
        self.redis.set("server_10002", json.dumps({"server_id": "10002", "project_name": "prod", "server_ip": "192.0.2.2", "server_port": 22}))
        self.redis.set("grant_2", json.dumps(dict(self.grant, id="2", project="prod", host="10002", remote_user="root")))
        with self.assertRaisesRegex(auth.ConnectionDenied, "proxy requires session approval"):
            self.context()

    def test_wrapper_honors_shortened_deadline_before_next_poll_interval(self):
        self.config["connection_authorization"]["recheck_interval"] = 60
        def decision(_interval):
            self.approve(approvals.list_session_approvals(self.redis)[0])
        def execute(argv, raw_log, control):
            self.time.return_value = 1010
            self.config["session_approval"]["max_session_seconds"] = 20
            self.assertFalse(control(force=True))
            self.time.return_value = 1020
            self.assertTrue(control())
            return 143
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ssh_wrapper, "_redis_client", return_value=self.redis), \
                mock.patch.object(ssh_wrapper, "trusted_config", return_value=self.config), \
                mock.patch.object(auth.time, "sleep", side_effect=decision), \
                mock.patch.object(ssh_wrapper, "_run_pipe_command", side_effect=execute), \
                mock.patch.object(ssh_wrapper.sys.stdin, "isatty", return_value=False):
            result = ssh_wrapper.run_command(["ssh"], os.path.join(directory, "raw.log"), RecordingAudit(),
                {"connection_id": "conn-1"}, config=self.config, authorization=self.context())
        self.assertEqual(result, 143)


if __name__ == "__main__":
    unittest.main()
