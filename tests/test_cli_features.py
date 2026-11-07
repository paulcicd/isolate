"""CLI authorization, fleet selection, and public access lifecycle integration."""

import fnmatch
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
import isolate
import isolate_connection_auth
import isolate_identity
from isolate_access import create_access_request, get_access_request


class MemoryRedis:
    def __init__(self):
        self.store = {}

    def keys(self, pattern):
        return [key for key in self.store if fnmatch.fnmatchcase(key, pattern)]

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value, **kwargs):
        self.store[key] = value
        return True

    def delete(self, key):
        return int(self.store.pop(key, None) is not None)

    def incr(self, key):
        value = int(self.store.get(key, 0)) + 1
        self.store[key] = value
        return value


class CLIFeatureTests(unittest.TestCase):
    def setUp(self):
        self.redis = MemoryRedis()
        self.identity = {"username": "alex", "keycloak_sub": "subject-alex", "groups": ["Operators"], "roles": []}
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        key_path = os.path.join(self.temp.name, "job.key")
        with open(key_path, "wb") as stream:
            stream.write(b"s" * 32)
        self.config = {
            "logging": {"base_path": self.temp.name},
            "history": {"max_limit": 100},
            "access": {"admin_groups": ["Admins"]},
            "dashboard": {"admin_groups": ["Admins"], "role_bindings": [
                {"group": "Operators", "role": "inventory-operator", "projects": ["payments"]},
            ]},
            "command_execution": {"signing_key_file": key_path, "jobs_path": self.temp.name, "max_timeout": 900},
            "runbooks": {"enabled": True, "max_fleet_hosts": 10,
                         "read_only": {"allowed_groups": ["Operators"], "allow_sudo": False}},
        }
        for host_id, env in (("1", "prod"), ("2", "stage")):
            self.redis.set("server_" + host_id, json.dumps({
                "server_id": host_id, "server_name": "host-" + host_id,
                "server_ip": "192.0.2." + host_id, "project_name": "payments",
                "tags": {"env": env, "owner": "payments"},
            }))
        self.redis.set("grant_1", json.dumps({
            "subject": "group", "name": "Operators", "project": "payments",
            "remote_user": "support", "sudo_mode": "none", "allowed_actions": ["runbook"],
        }))
        self.parser = isolate.build_parser()

    def invoke(self, argv, identity=None):
        args = self.parser.parse_args(argv)
        stdout, stderr = StringIO(), StringIO()
        with mock.patch.object(isolate, "redis_client", return_value=self.redis), \
                mock.patch.object(isolate, "_load_cli_identity", return_value=identity or self.identity), \
                mock.patch.object(isolate, "_job_context", return_value=(self.config, identity or self.identity)), \
                mock.patch.object(isolate, "prepare_and_dispatch"), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = args.func(args, self.config) or 0
        return code, stdout.getvalue(), stderr.getvalue()

    def test_own_job_list_never_includes_another_user(self):
        self.redis.set("job_1", json.dumps({"id": "1", "username": "alex", "status": "queued"}))
        self.redis.set("job_2", json.dumps({"id": "2", "username": "bailey", "status": "queued"}))
        code, output, _ = self.invoke(["job", "list", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual([job["id"] for job in json.loads(output)], ["1"])
        self.assertEqual(self.invoke(["job", "list", "--user", "bailey"])[0], 2)

    def test_another_users_job_cannot_be_viewed_read_or_cancelled(self):
        self.redis.set("job_1", json.dumps({"id": "1", "username": "bailey", "status": "queued"}))
        for command in ("show", "output", "cancel", "retry"):
            with self.subTest(command=command):
                argv = ["job", command, "1"] + (["--yes"] if command in ("cancel", "retry") else [])
                self.assertEqual(self.invoke(argv)[0], 2)
        self.assertNotIn("cancel_requested", json.loads(self.redis.get("job_1")))

    def test_cancel_requires_explicit_confirmation(self):
        self.redis.set("job_1", json.dumps({"id": "1", "username": "alex", "status": "queued"}))
        self.assertEqual(self.invoke(["job", "cancel", "1"])[0], 2)
        self.assertEqual(json.loads(self.redis.get("job_1"))["status"], "queued")
        self.assertEqual(self.invoke(["job", "cancel", "1", "--yes"])[0], 0)
        self.assertEqual(json.loads(self.redis.get("job_1"))["status"], "cancelled")

    def test_reassigned_username_does_not_grant_access_to_previous_subject_jobs(self):
        self.redis.set("job_1", json.dumps({"id": "1", "username": "alex", "keycloak_sub": "old-subject", "status": "queued"}))
        self.assertEqual(self.invoke(["job", "show", "1"])[0], 2)
        self.assertEqual(json.loads(self.invoke(["job", "list", "--json"])[1]), [])

    def test_own_retry_passes_current_verified_claims_to_backend(self):
        self.redis.set("job_1", json.dumps({"id": "1", "username": "alex", "keycloak_sub": "subject-alex", "status": "failed"}))
        with mock.patch.object(isolate, "retry_job", return_value={"id": "2"}) as retry:
            self.assertEqual(self.invoke(["job", "retry", "1", "--yes"])[0], 0)
            self.assertEqual(retry.call_args.kwargs["current_identity"], self.identity)

    def test_admin_cross_user_retry_still_requires_trusted_platform_authorization(self):
        self.redis.set("job_1", json.dumps({"id": "1", "username": "bailey", "status": "failed"}))
        with mock.patch.object(isolate, "_require_platform_admin", side_effect=isolate.AccessDenied("untrusted admin")), \
                mock.patch.object(isolate, "retry_job") as retry:
            self.assertEqual(self.invoke(["job", "retry", "1", "--yes"], identity=dict(self.identity, groups=["Admins"]))[0], 2)
            retry.assert_not_called()

    def test_job_output_uses_configured_directory_not_record_path(self):
        poisoned = os.path.join(self.temp.name, "private.txt")
        with open(poisoned, "w", encoding="utf-8") as stream:
            stream.write("secret")
        with open(os.path.join(self.temp.name, "job-1.log"), "w", encoding="utf-8") as stream:
            stream.write("expected output")
        self.redis.set("job_1", json.dumps({"id": "1", "username": "alex", "output_path": poisoned}))
        code, output, _ = self.invoke(["job", "output", "1"])
        self.assertEqual(code, 0)
        self.assertEqual(output, "expected output")

    def test_runbook_preview_selects_exact_tags_and_does_not_queue(self):
        code, output, error = self.invoke(["runbook", "preview", "uptime", "--project", "payments", "--tag", "env=prod"])
        self.assertEqual(code, 0, error)
        preview = json.loads(output)
        self.assertEqual([row["host_id"] for row in preview["hosts"]], ["1"])
        self.assertEqual(preview["command"], "/usr/bin/uptime")
        self.assertFalse(self.redis.keys("job_*"))

    def test_runbook_never_defaults_to_entire_inventory(self):
        self.assertEqual(self.invoke(["runbook", "preview", "uptime"])[0], 2)
        self.assertEqual(self.invoke(["runbook", "run", "uptime", "--yes"])[0], 2)
        self.assertFalse(self.redis.keys("job_*"))

    def test_runbook_rejects_mixed_explicit_and_dynamic_selectors(self):
        self.assertEqual(self.invoke(["runbook", "preview", "uptime", "--host", "1", "--tag", "env=prod"])[0], 2)

    def test_runbook_requires_confirmation_and_queues_validated_fleet(self):
        self.assertEqual(self.invoke(["runbook", "run", "uptime", "--host", "1,2"])[0], 2)
        self.assertFalse(self.redis.keys("job_*"))
        code, output, error = self.invoke(["runbook", "run", "uptime", "--host", "1,2", "--yes"])
        self.assertEqual(code, 0, error)
        result = json.loads(output)
        self.assertEqual(result["count"], 2)
        self.assertEqual(len(self.redis.keys("job_*")), 2)

    def test_runbook_validates_all_hosts_before_queueing(self):
        self.redis.set("server_3", json.dumps({"server_id": "3", "project_name": "forbidden"}))
        self.assertEqual(self.invoke(["runbook", "run", "uptime", "--host", "1,3", "--yes"])[0], 2)
        self.assertFalse(self.redis.keys("job_*"))

    def test_runbook_respects_current_groups(self):
        identity = dict(self.identity, groups=["NoAccess"])
        self.assertEqual(self.invoke(["runbook", "preview", "uptime", "--host", "1"], identity=identity)[0], 2)

    def test_runbook_duplicate_parameters_and_invalid_timeouts_fail(self):
        self.assertEqual(self.invoke(["runbook", "preview", "service-status", "--host", "1",
                                      "--param", "service=nginx", "--param", "service=redis"])[0], 2)
        self.assertEqual(self.invoke(["runbook", "run", "uptime", "--host", "1", "--timeout", "0", "--yes"])[0], 2)
        self.assertFalse(self.redis.keys("job_*"))

    def test_host_tag_update_preserves_other_tags_and_can_remove(self):
        code, output, error = self.invoke(["host", "update", "1", "--tag", "env=stage", "--remove-tag", "owner"])
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["tags"], {"env": "stage"})
        self.assertEqual(self.invoke(["host", "update", "1", "--clear-tags"])[0], 0)
        self.assertEqual(json.loads(self.redis.get("server_1"))["tags"], {})

    def test_history_and_export_forward_identical_filter_values(self):
        for argv in (["history", "--json"], ["export", "history", "--format", "json"]):
            with self.subTest(argv=argv), mock.patch.object(isolate, "load_verified_identity", return_value=self.identity), \
                    mock.patch.object(isolate, "read_history", return_value=[]) as reader:
                self.invoke(argv + ["--since", "2026-11-01", "--until", "2026-11-06", "--result", "success"])
                self.assertEqual(reader.call_args.kwargs["since"], "2026-11-01")
                self.assertEqual(reader.call_args.kwargs["until"], "2026-11-06")
                self.assertEqual(reader.call_args.kwargs["result"], "success")

    def test_pending_request_can_be_cancelled_only_by_owner(self):
        record = create_access_request(self.redis, self.identity, "payments", reason="incident")
        request_id = str(record["id"])
        self.assertEqual(self.invoke(["access", "cancel", "--id", request_id, "--yes"],
                                     identity=dict(self.identity, username="bailey", keycloak_sub="subject-bailey"))[0], 2)
        self.assertEqual(get_access_request(self.redis, request_id)["status"], "pending")
        self.assertEqual(self.invoke(["access", "cancel", "--id", request_id])[0], 2)
        self.assertEqual(self.invoke(["access", "cancel", "--id", request_id, "--yes"])[0], 0)
        self.assertEqual(get_access_request(self.redis, request_id)["status"], "cancelled")

    def test_scheduled_request_rejects_ambiguous_local_time(self):
        code, _, _ = self.invoke(["access", "request", "--project", "payments", "--reason", "change",
                                  "--starts-at", "2030-01-02T22:00:00"])
        self.assertEqual(code, 2)
        self.assertFalse(self.redis.keys("access_request_*"))

    def test_operational_context_binds_token_to_real_unix_user_and_trusted_config(self):
        fake_pwd = SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_name="unix-alex"))
        with mock.patch.object(isolate_connection_auth, "trusted_config", return_value=self.config), \
                mock.patch.object(isolate_connection_auth, "bind_identity", return_value=self.identity) as bind, \
                mock.patch.object(isolate_identity, "_load_token_cache", return_value={"id_token": "signed-token"}), \
                mock.patch.object(isolate.os, "name", "posix"), \
                mock.patch.object(isolate.os, "getuid", return_value=1000, create=True), \
                mock.patch.dict(sys.modules, {"pwd": fake_pwd}):
            config, identity = isolate._job_context()
        self.assertIs(config, self.config)
        self.assertEqual(identity, self.identity)
        bind.assert_called_once_with("signed-token", self.config, "unix-alex")

    def test_operational_context_rejects_unbound_non_linux_calls(self):
        with mock.patch.object(isolate_connection_auth, "trusted_config", return_value=self.config), \
                mock.patch.object(isolate.os, "name", "nt"):
            with self.assertRaises(isolate.AccessDenied):
                isolate._job_context()

    def test_runbook_uses_trusted_runtime_config_instead_of_argument_config(self):
        args = self.parser.parse_args(["runbook", "run", "uptime", "--host", "1", "--yes"])
        trusted = dict(self.config, runbooks={"enabled": False})
        with mock.patch.object(isolate, "_job_context", return_value=(trusted, self.identity)), \
                mock.patch.object(isolate, "redis_client") as redis_factory, redirect_stderr(StringIO()):
            self.assertEqual(isolate.cmd_runbook(args, self.config), 2)
        redis_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
