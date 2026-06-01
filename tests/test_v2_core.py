import os
import shutil
import sys
import uuid
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "shared"))

from isolate_identity import normalize_claims
from isolate_logging import SessionLogger
from isolate_policy import PolicyDenied, resolve_policy
from isolate_ssh import SSHArgumentError, build_ssh_argv


class PolicyResolverTest(unittest.TestCase):
    def test_user_host_wins_over_group_project(self):
        identity = {"username": "alice", "groups": ["ops"]}
        host = {"server_id": "42", "server_name": "db01", "server_user": "support"}
        rules = [
            {
                "subject": "group",
                "name": "ops",
                "project": "prod",
                "remote_user": "opsuser",
            },
            {
                "subject": "user",
                "name": "alice",
                "project": "prod",
                "host": "42",
                "remote_user": "alice-prod",
            },
        ]
        decision = resolve_policy(identity, project="prod", host=host, rules=rules)
        self.assertEqual(decision["remote_user"], "alice-prod")

    def test_denies_without_remote_user(self):
        with self.assertRaises(PolicyDenied):
            resolve_policy({"username": "bob", "groups": []}, project="prod", host={})


class SSHBuilderTest(unittest.TestCase):
    def test_builds_safe_argv(self):
        argv = build_ssh_argv(
            {"binary": "/usr/bin/ssh", "config_path": "/tmp/ssh_config", "allowed_extra_args": ["-v"]},
            {"hostname": "host.example.com", "user": "support", "port": 2222, "debug": False},
            extra_args=["-v"],
            remote_command="sudo -i",
        )
        self.assertIn("-l", argv)
        self.assertIn("support", argv)
        self.assertIn("-tt", argv)
        self.assertEqual(argv[-2:], ["host.example.com", "sudo -i"])

    def test_rejects_unknown_ssh_arg(self):
        with self.assertRaises(SSHArgumentError):
            build_ssh_argv(
                {"binary": "/usr/bin/ssh", "config_path": "/tmp/ssh_config", "allowed_extra_args": []},
                {"hostname": "host.example.com"},
                extra_args=["-oProxyCommand=sh"],
            )


class IdentityTest(unittest.TestCase):
    def test_normalizes_keycloak_claims(self):
        identity = normalize_claims(
            {
                "sub": "abc",
                "preferred_username": "alice",
                "email": "alice@example.com",
                "groups": ["/ops", "/prod"],
                "realm_access": {"roles": ["bastion"]},
            }
        )
        self.assertEqual(identity["keycloak_sub"], "abc")
        self.assertEqual(identity["username"], "alice")
        self.assertEqual(identity["groups"], ["/ops", "/prod"])
        self.assertEqual(identity["roles"], ["bastion"])


class SessionLoggerTest(unittest.TestCase):
    def test_creates_user_and_session_log_paths(self):
        tmpdir = os.path.join(ROOT, ".tmp-session-logger-{}".format(uuid.uuid4().hex))
        os.makedirs(tmpdir)
        try:
            logger = SessionLogger(
                tmpdir,
                {"username": "alice", "groups": ["auth"], "session_id": "session-1"},
            )
            logger.event("helper_start", project="prod")

            self.assertTrue(os.path.isdir(os.path.join(tmpdir, "alice")))
            self.assertTrue(os.path.isdir(os.path.join(tmpdir, "alice", "session-1")))
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "alice", "session-1", "session.jsonl")))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
