import os
import shutil
import sys
import uuid
import unittest
import fnmatch
import json
from contextlib import redirect_stdout
from types import SimpleNamespace
from io import BytesIO
from urllib.error import HTTPError

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "shared"))

from isolate_identity import IdentityError, KeycloakDeviceClient, load_cached_identity, normalize_claims, save_identity
from isolate_history import HistoryAccessDenied, read_history
from isolate_logging import SessionLogger
from isolate_policy import PolicyDenied, filter_allowed_hosts, resolve_grant, resolve_policy
from isolate_ssh import SSHArgumentError, build_ssh_argv
import isolate
from isolate_access import (
    AccessDenied,
    approve_access_request,
    create_access_request,
    deny_access_request,
    is_access_admin,
    list_access_requests,
    parse_duration,
)
from isolate import list_grant_records, load_project_sets, update_grant_record
from isolate_sessions import list_active_sessions, mark_session_end, mark_session_start
from isolate_web import is_dashboard_admin


class FakeRedis(object):
    def __init__(self):
        self.store = {}

    def keys(self, pattern):
        return [key for key in self.store if fnmatch.fnmatchcase(key, pattern)]

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value):
        self.store[key] = value

    def delete(self, key):
        if key in self.store:
            del self.store[key]
            return 1
        return 0

    def incr(self, key):
        value = int(self.store.get(key, 0)) + 1
        self.store[key] = str(value)
        return value

    def expire(self, key, ttl):
        return True


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

    def test_group_project_set_allows_matching_project(self):
        identity = {"username": "alice", "groups": ["DevOps"]}
        host = {"server_id": "10001", "server_name": "jump", "project_name": "vmware-test"}
        grants = [
            {
                "subject": "group",
                "name": "DevOps",
                "project_set": "prod-all",
                "remote_user": "support",
                "allowed_actions": ["ssh"],
            }
        ]
        project_sets = {"prod-all": {"name": "prod-all", "projects": ["vmware-test"], "project_globs": ["*-prod"]}}

        decision = resolve_grant(identity, project="vmware-test", host=host, grants=grants, project_sets=project_sets)

        self.assertEqual(decision["remote_user"], "support")

    def test_user_host_grant_wins_over_group_glob(self):
        identity = {"username": "alice", "groups": ["DevOps"]}
        host = {"server_id": "10001", "server_name": "jump", "project_name": "poker-prod"}
        grants = [
            {
                "subject": "group",
                "name": "DevOps",
                "project_glob": "poker-*",
                "remote_user": "support",
                "allowed_actions": ["ssh"],
            },
            {
                "subject": "user",
                "name": "alice",
                "project": "poker-prod",
                "host": "10001",
                "remote_user": "alice",
                "allowed_actions": ["ssh"],
            },
        ]

        decision = resolve_grant(identity, project="poker-prod", host=host, grants=grants)

        self.assertEqual(decision["remote_user"], "alice")

    def test_filters_hosts_without_matching_grant(self):
        identity = {"username": "alice", "groups": ["pokerteam"]}
        hosts = [
            {"server_id": "1", "server_name": "jump", "project_name": "poker-prod"},
            {"server_id": "2", "server_name": "db", "project_name": "billing-prod"},
        ]
        grants = [
            {
                "subject": "group",
                "name": "pokerteam",
                "project_glob": "poker*",
                "remote_user": "poker-support",
                "allowed_actions": ["ssh"],
            }
        ]

        allowed = filter_allowed_hosts(identity, hosts, grants=grants)

        self.assertEqual([host["server_id"] for host in allowed], ["1"])

    def test_expired_grant_does_not_match(self):
        identity = {"username": "alice", "groups": []}
        host = {"server_id": "1", "project_name": "prod"}
        grants = [
            {
                "subject": "user",
                "name": "alice",
                "project": "prod",
                "remote_user": "dba",
                "expires_at": 1,
            }
        ]

        with self.assertRaises(PolicyDenied):
            resolve_grant(identity, project="prod", host=host, grants=grants)


class AccessRequestTest(unittest.TestCase):
    def test_create_approve_and_deny_access_request(self):
        redis = FakeRedis()
        requester = {"username": "alice", "keycloak_sub": "sub-a", "groups": ["DBA"]}
        approver = {"username": "admin", "groups": ["DevOps"]}

        record = create_access_request(
            redis,
            requester,
            project="kube",
            host="10004",
            remote_user="dba",
            sudo_mode="none",
            reason="INC-1",
        )
        self.assertEqual(record["status"], "pending")
        self.assertEqual(len(list_access_requests(redis, status="pending")), 1)

        approved, grant = approve_access_request(redis, record["id"], approver, parse_duration("2h"), max_ttl=parse_duration("24h"))
        self.assertEqual(approved["status"], "approved")
        self.assertTrue(grant["temporary"])
        self.assertEqual(grant["request_id"], record["id"])
        self.assertEqual(grant["remote_user"], "dba")

        second = create_access_request(redis, requester, project="prod", reason="test")
        denied = deny_access_request(redis, second["id"], approver, reason="no")
        self.assertEqual(denied["status"], "denied")

    def test_access_admin_check_and_max_ttl(self):
        redis = FakeRedis()
        record = create_access_request(redis, {"username": "alice"}, project="prod", reason="test")
        self.assertTrue(is_access_admin({"groups": ["DevOps"]}, ["DevOps"]))
        self.assertFalse(is_access_admin({"groups": ["DBA"]}, ["DevOps"]))
        with self.assertRaises(AccessDenied):
            approve_access_request(redis, record["id"], {"username": "admin"}, parse_duration("25h"), max_ttl=parse_duration("24h"))


class ActiveSessionRegistryTest(unittest.TestCase):
    def test_active_session_lifecycle(self):
        redis = FakeRedis()
        mark_session_start(redis, "conn-1", {"username": "alice", "project": "kube"})
        self.assertEqual(len(list_active_sessions(redis)), 1)
        mark_session_end(redis, "conn-1", exit_code=0)
        self.assertEqual(list_active_sessions(redis), [])


class GrantAdminUxTest(unittest.TestCase):
    def test_lists_and_filters_grants(self):
        redis = FakeRedis()
        redis.set(
            "grant_1",
            '{"subject":"group","name":"DBA","project_set":"prod-all","remote_user":"dba","sudo_mode":"none"}',
        )
        redis.set(
            "grant_2",
            '{"subject":"group","name":"DevOps","project":"kube","remote_user":"support","sudo_mode":"sudo-i"}',
        )

        grants = list_grant_records(redis, group="DBA")

        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0]["id"], "1")
        self.assertEqual(grants[0]["remote_user"], "dba")

    def test_updates_grant_without_changing_id(self):
        redis = FakeRedis()
        redis.set(
            "grant_7",
            '{"subject":"group","name":"DBA","project_set":"prod-all","remote_user":"dba","sudo_mode":"sudo-i"}',
        )

        updated = update_grant_record(redis, "7", {"sudo_mode": "none", "remote_user": "l2-support"})

        self.assertEqual(updated["id"], "7")
        self.assertEqual(updated["sudo_mode"], "none")
        self.assertEqual(updated["remote_user"], "l2-support")
        self.assertEqual(list_grant_records(redis)[0]["project_set"], "prod-all")

    def test_project_set_remove_pattern_and_remove(self):
        redis = FakeRedis()
        redis.set(
            "project_set_prod-all",
            '{"schema_version":2,"name":"prod-all","projects":["kube"],"project_globs":["*-prod","old-*"]}',
        )
        original_redis_client = isolate.redis_client
        isolate.redis_client = lambda config: redis
        try:
            with open(os.devnull, "w") as devnull, redirect_stdout(devnull):
                isolate.cmd_project_set_remove_pattern(SimpleNamespace(name="prod-all", project_glob="old-*"), {})
            self.assertEqual(load_project_sets(redis)["prod-all"]["project_globs"], ["*-prod"])

            with open(os.devnull, "w") as devnull, redirect_stdout(devnull):
                result = isolate.cmd_project_set_remove(SimpleNamespace(name="prod-all"), {})
            self.assertEqual(result, 0)
            self.assertEqual(load_project_sets(redis), {})
        finally:
            isolate.redis_client = original_redis_client


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

    def test_formats_keycloak_http_error_body(self):
        exc = HTTPError(
            "https://keycloak.example/auth/device",
            403,
            "Forbidden",
            {},
            BytesIO(b'{"error":"access_denied","error_description":"blocked by policy"}'),
        )
        client = KeycloakDeviceClient({"issuer": "https://keycloak.example", "client_id": "isolate"})

        with self.assertRaises(IdentityError) as ctx:
            raise IdentityError(client._format_http_error(exc))

        self.assertIn("HTTP 403 Forbidden", str(ctx.exception))
        self.assertIn("blocked by policy", str(ctx.exception))

    def test_identity_cache_roundtrip_and_expiry(self):
        tmpdir = os.path.join(ROOT, ".tmp-identity-cache-{}".format(uuid.uuid4().hex))
        os.makedirs(tmpdir)
        path = os.path.join(tmpdir, "identity.json")
        try:
            identity = {
                "username": "alice",
                "groups": ["DevOps"],
                "roles": [],
                "keycloak_sub": "abc",
                "email": "alice@example.com",
                "session_id": "session-1",
                "exp": 200,
            }
            save_identity(identity, path=path)

            loaded = load_cached_identity(path=path, now=100)
            self.assertEqual(loaded["username"], "alice")

            with self.assertRaises(IdentityError):
                load_cached_identity(path=path, now=201)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


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


class HistoryTest(unittest.TestCase):
    def _write_session(self, base, user, session_id, events):
        session_dir = os.path.join(base, user, session_id)
        os.makedirs(session_dir)
        with open(os.path.join(session_dir, "session.jsonl"), "w", encoding="utf-8") as session_f:
            for event in events:
                session_f.write("{}\n".format(json.dumps(event, sort_keys=True)))

    def test_reads_recent_connection_history(self):
        tmpdir = os.path.join(ROOT, ".tmp-history-{}".format(uuid.uuid4().hex))
        try:
            self._write_session(
                tmpdir,
                "alice",
                "session-1",
                [
                    {
                        "ts": 100,
                        "event": "policy_selected",
                        "session_id": "session-1",
                        "username": "alice",
                        "project": "kube",
                        "host_id": "10004",
                        "target_host": "192.168.234.4",
                        "remote_user": "dba",
                    },
                    {
                        "ts": 101,
                        "event": "ssh_end",
                        "session_id": "session-1",
                        "username": "alice",
                        "exit_code": 0,
                        "raw_log_path": "/opt/auth/logs/alice/raw.log",
                    },
                ],
            )

            rows = read_history(tmpdir, {"username": "alice", "groups": []}, query="10004")

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["project"], "kube")
            self.assertEqual(rows[0]["result"], "exit=0")
            self.assertEqual(rows[0]["raw_log_path"], "/opt/auth/logs/alice/raw.log")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_history_acl_self_and_admin(self):
        tmpdir = os.path.join(ROOT, ".tmp-history-{}".format(uuid.uuid4().hex))
        try:
            self._write_session(
                tmpdir,
                "bob",
                "session-2",
                [
                    {
                        "ts": 200,
                        "event": "policy_selected",
                        "session_id": "session-2",
                        "username": "bob",
                        "project": "prod",
                        "host_id": "10002",
                        "target_host": "node0",
                        "remote_user": "support",
                    }
                ],
            )

            with self.assertRaises(HistoryAccessDenied):
                read_history(tmpdir, {"username": "alice", "groups": []}, user="bob")

            rows = read_history(tmpdir, {"username": "alice", "groups": ["DevOps"]}, user="bob", admin_groups=["DevOps"])
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["username"], "bob")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class DashboardTest(unittest.TestCase):
    def test_dashboard_admin_check(self):
        config = {"dashboard": {"admin_groups": ["DevOps"]}}
        self.assertTrue(is_dashboard_admin({"groups": ["DevOps"]}, config))
        self.assertFalse(is_dashboard_admin({"groups": ["DBA"]}, config))


if __name__ == "__main__":
    unittest.main()
