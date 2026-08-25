import os
import shutil
import sys
import uuid
import unittest
import fnmatch
import json
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from io import BytesIO, StringIO
from urllib.error import HTTPError
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "shared"))

import isolate_identity
from isolate_identity import (
    IdentityError,
    KeycloakDeviceClient,
    load_cached_identity,
    load_verified_identity,
    normalize_claims,
    save_identity,
    save_token_cache,
)
from isolate_history import HistoryAccessDenied, read_history
from isolate_inventory import format_hosts_table, get_host, list_hosts, update_host
from isolate_logging import SessionLogger
from isolate_policy import PolicyDenied, filter_allowed_hosts, resolve_grant, resolve_policy
from isolate_replay import find_session, parse_raw_replay
from isolate_ssh import SSHArgumentError, build_ssh_argv
import isolate
import isolate_web
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
from isolate_notifications import NotificationError, build_access_notification, notify_access_event


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


class InventoryTest(unittest.TestCase):
    def test_search_matches_services_and_note_but_go_fields_do_not(self):
        try:
            from helper import AuthHelper
        except ImportError as exc:
            self.skipTest(str(exc))
        host = {
            "project_name": "stakepoker",
            "server_id": "10703",
            "server_ip": "50.19.167.140",
            "server_name": "lobby",
            "server_services": "poker-ls, redis, clickhouse",
            "server_note": "VIP frontend",
        }

        self.assertTrue(AuthHelper._search_in_item(item=dict(host), query_lower="redis"))
        self.assertTrue(AuthHelper._search_in_item(item=dict(host), query_lower="vip"))
        self.assertFalse(
            AuthHelper._search_in_item(
                item=dict(host),
                query_lower="redis",
                fields=["server_name", "server_id", "server_ip"],
                exact_match=True,
            )
        )

    def test_host_list_show_update(self):
        redis = FakeRedis()
        redis.set(
            "server_10703",
            json.dumps(
                {
                    "server_id": 10703,
                    "project_name": "stakepoker",
                    "server_ip": "50.19.167.140",
                    "server_name": "lobby",
                    "server_user": "support",
                }
            ),
        )

        rows = list_hosts(redis, query="stake")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["server_services"], "")

        updated = update_host(
            redis,
            "10703",
            {"server_services": "redis, clickhouse", "server_note": "VIP frontend", "server_nosudo": True},
            updated_by="tester",
        )
        self.assertEqual(updated["server_services"], "redis, clickhouse")
        self.assertEqual(updated["server_note"], "VIP frontend")
        self.assertTrue(json.loads(redis.get("server_10703"))["server_nosudo"])
        self.assertEqual(get_host(redis, "10703")["updated_by"], "tester")

    def test_host_update_cli_and_validation(self):
        redis = FakeRedis()
        redis.set(
            "server_1",
            json.dumps(
                {
                    "server_id": 1,
                    "project_name": "prod",
                    "server_ip": "10.0.0.1",
                    "server_name": "web",
                    "server_user": "support",
                }
            ),
        )
        args = SimpleNamespace(
            server_id="1",
            project=None,
            name=None,
            ip=None,
            port=None,
            user=None,
            nosudo=None,
            vip=None,
            services="nginx, kafka",
            note=None,
            privileged_provider=None,
            privileged_url=None,
            privileged_hint=None,
            proxy_id=None,
        )
        with mock.patch.object(isolate, "redis_client", return_value=redis), redirect_stdout(StringIO()) as output:
            code = isolate.cmd_host_update(args, {})

        self.assertIsNone(code)
        self.assertEqual(json.loads(output.getvalue())["server_services"], "nginx, kafka")

        args.ip = "not-an-ip"
        with mock.patch.object(isolate, "redis_client", return_value=redis), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            code = isolate.cmd_host_update(args, {})
        self.assertEqual(code, 2)

    def test_vip_privileged_fields_update_and_render(self):
        redis = FakeRedis()
        redis.set(
            "server_10",
            json.dumps(
                {
                    "server_id": 10,
                    "project_name": "vip-prod",
                    "server_ip": "10.0.0.10",
                    "server_name": "vip-db",
                    "server_user": "support",
                }
            ),
        )
        updated = update_host(
            redis,
            "10",
            {
                "server_vip": True,
                "privileged_access_provider": "Warpgate",
                "privileged_access_url": "https://pam.example.org",
                "privileged_access_hint": "Use external PAM for sudo",
            },
            updated_by="tester",
        )

        self.assertTrue(updated["server_vip"])
        self.assertEqual(updated["server_vip_marker"], "VIP")
        self.assertEqual(updated["privileged_access_provider"], "Warpgate")
        self.assertIn("VIP", format_hosts_table([updated]))


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

    def test_grant_explain_allowed_and_denied(self):
        redis = FakeRedis()
        redis.set(
            "server_10703",
            json.dumps(
                {
                    "server_id": 10703,
                    "project_name": "stakepoker",
                    "server_ip": "50.19.167.140",
                    "server_name": "lobby",
                }
            ),
        )
        redis.set(
            "grant_42",
            json.dumps(
                {
                    "subject": "group",
                    "name": "Demo-DevOps",
                    "project": "stakepoker",
                    "remote_user": "support",
                    "sudo_mode": "none",
                    "allowed_actions": ["ssh"],
                }
            ),
        )
        args = SimpleNamespace(user="demo.alex", group=["Demo-DevOps"], role=None, project=None, host="10703")
        with mock.patch.object(isolate, "redis_client", return_value=redis), redirect_stdout(StringIO()) as output:
            code = isolate.cmd_grant_explain(args, {"policy": {}, "ssh": {}})

        self.assertEqual(code, 0)
        allowed = json.loads(output.getvalue())
        self.assertTrue(allowed["allowed"])
        self.assertEqual(allowed["matched_grant"]["id"], "42")
        self.assertEqual(allowed["remote_user"], "support")

        denied_args = SimpleNamespace(user="demo.alex", group=["Demo-DBA"], role=None, project=None, host="10703")
        with mock.patch.object(isolate, "redis_client", return_value=redis), redirect_stdout(StringIO()) as denied_output:
            code = isolate.cmd_grant_explain(denied_args, {"policy": {}, "ssh": {}})

        self.assertEqual(code, 2)
        denied = json.loads(denied_output.getvalue())
        self.assertFalse(denied["allowed"])
        self.assertIn("isolate access request", denied["suggested_request"])


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

    def test_legacy_identity_cache_is_rejected_for_verified_load(self):
        tmpdir = os.path.join(ROOT, ".tmp-identity-cache-{}".format(uuid.uuid4().hex))
        os.makedirs(tmpdir)
        path = os.path.join(tmpdir, "identity.json")
        try:
            save_identity({"username": "alice", "groups": ["Admin"]}, path=path)
            with self.assertRaises(IdentityError):
                load_verified_identity({"keycloak": {}}, path=path)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_verified_identity_ignores_tampered_cached_display(self):
        tmpdir = os.path.join(ROOT, ".tmp-identity-cache-{}".format(uuid.uuid4().hex))
        os.makedirs(tmpdir)
        path = os.path.join(tmpdir, "identity.json")
        original_verify = isolate_identity.verify_jwt_claims
        try:
            save_token_cache(
                {"id_token": "signed.jwt.token", "access_token": "access", "expires_in": 300},
                {"username": "alice", "email": "alice@example.org", "raw_claims": {"exp": 9999999999}},
                path=path,
            )
            with open(path, "r", encoding="utf-8") as cache_f:
                cache = json.load(cache_f)
            cache["cached_display"]["username"] = "mallory"
            cache["cached_display"]["groups"] = ["Admin"]
            with open(path, "w", encoding="utf-8") as cache_f:
                json.dump(cache, cache_f)

            isolate_identity.verify_jwt_claims = lambda token, config, now=None: {
                "sub": "abc",
                "preferred_username": "alice",
                "email": "alice@example.org",
                "groups": ["DBA"],
                "exp": 9999999999,
            }
            identity = load_verified_identity({"keycloak": {}}, path=path)
            self.assertEqual(identity["username"], "alice")
            self.assertEqual(identity["groups"], ["DBA"])
        finally:
            isolate_identity.verify_jwt_claims = original_verify
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_validates_jwt_issuer_audience_and_expiry(self):
        claims = {
            "iss": "https://keycloak.example.org/realms/demo",
            "aud": "isolate-bastion",
            "exp": 200,
        }
        isolate_identity._validate_claims(
            claims,
            {"issuer": "https://keycloak.example.org/realms/demo", "expected_audience": "isolate-bastion"},
            now=100,
        )
        with self.assertRaises(IdentityError):
            isolate_identity._validate_claims(dict(claims, exp=99), {"expected_audience": "isolate-bastion"}, now=100)
        with self.assertRaises(IdentityError):
            isolate_identity._validate_claims(dict(claims, iss="bad"), {"issuer": "issuer"}, now=100)
        with self.assertRaises(IdentityError):
            isolate_identity._validate_claims(dict(claims, aud="other"), {"expected_audience": "isolate-bastion"}, now=100)

    def test_jwks_cache_read_and_unsafe_ignore(self):
        tmpdir = os.path.join(ROOT, ".tmp-jwks-cache-{}".format(uuid.uuid4().hex))
        os.makedirs(tmpdir)
        path = os.path.join(tmpdir, "keycloak_jwks.json")
        original_safe = isolate_identity._is_safe_cache_path
        try:
            with open(path, "w", encoding="utf-8") as cache_f:
                json.dump({"fetched_at": int(isolate_identity.time.time()), "jwks": {"keys": [{"kid": "1"}]}}, cache_f)
            self.assertEqual(isolate_identity._read_jwks_cache(path, 3600), {"keys": [{"kid": "1"}]})
            isolate_identity._is_safe_cache_path = lambda _: False
            self.assertIsNone(isolate_identity._read_jwks_cache(path, 3600))
        finally:
            isolate_identity._is_safe_cache_path = original_safe
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


class SessionReplayTest(unittest.TestCase):
    def test_find_session_details_and_parse_replay(self):
        tmpdir = os.path.join(ROOT, ".tmp-session-{}".format(uuid.uuid4().hex))
        raw_path = os.path.join(tmpdir, "alice", "session-1", "raw.log")
        try:
            self._write_session(
                tmpdir,
                "alice",
                "session-1",
                [
                    {
                        "event": "policy_selected",
                        "ts": 10.0,
                        "username": "alice",
                        "project": "prod",
                        "host_id": "10001",
                        "target_host": "10.0.0.1",
                        "remote_user": "support",
                        "connection_id": "conn-1",
                        "session_id": "session-1",
                    },
                    {
                        "event": "ssh_start",
                        "ts": 11.0,
                        "username": "alice",
                        "connection_id": "conn-1",
                        "session_id": "session-1",
                        "raw_log_path": raw_path,
                    },
                    {
                        "event": "ssh_end",
                        "ts": 12.0,
                        "username": "alice",
                        "connection_id": "conn-1",
                        "session_id": "session-1",
                        "exit_code": 0,
                        "raw_log_path": raw_path,
                    },
                ],
            )
            with open(raw_path, "w", encoding="utf-8") as raw_f:
                raw_f.write("1000.000000\nwhoami\n1000.500000\nsupport\n")

            details = find_session(tmpdir, "conn-1")
            self.assertEqual(details["summary"]["connection_id"], "conn-1")
            self.assertEqual(details["summary"]["result"], "exit=0")
            self.assertEqual(details["raw_log_path"], raw_path)

            replay = parse_raw_replay(raw_path)
            self.assertIsNone(replay["error"])
            self.assertEqual(replay["chunks"][0]["t"], 0.0)
            self.assertIn("whoami", replay["plain"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_malformed_replay_falls_back_to_plain_text(self):
        tmpdir = os.path.join(ROOT, ".tmp-replay-{}".format(uuid.uuid4().hex))
        raw_path = os.path.join(tmpdir, "raw.log")
        try:
            os.makedirs(tmpdir)
            with open(raw_path, "w", encoding="utf-8") as raw_f:
                raw_f.write("plain transcript without timestamps")
            replay = parse_raw_replay(raw_path)
            self.assertEqual(replay["chunks"], [])
            self.assertIn("plain transcript", replay["plain"])
            self.assertIsNotNone(replay["error"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _write_session(self, base, user, session_id, events):
        session_dir = os.path.join(base, user, session_id)
        os.makedirs(session_dir)
        with open(os.path.join(session_dir, "session.jsonl"), "w", encoding="utf-8") as session_f:
            for event in events:
                session_f.write("{}\n".format(json.dumps(event, sort_keys=True)))


class DashboardTest(unittest.TestCase):
    def test_dashboard_admin_check(self):
        config = {"dashboard": {"admin_groups": ["DevOps"]}}
        self.assertTrue(is_dashboard_admin({"groups": ["DevOps"]}, config))
        self.assertFalse(is_dashboard_admin({"groups": ["DBA"]}, config))

    def test_access_page_renders_actions_csrf_and_refresh(self):
        try:
            app = isolate_web.create_app(
                {
                    "dashboard": {
                        "admin_groups": ["DevOps"],
                        "public_url": "http://bastion.example.org",
                        "refresh_seconds": 15,
                    },
                    "access": {"default_ttl": "2h", "max_ttl": "24h"},
                    "keycloak": {"issuer": "http://keycloak", "client_id": "isolate"},
                    "logging": {"base_path": "/tmp/no-history"},
                }
            )
        except ImportError as exc:
            self.skipTest(str(exc))
        redis = FakeRedis()
        create_access_request(
            redis,
            {"username": "alice", "keycloak_sub": "sub-a", "groups": ["DBA"]},
            project="kube",
            host="10004",
            remote_user="dba",
            sudo_mode="none",
            reason="INC-1",
        )
        app.config["TESTING"] = True
        with mock.patch.object(isolate_web, "redis_client", return_value=redis):
            client = app.test_client()
            with client.session_transaction() as sess:
                sess["identity"] = {"username": "admin", "groups": ["DevOps"]}
                sess["csrf_token"] = "csrf"
            response = client.get("/access")

        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn('http-equiv="refresh" content="15"', text)
        self.assertIn('name="csrf_token" value="csrf"', text)
        self.assertIn("Approve", text)
        self.assertIn("Deny", text)

    def test_access_post_rejects_bad_csrf(self):
        try:
            app = isolate_web.create_app(
                {
                    "dashboard": {"admin_groups": ["DevOps"], "public_url": "http://bastion.example.org"},
                    "access": {"default_ttl": "2h", "max_ttl": "24h"},
                    "keycloak": {"issuer": "http://keycloak", "client_id": "isolate"},
                    "logging": {"base_path": "/tmp/no-history"},
                }
            )
        except ImportError as exc:
            self.skipTest(str(exc))
        redis = FakeRedis()
        app.config["TESTING"] = True
        with mock.patch.object(isolate_web, "redis_client", return_value=redis):
            client = app.test_client()
            with client.session_transaction() as sess:
                sess["identity"] = {"username": "admin", "groups": ["DevOps"]}
                sess["csrf_token"] = "expected"
            response = client.post("/access", data={"csrf_token": "bad", "action": "deny", "id": "1"})

        self.assertEqual(response.status_code, 403)

    def test_inventory_page_filters_and_renders_links(self):
        try:
            app = isolate_web.create_app(
                {
                    "dashboard": {"admin_groups": ["DevOps"], "public_url": "http://bastion.example.org"},
                    "access": {"default_ttl": "2h", "max_ttl": "24h"},
                    "keycloak": {"issuer": "http://keycloak", "client_id": "isolate"},
                    "logging": {"base_path": "/tmp/no-history"},
                }
            )
        except ImportError as exc:
            self.skipTest(str(exc))
        redis = FakeRedis()
        redis.set(
            "server_10703",
            json.dumps(
                {
                    "server_id": 10703,
                    "project_name": "stakepoker",
                    "server_ip": "50.19.167.140",
                    "server_name": "lobby",
                    "server_user": "support",
                    "server_services": "redis, clickhouse",
                    "server_note": "<vip>",
                    "server_vip": True,
                    "privileged_access_provider": "Warpgate",
                    "privileged_access_hint": "<sudo via PAM>",
                }
            ),
        )
        app.config["TESTING"] = True
        with mock.patch.object(isolate_web, "redis_client", return_value=redis):
            client = app.test_client()
            with client.session_transaction() as sess:
                sess["identity"] = {"username": "admin", "groups": ["DevOps"]}
            response = client.get("/inventory?q=redis")

        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn("redis, clickhouse", text)
        self.assertIn("VIP", text)
        self.assertIn("Warpgate", text)
        self.assertIn("&lt;sudo via PAM&gt;", text)
        self.assertIn('/history?host=10703', text)
        self.assertIn("&lt;vip&gt;", text)

    def test_session_details_and_replay_routes(self):
        tmpdir = os.path.join(ROOT, ".tmp-dashboard-session-{}".format(uuid.uuid4().hex))
        raw_path = os.path.join(tmpdir, "admin", "session-1", "raw.log")
        try:
            try:
                app = isolate_web.create_app(
                    {
                        "dashboard": {"admin_groups": ["DevOps"], "public_url": "http://bastion.example.org"},
                        "access": {"default_ttl": "2h", "max_ttl": "24h"},
                        "keycloak": {"issuer": "http://keycloak", "client_id": "isolate"},
                        "logging": {"base_path": tmpdir},
                    }
                )
            except ImportError as exc:
                self.skipTest(str(exc))
            os.makedirs(os.path.dirname(raw_path))
            with open(os.path.join(os.path.dirname(raw_path), "session.jsonl"), "w", encoding="utf-8") as session_f:
                for event in [
                    {
                        "event": "policy_selected",
                        "ts": 10.0,
                        "username": "admin",
                        "project": "prod",
                        "host_id": "10001",
                        "target_host": "10.0.0.1",
                        "remote_user": "support",
                        "connection_id": "conn-1",
                        "session_id": "session-1",
                    },
                    {
                        "event": "ssh_end",
                        "ts": 11.0,
                        "username": "admin",
                        "connection_id": "conn-1",
                        "session_id": "session-1",
                        "exit_code": 0,
                        "raw_log_path": raw_path,
                    },
                ]:
                    session_f.write("{}\n".format(json.dumps(event, sort_keys=True)))
            with open(raw_path, "w", encoding="utf-8") as raw_f:
                raw_f.write("1000.000000\nhello\n1000.250000\nworld\n")

            app.config["TESTING"] = True
            client = app.test_client()
            with client.session_transaction() as sess:
                sess["identity"] = {"username": "admin", "groups": ["DevOps"]}

            details = client.get("/session/conn-1")
            self.assertEqual(details.status_code, 200)
            self.assertIn("Session Details", details.get_data(as_text=True))
            self.assertIn("/replay/conn-1", details.get_data(as_text=True))

            events = client.get("/session/conn-1/events.json")
            self.assertEqual(events.status_code, 200)
            self.assertIn("policy_selected", events.get_data(as_text=True))

            replay = client.get("/replay/conn-1.json")
            self.assertEqual(replay.status_code, 200)
            self.assertIn("hello", replay.get_data(as_text=True))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class NotificationTest(unittest.TestCase):
    def test_build_access_notification_payload(self):
        record = {
            "id": "7",
            "status": "pending",
            "requester": "demo.alice",
            "project": "kube",
            "host": "10004",
            "remote_user": "dba",
            "sudo_mode": "none",
            "reason": "INC-1",
        }
        notification = build_access_notification(
            {"dashboard": {"public_url": "https://bastion.example.org"}},
            "access_request_created",
            record,
            actor={"username": "demo.alice"},
        )

        self.assertIn("Access request created #7", notification["subject"])
        self.assertEqual(notification["payload"]["dashboard_url"], "https://bastion.example.org/access?id=7")
        self.assertIn("project: kube", notification["text"])

    def test_webhook_and_telegram_sinks_send_expected_requests(self):
        config = {
            "dashboard": {"public_url": "https://bastion.example.org"},
            "notifications": {
                "enabled": True,
                "sinks": [
                    {"type": "webhook", "url": "https://hooks.example.org/isolate"},
                    {"type": "telegram", "bot_token": "token", "chat_id": "-100"},
                ],
            },
        }
        record = {"id": "1", "status": "pending", "requester": "alice", "project": "prod"}
        requests = []

        class Response(object):
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getcode(self):
                return 200

        def fake_urlopen(req, timeout=None):
            requests.append(req)
            return Response()

        with mock.patch("isolate_notifications.urllib.request.urlopen", side_effect=fake_urlopen):
            result = notify_access_event(config, "access_request_created", record)

        self.assertEqual(len(result["sent"]), 2)
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0].full_url, "https://hooks.example.org/isolate")
        self.assertIn("/bottoken/sendMessage", requests[1].full_url)

    def test_email_sink_uses_smtp(self):
        config = {
            "notifications": {
                "enabled": True,
                "sinks": [
                    {
                        "type": "email",
                        "smtp_host": "smtp.example.org",
                        "smtp_port": 587,
                        "starttls": True,
                        "username": "isolate@example.org",
                        "password": "secret",
                        "from": "isolate@example.org",
                        "to": ["devsecops@example.org"],
                    }
                ],
            }
        }
        smtp = mock.Mock()
        smtp.__enter__ = mock.Mock(return_value=smtp)
        smtp.__exit__ = mock.Mock(return_value=False)
        with mock.patch("isolate_notifications.smtplib.SMTP", return_value=smtp):
            result = notify_access_event(config, "access_request_created", {"id": "2", "status": "pending"})

        self.assertEqual(result["sent"][0]["type"], "email")
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("isolate@example.org", "secret")
        smtp.send_message.assert_called_once()

    def test_sink_failure_is_warning_or_fail_closed(self):
        config = {
            "notifications": {
                "enabled": True,
                "fail_closed": False,
                "sinks": [{"type": "webhook", "url": "https://hooks.example.org/isolate"}],
            }
        }
        with mock.patch("isolate_notifications.urllib.request.urlopen", side_effect=OSError("down")):
            result = notify_access_event(config, "access_request_created", {"id": "3"})
        self.assertEqual(len(result["errors"]), 1)

        config["notifications"]["fail_closed"] = True
        with mock.patch("isolate_notifications.urllib.request.urlopen", side_effect=OSError("down")):
            with self.assertRaises(NotificationError):
                notify_access_event(config, "access_request_created", {"id": "3"})


class AccessNotificationCliTest(unittest.TestCase):
    def test_access_request_calls_notifier(self):
        redis = FakeRedis()
        args = SimpleNamespace(project="prod", host="10001", remote_user="dba", sudo_mode="none", reason="INC-1")
        with mock.patch.object(isolate, "_load_cli_identity", return_value={"username": "alice", "groups": ["DBA"]}), \
                mock.patch.object(isolate, "redis_client", return_value=redis), \
                mock.patch.object(isolate, "notify_access_event", return_value={"sent": [], "errors": []}) as notifier, \
                redirect_stdout(StringIO()):
            code = isolate.cmd_access_request(args, {"notifications": {"enabled": False}})

        self.assertIsNone(code)
        notifier.assert_called_once()
        self.assertEqual(notifier.call_args[0][1], "access_request_created")

    def test_access_approve_and_deny_call_notifier(self):
        redis = FakeRedis()
        requester = {"username": "alice", "groups": ["DBA"]}
        approver = {"username": "admin", "groups": ["DevOps"]}
        first = create_access_request(redis, requester, project="prod", reason="INC-1")
        second = create_access_request(redis, requester, project="prod", reason="INC-2")
        config = {"access": {"default_ttl": "2h", "max_ttl": "24h"}, "notifications": {"enabled": False}}

        with mock.patch.object(isolate, "_require_access_admin", return_value=approver), \
                mock.patch.object(isolate, "redis_client", return_value=redis), \
                mock.patch.object(isolate, "notify_access_event", return_value={"sent": [], "errors": []}) as notifier, \
                redirect_stdout(StringIO()):
            approve_code = isolate.cmd_access_approve(
                SimpleNamespace(id=first["id"], ttl="2h", remote_user=None, sudo_mode=None),
                config,
            )
            deny_code = isolate.cmd_access_deny(SimpleNamespace(id=second["id"], reason="not needed"), config)

        self.assertIsNone(approve_code)
        self.assertIsNone(deny_code)
        self.assertEqual([call[0][1] for call in notifier.call_args_list], ["access_request_approved", "access_request_denied"])


if __name__ == "__main__":
    unittest.main()
