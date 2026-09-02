import os
import shutil
import sys
import uuid
import unittest
import fnmatch
import json
import tarfile
import tempfile
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
from isolate_command_audit import CommandAuditError, append_command_event
from isolate_ssh import SSHArgumentError, build_ssh_argv
import isolate
import isolate_web
from isolate_access import (
    AccessDenied,
    approve_access_request,
    comment_access_request,
    create_access_request,
    deny_access_request,
    is_access_admin,
    list_access_requests,
    parse_duration,
    repeat_access_request,
)
from isolate import list_grant_records, load_project_sets, update_grant_record
from isolate_sessions import list_active_sessions, mark_session_end, mark_session_start
from isolate_web import is_dashboard_admin
from isolate_notifications import NotificationError, build_access_notification, notify_access_event
from isolate_audit import classify_audit_record, prepare_and_dispatch, verify_audit_record, verify_jsonl_file
from isolate_backup import BackupError, create_backup, restore_backup, restore_redis_snapshot, verify_backup
from isolate_health import run_health_checks, validate_config
from isolate_policy_bundle import PolicyBundleError, apply_bundle, export_bundle, plan_bundle, validate_bundle
from isolate_redis import redis_options
from isolate_retention import expired_session_dirs


class FakeRedis(object):
    def __init__(self):
        self.store = {}
        self.ttls = {}

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

    def dump(self, key):
        value = self.store.get(self._key(key))
        if value is None:
            return None
        if isinstance(value, bytes):
            return value
        return str(value).encode("utf-8")

    def pttl(self, key):
        return self.ttls.get(self._key(key), -1)

    def exists(self, key):
        return self._key(key) in self.store

    def restore(self, key, ttl, payload, replace=False):
        key = self._key(key)
        if key in self.store and not replace:
            raise RuntimeError("BUSYKEY")
        self.store[key] = payload.decode("utf-8") if isinstance(payload, bytes) else payload
        if ttl:
            self.ttls[key] = int(ttl)
        return True

    @staticmethod
    def _key(key):
        return key.decode("utf-8") if isinstance(key, bytes) else key

    def incr(self, key):
        value = int(self.store.get(key, 0)) + 1
        self.store[key] = str(value)
        return value

    def expire(self, key, ttl):
        return True

    def ping(self):
        return True


class ProductionHardeningTest(unittest.TestCase):
    def test_redis_options_preserve_plain_defaults_and_support_acl_tls(self):
        plain = redis_options({"redis": {"host": "127.0.0.1", "port": 6379, "db": 0}})
        self.assertNotIn("ssl", plain)
        self.assertNotIn("username", plain)

        secure = redis_options({"redis": {
            "host": "redis.example.org",
            "port": 6380,
            "db": 2,
            "username": "isolate",
            "password": "secret",
            "ssl": True,
            "ssl_ca_certs": "/etc/isolate/redis-ca.pem",
        }})
        self.assertTrue(secure["ssl"])
        self.assertEqual(secure["username"], "isolate")
        self.assertEqual(secure["ssl_ca_certs"], "/etc/isolate/redis-ca.pem")

    def test_config_validation_and_health(self):
        tmpdir = os.path.join(ROOT, ".tmp-health-{}".format(uuid.uuid4().hex))
        os.makedirs(tmpdir)
        try:
            config = {
                "redis": {"host": "127.0.0.1", "port": 6379},
                "keycloak": {"issuer": "https://id.example.org/realms/demo", "client_id": "isolate"},
                "logging": {"base_path": tmpdir, "retention_days": 30, "sinks": []},
                "dashboard": {"enabled": False},
            }
            self.assertTrue(validate_config(config)["valid"])
            health = run_health_checks(config, redis_factory=lambda cfg: FakeRedis())
            self.assertTrue(health["ok"])

            config["logging"]["sinks"] = [{"type": "unknown"}]
            self.assertFalse(validate_config(config)["valid"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class ServiceBackupTest(unittest.TestCase):
    def _config(self, root):
        configs = os.path.join(root, "runtime", "configs")
        keys = os.path.join(root, "runtime", "keys")
        os.makedirs(configs)
        os.makedirs(keys)
        with open(os.path.join(configs, "isolate.yml"), "w", encoding="utf-8") as config_f:
            config_f.write("schema_version: 2\nsecret: test-only\n")
        with open(os.path.join(keys, "id_rsa"), "w", encoding="utf-8") as key_f:
            key_f.write("TEST PRIVATE KEY\n")
        return {
            "data_root": os.path.join(root, "runtime"),
            "logging": {"base_path": os.path.join(root, "runtime", "logs")},
            "backup": {
                "base_path": os.path.join(root, "backups"),
                "retention_count": 2,
                "include_logs": False,
                "redis_patterns": ["server_*", "grant_*", "projects_list"],
                "paths": [
                    {"path": configs, "required": True},
                    {"path": keys, "required": True},
                    {"path": os.path.join(root, "optional"), "required": False},
                ],
            },
        }

    def test_backup_verify_and_staged_restore_round_trip(self):
        with tempfile.TemporaryDirectory(prefix="isolate-backup-") as root:
            config = self._config(root)
            source_redis = FakeRedis()
            source_redis.set("server_10001", '{"server_id": 10001}')
            source_redis.set("grant_1", '{"remote_user": "support"}')
            source_redis.set("unrelated", "must-not-be-backed-up")

            created = create_backup(config, source_redis)
            self.assertTrue(os.path.isfile(created["archive"]))
            self.assertEqual(created["redis_key_count"], 2)
            self.assertFalse(created["redis_consistent"])
            verified = verify_backup(created["archive"])
            self.assertTrue(verified["valid"], verified["errors"])
            self.assertTrue(verified["sidecar_verified"])

            with tarfile.open(created["archive"], "r:gz") as archive:
                snapshot = json.load(archive.extractfile("redis.json"))
            self.assertEqual({record["key"] for record in snapshot["records"]}, {"server_10001", "grant_1"})

            restored_redis = FakeRedis()
            target_root = os.path.join(root, "restore")
            result = restore_backup(
                created["archive"],
                target_root,
                redis=restored_redis,
                restore_redis=True,
                confirmed=True,
            )
            self.assertEqual(result["redis"]["restored"], 2)
            self.assertEqual(restored_redis.get("server_10001"), '{"server_id": 10001}')
            self.assertIsNone(restored_redis.get("unrelated"))
            restored_configs = []
            for current_root, _, filenames in os.walk(target_root):
                if "isolate.yml" in filenames:
                    restored_configs.append(os.path.join(current_root, "isolate.yml"))
            self.assertEqual(len(restored_configs), 1)
            with open(restored_configs[0], "r", encoding="utf-8") as restored_f:
                self.assertIn("secret: test-only", restored_f.read())

            with self.assertRaises(BackupError):
                restore_backup(created["archive"], target_root, confirmed=False)
            with self.assertRaises(BackupError):
                restore_backup(
                    created["archive"],
                    os.path.join(root, "restore-conflict"),
                    redis=restored_redis,
                    restore_files=False,
                    restore_redis=True,
                    confirmed=True,
                )

            with open(created["archive"] + ".sha256", "w", encoding="ascii") as checksum_f:
                checksum_f.write("{}  backup.tar.gz\n".format("0" * 64))
            tampered = verify_backup(created["archive"])
            self.assertFalse(tampered["valid"])
            self.assertIn("archive checksum sidecar mismatch", tampered["errors"])

    def test_redis_restore_skips_expired_and_supports_replace(self):
        redis = FakeRedis()
        redis.set("server_1", "old")
        snapshot = {
            "records": [
                {
                    "key": "server_1",
                    "key_b64": "c2VydmVyXzE=",
                    "dump_b64": "bmV3",
                    "expire_at_ms": None,
                },
                {
                    "key": "active_session_old",
                    "key_b64": "YWN0aXZlX3Nlc3Npb25fb2xk",
                    "dump_b64": "ZXhwaXJlZA==",
                    "expire_at_ms": 999,
                },
            ],
        }
        result = restore_redis_snapshot(redis, snapshot, conflict="replace", now_ms=1000)
        self.assertEqual(redis.get("server_1"), "new")
        self.assertEqual(result["expired_skipped"], ["active_session_old"])

    def test_backup_retention_keeps_configured_archive_count(self):
        with tempfile.TemporaryDirectory(prefix="isolate-backup-retention-") as root:
            config = self._config(root)
            redis = FakeRedis()
            redis.set("server_1", "one")
            for _ in range(3):
                create_backup(config, redis)
            archives = [
                name for name in os.listdir(config["backup"]["base_path"])
                if name.endswith(".tar.gz")
            ]
            self.assertEqual(len(archives), 2)

    def test_log_retention_selects_only_expired_session_directories(self):
        tmpdir = os.path.join(ROOT, ".tmp-retention-{}".format(uuid.uuid4().hex))
        old_dir = os.path.join(tmpdir, "alice", "old-session")
        new_dir = os.path.join(tmpdir, "alice", "new-session")
        os.makedirs(old_dir)
        os.makedirs(new_dir)
        old_log = os.path.join(old_dir, "session.jsonl")
        new_log = os.path.join(new_dir, "session.jsonl")
        now = 2_000_000_000
        try:
            for path in (old_log, new_log):
                with open(path, "w", encoding="utf-8") as log_f:
                    log_f.write("{}\n")
            old_time = now - (91 * 86400)
            new_time = now - (2 * 86400)
            os.utime(old_log, (old_time, old_time))
            os.utime(old_dir, (old_time, old_time))
            os.utime(new_log, (new_time, new_time))
            os.utime(new_dir, (new_time, new_time))
            self.assertEqual(expired_session_dirs(tmpdir, 90, now=now), [os.path.realpath(old_dir)])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class PolicyAsCodeTest(unittest.TestCase):
    def _current_redis(self):
        redis = FakeRedis()
        redis.set("offset_grant_id", "2")
        redis.set("project_set_prod", json.dumps({
            "schema_version": 2,
            "name": "prod",
            "projects": ["payments-prod"],
            "project_globs": [],
        }))
        redis.set("grant_1", json.dumps({
            "schema_version": 2,
            "subject": "group",
            "name": "Support",
            "project_set": "prod",
            "remote_user": "support",
            "sudo_mode": "none",
            "allowed_actions": ["ssh"],
        }))
        redis.set("grant_2", json.dumps({
            "schema_version": 2,
            "subject": "group",
            "name": "Legacy",
            "project": "legacy",
            "remote_user": "support",
            "sudo_mode": "none",
            "allowed_actions": ["ssh"],
        }))
        return redis

    def test_bundle_diff_apply_and_explicit_prune(self):
        redis = self._current_redis()
        bundle = export_bundle(redis)
        bundle["grants"] = [dict(bundle["grants"][0], remote_user="l2-support")]
        validation = validate_bundle(bundle)
        self.assertTrue(validation["valid"])

        no_prune = plan_bundle(redis, bundle, prune=False)
        self.assertEqual(len(no_prune["grant_update"]), 1)
        self.assertEqual(no_prune["grant_remove"], [])
        apply_bundle(redis, bundle, prune=False)
        self.assertEqual(json.loads(redis.get("grant_1"))["remote_user"], "l2-support")
        self.assertIsNotNone(redis.get("grant_2"))

        prune = apply_bundle(redis, bundle, prune=True)
        self.assertEqual(len(prune["grant_remove"]), 1)
        self.assertIsNone(redis.get("grant_2"))

    def test_bundle_rejects_conflicting_selectors(self):
        base = {
            "subject": "group", "name": "Support", "project": "prod",
            "remote_user": "support", "allowed_actions": ["ssh"],
        }
        bundle = {"schema_version": 2, "project_sets": [], "grants": [base, dict(base, remote_user="root")]}
        validation = validate_bundle(bundle)
        self.assertFalse(validation["valid"])
        with self.assertRaises(PolicyBundleError):
            plan_bundle(FakeRedis(), bundle)


class CentralAuditTest(unittest.TestCase):
    def test_risk_tags_cover_privileged_vip_and_denied_events(self):
        record = classify_audit_record({
            "event": "policy_denied",
            "remote_user": "root",
            "server_vip": True,
        })
        self.assertEqual(record["risk_tags"], ["denied", "privileged", "vip"])

    def test_signed_jsonl_sink_and_tamper_detection(self):
        tmpdir = os.path.join(ROOT, ".tmp-audit-{}".format(uuid.uuid4().hex))
        os.makedirs(tmpdir)
        key_path = os.path.join(tmpdir, "audit.key")
        spool_path = os.path.join(tmpdir, "audit.jsonl")
        try:
            with open(key_path, "wb") as key_f:
                key_f.write(b"test-signing-key")
            config = {
                "integrity": {"enabled": True, "key_file": key_path, "key_id": "test"},
                "sinks": [{"type": "jsonl", "path": spool_path}],
                "fail_closed": True,
            }
            record = prepare_and_dispatch({"event": "ssh_start", "username": "alice"}, config)
            self.assertTrue(verify_audit_record(record, b"test-signing-key"))
            self.assertTrue(verify_jsonl_file(spool_path, key_path)["valid"])
            record["username"] = "mallory"
            self.assertFalse(verify_audit_record(record, b"test-signing-key"))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


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
            ticket="INC-1",
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

    def test_ticket_validation_comments_and_repeat(self):
        redis = FakeRedis()
        config = {"access": {"ticket_required": True, "ticket_pattern": r"^(INC|CHG)-[0-9]+$"}}
        with self.assertRaises(AccessDenied):
            create_access_request(redis, {"username": "alice"}, project="prod", reason="test", config=config)
        record = create_access_request(redis, {"username": "alice"}, project="prod", reason="test", ticket="INC-123", config=config)
        commented = comment_access_request(redis, record["id"], {"username": "alice"}, "extra context")
        self.assertEqual(commented["comments"][0]["text"], "extra context")
        approved, _ = approve_access_request(redis, record["id"], {"username": "admin"}, 60, comment="approved")
        self.assertEqual(approved["comments"][-1]["action"], "approve")
        repeated = repeat_access_request(redis, record["id"], {"username": "alice"}, reason="again", ticket="CHG-1", config=config)
        self.assertEqual(repeated["status"], "pending")
        self.assertEqual(repeated["ticket"], "CHG-1")


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

    def test_best_effort_sink_failure_keeps_local_session_log(self):
        tmpdir = os.path.join(ROOT, ".tmp-session-sink-{}".format(uuid.uuid4().hex))
        os.makedirs(tmpdir)
        blocked_parent = os.path.join(tmpdir, "not-a-directory")
        try:
            with open(blocked_parent, "w", encoding="utf-8") as blocked_f:
                blocked_f.write("blocked")
            logger = SessionLogger(
                tmpdir,
                {"username": "alice", "groups": [], "session_id": "session-sink"},
                logging_config={
                    "fail_closed": False,
                    "sinks": [{"type": "jsonl", "path": os.path.join(blocked_parent, "audit.jsonl")}],
                },
            )
            logger.event("ssh_start", project="prod")
            with open(logger.jsonl_path, "r", encoding="utf-8") as session_f:
                self.assertIn("ssh_start", session_f.read())
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
            self.assertEqual(replay["duration"], 0.5)
            self.assertEqual(replay["chunks"][0]["t"], 0.0)
            self.assertIn("whoami", replay["plain"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_command_audit_append_writes_command_event(self):
        tmpdir = os.path.join(ROOT, ".tmp-command-audit-{}".format(uuid.uuid4().hex))
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
                        "groups": ["DevOps"],
                        "project": "prod",
                        "host_id": "10001",
                        "connection_id": "conn-1",
                        "session_id": "session-1",
                    }
                ],
            )
            config = {"command_audit": {"enabled": True, "require_connection_id": True, "max_command_length": 4}}
            event = append_command_event(
                tmpdir,
                "conn-1",
                "systemctl status nginx",
                cwd="/root",
                exit_code=0,
                shell="bash",
                config=config,
            )
            self.assertEqual(event["event"], "command")
            self.assertEqual(event["command"], "syst")
            self.assertTrue(event["command_truncated"])
            details = find_session(tmpdir, "conn-1")
            self.assertEqual(details["events"][-1]["event"], "command")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_command_audit_rejects_disabled_or_unknown_session(self):
        with self.assertRaises(CommandAuditError):
            append_command_event("/tmp/no-such-dir", "missing", "whoami", config={"command_audit": {"enabled": False}})
        with self.assertRaises(CommandAuditError):
            append_command_event("/tmp/no-such-dir", "missing", "whoami", config={"command_audit": {"enabled": True}})

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

    def test_health_endpoint_does_not_require_login(self):
        try:
            app = isolate_web.create_app({
                "dashboard": {"admin_groups": ["DevOps"], "public_url": "https://bastion.example.org"},
                "keycloak": {"issuer": "https://id.example.org/realms/demo", "client_id": "isolate"},
                "logging": {"base_path": "/tmp/isolate"},
            })
        except ImportError as exc:
            self.skipTest(str(exc))
        with mock.patch.object(isolate_web, "run_health_checks", return_value={"ok": True, "status": "ok", "checks": {}}):
            response = app.test_client().get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

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
            response = client.get("/access?ticket=INC-1")

        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn('http-equiv="refresh" content="15"', text)
        self.assertIn('name="csrf_token" value="csrf"', text)
        self.assertIn("INC-1", text)
        self.assertIn('name="comment"', text)
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
                    {
                        "event": "command",
                        "ts": 12.0,
                        "username": "admin",
                        "connection_id": "conn-1",
                        "session_id": "session-1",
                        "cwd": "/root",
                        "command": "whoami",
                        "exit_code": 0,
                        "shell": "bash",
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
            details_text = details.get_data(as_text=True)
            self.assertIn("Session Details", details_text)
            self.assertIn("/replay/conn-1", details_text)
            self.assertIn("Commands", details_text)
            self.assertIn("whoami", details_text)

            events = client.get("/session/conn-1/events.json")
            self.assertEqual(events.status_code, 200)
            self.assertIn("policy_selected", events.get_data(as_text=True))

            replay = client.get("/replay/conn-1.json")
            self.assertEqual(replay.status_code, 200)
            self.assertIn("hello", replay.get_data(as_text=True))

            replay_page = client.get("/replay/conn-1")
            replay_text = replay_page.get_data(as_text=True)
            self.assertIn('id="scrubber"', replay_text)
            self.assertIn("Plain transcript", replay_text)
            self.assertIn("replay.json", replay_text)
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
        args = SimpleNamespace(project="prod", host="10001", remote_user="dba", sudo_mode="none", reason="INC-1", ticket=None, template=None)
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
                SimpleNamespace(id=first["id"], ttl="2h", remote_user=None, sudo_mode=None, comment=None),
                config,
            )
            deny_code = isolate.cmd_access_deny(SimpleNamespace(id=second["id"], reason="not needed", comment=None), config)

        self.assertIsNone(approve_code)
        self.assertIsNone(deny_code)
        self.assertEqual([call[0][1] for call in notifier.call_args_list], ["access_request_approved", "access_request_denied"])


if __name__ == "__main__":
    unittest.main()
