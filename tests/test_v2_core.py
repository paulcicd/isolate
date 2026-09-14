import os
import shutil
import sys
import uuid
import unittest
import fnmatch
import json
import subprocess
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
import isolate_policy_bundle
from isolate_identity import (
    IdentityError,
    KeycloakDeviceClient,
    load_cached_identity,
    load_verified_identity,
    normalize_claims,
    save_identity,
    save_token_cache,
)
from isolate_history import HistoryAccessDenied, read_history, user_activity_summary
from isolate_inventory import HostValidationError, bulk_update_hosts, create_host, format_hosts_table, get_host, is_host_in_maintenance, list_hosts, update_host
from isolate_announcements import AnnouncementError, create_announcement, delete_announcement, list_announcements
from isolate_connectivity import check_host, get_last_check, save_check
from isolate_exports import flatten_access_matrix, render_export
from isolate_logging import SessionLogger
from isolate_policy import PolicyDenied, filter_allowed_hosts, matching_grants, resolve_grant, resolve_policy
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
    get_access_request,
    is_access_admin,
    list_access_requests,
    parse_duration,
    repeat_access_request,
)
from isolate import list_grant_records, load_grants, load_project_sets, update_grant_record
from isolate_sessions import (
    get_session,
    list_active_sessions,
    mark_alert_delivery,
    mark_session_end,
    mark_session_start,
    request_session_termination,
)
from isolate_session_alerts import initial_session_alerts, long_session_alert, source_is_unusual
from isolate_web import is_dashboard_admin
from isolate_notifications import NotificationError, build_access_notification, build_session_notification, notify_access_event
from isolate_audit import classify_audit_record, prepare_and_dispatch, verify_audit_record, verify_jsonl_file
from isolate_backup import BackupError, create_backup, restore_backup, restore_redis_snapshot, verify_backup
from isolate_health import run_health_checks, validate_config
from isolate_policy_bundle import PolicyBundleError, apply_bundle, blast_radius, export_bundle, plan_bundle, validate_bundle
from isolate_gitops import (
    create_approval_attestation,
    git_policy_status,
    GitOpsError,
    list_policy_snapshots,
    rollback_policy,
    sync_git_policy,
    verify_approval_attestation,
)
from isolate_redis import redis_options
from isolate_retention import expired_session_dirs
from isolate_mcp import (
    IsolateMCPService,
    KeycloakMCPTokenVerifier,
    MCPAccessDenied,
    create_mcp_server,
    token_scopes,
)
from isolate_jobs import JobError, create_runbook_fleet, execute_job, get_job, list_jobs, retry_job, verify_job_signature
from isolate_runbooks import RunbookError, list_runbooks, render_runbook
from isolate_dashboard_data import build_access_matrix, collect_alerts, fleet_progress, preview_grant_change, update_alert_state
from isolate_build import get_build_info
from isolate_packages import (
    AccessPackageError,
    assign_package,
    create_package,
    get_package,
    list_assignments,
    list_package_revisions,
    preview_package_update,
    rollback_package,
    unassign_package,
    update_package,
)


def has_mcp_v2():
    try:
        from mcp.server import MCPServer  # noqa: F401
        return True
    except ImportError:
        return False


class FakeRedis(object):
    def __init__(self):
        self.store = {}
        self.ttls = {}

    def keys(self, pattern):
        return [key for key in self.store if fnmatch.fnmatchcase(key, pattern)]

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return False
        self.store[key] = value
        if ex is not None:
            self.ttls[key] = int(ex) * 1000
        return True

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
        self.ttls[self._key(key)] = int(ttl) * 1000
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

    def test_dashboard_job_limits_are_validated(self):
        result = validate_config({
            "keycloak": {"client_id": "isolate"},
            "dashboard": {"jobs_max_results": 0},
            "runbooks": {"max_fleet_hosts": 1001},
        })
        self.assertIn("dashboard.jobs_max_results must be greater than zero", result["errors"])
        self.assertIn("runbooks.max_fleet_hosts must be between 1 and 1000", result["errors"])


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


class MCPServiceTest(unittest.TestCase):
    def _config(self, log_path):
        signing_key = os.path.join(log_path, "job_hmac.key")
        if os.path.isdir(log_path) and not os.path.exists(signing_key):
            with open(signing_key, "wb") as key_f:
                key_f.write(b"test-only-command-job-signing-key-32-bytes")
        return {
            "keycloak": {"issuer": "https://id.example.org/realms/demo", "client_id": "isolate-bastion"},
            "mcp": {
                "enabled": True,
                "public_url": "https://mcp.example.org/mcp",
                "expected_audience": "isolate-mcp",
                "required_scopes": ["isolate.read"],
                "self_service_scope": "isolate.self-service",
                "approval_scope": "isolate.approve",
                "inventory_write_scope": "isolate.inventory.write",
                "policy_read_scope": "isolate.policy.read",
                "execute_scope": "isolate.execute",
                "runbook_scope": "isolate.runbook",
                "operate_scope": "isolate.operate",
                "inventory_admin_groups": ["Demo-Security"],
                "policy_admin_groups": ["Demo-Security"],
                "execution_admin_groups": ["Demo-Security"],
                "prevent_self_approval": True,
                "require_mutation_confirmation": True,
                "allowed_hosts": ["mcp.example.org"],
                "allowed_origins": [],
                "max_results": 100,
            },
            "ssh": {"default_sudo_mode": "none"},
            "policy": {"fallback_remote_user": None},
            "logging": {
                "base_path": log_path,
                "sinks": [],
                "fail_closed": False,
                "integrity": {"enabled": False},
            },
            "history": {"default_limit": 10, "max_limit": 100},
            "notifications": {"enabled": False, "sinks": []},
            "command_execution": {
                "enabled": False,
                "allowed_groups": ["Demo-DevOps"],
                "allow_arbitrary_commands": False,
                "allowed_command_patterns": [r"^(uptime|whoami)$"],
                "allow_sudo": False,
                "require_confirmation": True,
                "default_timeout": 60,
                "max_timeout": 900,
                "max_command_length": 4096,
                "max_output_bytes": 1048576,
                "max_return_bytes": 262144,
                "jobs_path": log_path,
                "signing_key_file": signing_key,
                "remote_shell": "/bin/sh",
            },
            "runbooks": {
                "enabled": False,
                "disabled": [],
                "read_only": {
                    "allowed_groups": ["Demo-DevOps"],
                    "allow_sudo": False,
                    "require_confirmation": True,
                },
                "operational": {
                    "enabled": False,
                    "allowed_groups": ["Demo-DevOps"],
                    "allow_sudo": False,
                    "require_confirmation": True,
                },
            },
            "access": {
                "admin_groups": ["Demo-Security"],
                "default_ttl": "2h",
                "max_ttl": "24h",
                "ticket_required": False,
                "request_templates": {},
            },
        }

    def _redis(self):
        redis = FakeRedis()
        redis.set("server_1", json.dumps({
            "server_id": 1,
            "project_name": "payments-prod",
            "server_name": "api-1",
            "server_ip": "10.0.0.1",
            "server_user": "support",
        }))
        redis.set("server_2", json.dumps({
            "server_id": 2,
            "project_name": "secret-prod",
            "server_name": "db-1",
            "server_ip": "10.0.0.2",
            "server_user": "dba",
        }))
        redis.set("project_set_payments", json.dumps({
            "schema_version": 2,
            "name": "payments",
            "projects": ["payments-prod"],
            "project_globs": [],
        }))
        redis.set("grant_1", json.dumps({
            "schema_version": 2,
            "subject": "group",
            "name": "Demo-DevOps",
            "project_set": "payments",
            "remote_user": "support",
            "sudo_mode": "none",
            "allowed_actions": ["ssh"],
        }))
        redis.set("offset_grant_id", "1")
        return redis

    def _identity(self):
        return {
            "username": "demo.alex",
            "email": "demo.alex@example.org",
            "keycloak_sub": "sub-1",
            "groups": ["Demo-DevOps"],
            "roles": [],
        }

    def _admin_identity(self):
        return {
            "username": "demo.admin",
            "email": "demo.admin@example.org",
            "keycloak_sub": "sub-admin",
            "groups": ["Demo-Security"],
            "roles": [],
        }

    def test_inventory_and_host_get_follow_existing_grants(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-") as logs:
            service = IsolateMCPService(self._config(logs), self._redis())
            result = service.inventory_search(self._identity())
            self.assertEqual([host["server_id"] for host in result["hosts"]], ["1"])
            self.assertEqual(service.inventory_projects(self._identity())["projects"], ["payments-prod"])
            self.assertEqual(service.host_get(self._identity(), "1")["server_name"], "api-1")
            with self.assertRaises(MCPAccessDenied):
                service.host_get(self._identity(), "2")

    def test_grant_explain_and_pending_access_request(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-") as logs:
            redis = self._redis()
            service = IsolateMCPService(self._config(logs), redis)
            explained = service.grant_explain(self._identity(), host_id="1")
            self.assertTrue(explained["allowed"])
            self.assertEqual(explained["remote_user"], "support")
            denied = service.grant_explain(self._identity(), host_id="2")
            self.assertFalse(denied["allowed"])

            created = service.access_request_create(
                self._identity(),
                project="secret-prod",
                host="2",
                remote_user="dba",
                sudo_mode="none",
                reason="INC-1001 diagnostics",
                ticket="INC-1001",
            )
            self.assertEqual(created["request"]["status"], "pending")
            self.assertEqual(json.loads(redis.get("access_request_1"))["requester"], "demo.alex")
            self.assertIsNone(redis.get("grant_2"))

    def test_history_is_scoped_to_authenticated_user(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-history-") as logs:
            session_dir = os.path.join(logs, "demo.alex", "session-1")
            other_dir = os.path.join(logs, "demo.bailey", "session-2")
            os.makedirs(session_dir)
            os.makedirs(other_dir)
            own = {"event": "ssh_start", "ts": 10, "username": "demo.alex", "project": "payments-prod", "host_id": "1", "target_host": "10.0.0.1", "remote_user": "support"}
            other = {"event": "ssh_start", "ts": 20, "username": "demo.bailey", "project": "secret-prod", "host_id": "2", "target_host": "10.0.0.2", "remote_user": "dba"}
            with open(os.path.join(session_dir, "session.jsonl"), "w", encoding="utf-8") as session_f:
                session_f.write(json.dumps(own) + "\n")
            with open(os.path.join(other_dir, "session.jsonl"), "w", encoding="utf-8") as session_f:
                session_f.write(json.dumps(other) + "\n")
            service = IsolateMCPService(self._config(logs), self._redis())
            rows = service.history_search(self._identity())["connections"]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["username"], "demo.alex")

    def test_access_request_visibility_requires_scope_and_admin_group(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-access-") as logs:
            redis = self._redis()
            own = create_access_request(redis, self._identity(), project="payments-prod", host="1", reason="own")
            other_identity = {"username": "demo.bailey", "keycloak_sub": "sub-2", "groups": []}
            other = create_access_request(redis, other_identity, project="secret-prod", host="2", reason="other")
            service = IsolateMCPService(self._config(logs), redis)

            own_list = service.access_request_list(
                self._identity(),
                ["isolate.read", "isolate.self-service"],
            )
            self.assertEqual([row["id"] for row in own_list["requests"]], [own["id"]])
            self.assertFalse(own_list["admin_view"])
            with self.assertRaises(MCPAccessDenied):
                service.access_request_show(self._identity(), ["isolate.read", "isolate.self-service"], other["id"])

            with self.assertRaises(MCPAccessDenied):
                service.access_request_list(
                    self._admin_identity(),
                    ["isolate.read"],
                    user="demo.bailey",
                )

            admin_list = service.access_request_list(
                self._admin_identity(),
                ["isolate.read", "isolate.approve"],
            )
            self.assertEqual({row["id"] for row in admin_list["requests"]}, {own["id"], other["id"]})
            self.assertTrue(admin_list["admin_view"])
            self.assertEqual(
                service.access_request_show(self._admin_identity(), ["isolate.approve"], other["id"])["request"]["requester"],
                "demo.bailey",
            )

            redis.set("access_request_lock_999", "transient", ex=30)
            locked_list = service.access_request_list(
                self._admin_identity(),
                ["isolate.read", "isolate.approve"],
            )
            self.assertEqual({row["id"] for row in locked_list["requests"]}, {own["id"], other["id"]})

    def test_access_request_comment_is_attributed_and_scoped(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-access-") as logs:
            redis = self._redis()
            request_record = create_access_request(redis, self._identity(), project="payments-prod", host="1", reason="review")
            service = IsolateMCPService(self._config(logs), redis)

            result = service.access_request_comment(
                self._identity(),
                ["isolate.self-service"],
                request_record["id"],
                "Additional context",
            )
            comment = result["request"]["comments"][0]
            self.assertEqual(comment["username"], "demo.alex")
            self.assertEqual(comment["text"], "Additional context")
            with self.assertRaises(MCPAccessDenied):
                service.access_request_comment(
                    {"username": "demo.bailey", "groups": []},
                    ["isolate.self-service"],
                    request_record["id"],
                    "not allowed",
                )

    def test_access_approval_requires_two_factors_confirmation_and_no_self_approval(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-access-") as logs:
            redis = self._redis()
            requester = {"username": "demo.bailey", "keycloak_sub": "sub-2", "groups": ["Demo-Security"]}
            request_record = create_access_request(
                redis,
                requester,
                project="secret-prod",
                host="2",
                remote_user="dba",
                sudo_mode="none",
                reason="INC-2001",
            )
            service = IsolateMCPService(self._config(logs), redis)

            with self.assertRaises(MCPAccessDenied):
                service.access_request_approve(
                    self._admin_identity(), ["isolate.approve"], request_record["id"], confirm=False
                )
            with self.assertRaises(MCPAccessDenied):
                service.access_request_approve(
                    self._admin_identity(), ["isolate.read"], request_record["id"], confirm=True
                )
            with self.assertRaises(MCPAccessDenied):
                service.access_request_approve(
                    requester, ["isolate.approve"], request_record["id"], confirm=True
                )
            with self.assertRaises(AccessDenied):
                service.access_request_approve(
                    self._admin_identity(), ["isolate.approve"], request_record["id"], ttl="25h", confirm=True
                )

            approved = service.access_request_approve(
                self._admin_identity(),
                ["isolate.approve"],
                request_record["id"],
                ttl="2h",
                comment="Approved for incident window",
                confirm=True,
            )
            self.assertEqual(approved["request"]["status"], "approved")
            self.assertEqual(approved["request"]["decided_by"], "demo.admin")
            self.assertEqual(approved["grant"]["remote_user"], "dba")
            self.assertTrue(approved["grant"]["temporary"])
            self.assertEqual(json.loads(redis.get("grant_2"))["request_id"], request_record["id"])
            with self.assertRaises(AccessDenied):
                service.access_request_approve(
                    self._admin_identity(), ["isolate.approve"], request_record["id"], confirm=True
                )

    def test_access_deny_requires_confirmation_and_records_reason(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-access-") as logs:
            redis = self._redis()
            requester = {"username": "demo.bailey", "keycloak_sub": "sub-2", "groups": []}
            request_record = create_access_request(redis, requester, project="secret-prod", host="2", reason="request")
            service = IsolateMCPService(self._config(logs), redis)

            with self.assertRaises(MCPAccessDenied):
                service.access_request_deny(
                    self._admin_identity(), ["isolate.approve"], request_record["id"], reason="No change", confirm=False
                )
            denied = service.access_request_deny(
                self._admin_identity(),
                ["isolate.approve"],
                request_record["id"],
                reason="Use staging",
                comment="Production access is unnecessary",
                confirm=True,
            )
            self.assertEqual(denied["request"]["status"], "denied")
            self.assertEqual(denied["request"]["decision_reason"], "Use staging")
            self.assertEqual(denied["request"]["comments"][0]["action"], "deny")

    def test_access_decision_lock_rejects_concurrent_mcp_mutation(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-access-") as logs:
            redis = self._redis()
            requester = {"username": "demo.bailey", "keycloak_sub": "sub-2", "groups": []}
            request_record = create_access_request(
                redis,
                requester,
                project="secret-prod",
                host="2",
                remote_user="dba",
                reason="request",
            )
            redis.set("access_request_lock_{}".format(request_record["id"]), "another-worker", ex=30)
            service = IsolateMCPService(self._config(logs), redis)
            with self.assertRaisesRegex(AccessDenied, "already in progress"):
                service.access_request_approve(
                    self._admin_identity(),
                    ["isolate.approve"],
                    request_record["id"],
                    confirm=True,
                )
            self.assertEqual(get_access_request(redis, request_record["id"])["status"], "pending")
            self.assertIsNone(redis.get("grant_2"))

    def test_inventory_mutations_require_admin_scope_dry_run_and_revision(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-inventory-") as logs:
            redis = self._redis()
            service = IsolateMCPService(self._config(logs), redis)
            values = {
                "project_name": "payments-prod",
                "server_name": "api-2",
                "server_ip": "10.0.0.3",
                "server_user": "support",
                "server_port": 22,
                "server_services": "nginx",
            }
            with self.assertRaises(MCPAccessDenied):
                service.inventory_host_add(self._identity(), ["isolate.inventory.write"], values)

            preview = service.inventory_host_add(
                self._admin_identity(), ["isolate.inventory.write"], values
            )
            self.assertFalse(preview["applied"])
            self.assertIsNone(redis.get("server_10001"))
            with self.assertRaises(MCPAccessDenied):
                service.inventory_host_add(
                    self._admin_identity(), ["isolate.inventory.write"], values, dry_run=False, confirm=False
                )
            created = service.inventory_host_add(
                self._admin_identity(), ["isolate.inventory.write"], values, dry_run=False, confirm=True
            )["host"]
            self.assertEqual(created["server_id"], "10001")
            self.assertTrue(created["_revision"])

            update_preview = service.inventory_host_update(
                self._admin_identity(), ["isolate.inventory.write"], created["server_id"], {"server_note": "new note"}
            )
            self.assertFalse(update_preview["applied"])
            updated = service.inventory_host_update(
                self._admin_identity(),
                ["isolate.inventory.write"],
                created["server_id"],
                {"server_note": "new note"},
                expected_revision=update_preview["current_revision"],
                dry_run=False,
                confirm=True,
            )["host"]
            self.assertEqual(updated["server_note"], "new note")
            with self.assertRaisesRegex(MCPAccessDenied, "revision changed"):
                service.inventory_host_update(
                    self._admin_identity(),
                    ["isolate.inventory.write"],
                    created["server_id"],
                    {"server_note": "stale"},
                    expected_revision=update_preview["current_revision"],
                    dry_run=False,
                    confirm=True,
                )

    def test_policy_admin_reads_and_previews_command_action(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-policy-") as logs:
            redis = self._redis()
            service = IsolateMCPService(self._config(logs), redis)
            with self.assertRaises(MCPAccessDenied):
                service.grant_list(self._identity(), ["isolate.policy.read"])

            grants = service.grant_list(self._admin_identity(), ["isolate.policy.read"])
            self.assertEqual(grants["count"], 1)
            self.assertEqual(service.grant_show(self._admin_identity(), ["isolate.policy.read"], "1")["grant"]["name"], "Demo-DevOps")
            self.assertEqual(service.project_set_list(self._admin_identity(), ["isolate.policy.read"])["count"], 1)
            self.assertEqual(
                service.project_set_show(self._admin_identity(), ["isolate.policy.read"], "payments")["project_set"]["name"],
                "payments",
            )
            denied = service.policy_preview(
                self._admin_identity(),
                ["isolate.policy.read"],
                host_id="1",
                action="command",
                user="demo.alex",
                groups=["Demo-DevOps"],
            )
            self.assertFalse(denied["allowed"])
            grant = json.loads(redis.get("grant_1"))
            grant["allowed_actions"] = ["ssh", "command"]
            redis.set("grant_1", json.dumps(grant))
            allowed = service.policy_preview(
                self._admin_identity(),
                ["isolate.policy.read"],
                host_id="1",
                action="command",
                user="demo.alex",
                groups=["Demo-DevOps"],
            )
            self.assertTrue(allowed["allowed"])
            self.assertEqual(allowed["decision"]["remote_user"], "support")

    def test_runbook_catalog_and_parameter_validation(self):
        config = self._config("unused")
        read_only = list_runbooks(config, classes=["read_only"])
        operational = list_runbooks(config, classes=["operational"])
        self.assertEqual(len(read_only), 15)
        self.assertEqual(
            {item["id"] for item in operational},
            {"service-restart", "dns-cache-flush", "deploy-diagnostics"},
        )
        rendered = render_runbook(config, "journal-tail", {"service": "nginx.service", "lines": 25})
        self.assertIn("nginx.service", rendered["command"])
        self.assertIn("25", rendered["command"])
        self.assertEqual(rendered["policy_action"], "runbook")
        with self.assertRaises(RunbookError):
            render_runbook(config, "service-status", {"service": "nginx; id"})
        with self.assertRaises(RunbookError):
            render_runbook(config, "uptime", {"command": "id"})

    def test_read_only_runbook_authorization_and_worker_revalidation(self):
        with tempfile.TemporaryDirectory(prefix="isolate-runbook-jobs-") as jobs_path:
            config = self._config(jobs_path)
            config["runbooks"]["enabled"] = True
            redis = self._redis()
            grant = json.loads(redis.get("grant_1"))
            grant["allowed_actions"] = ["ssh", "runbook"]
            redis.set("grant_1", json.dumps(grant))
            service = IsolateMCPService(config, redis)

            with self.assertRaises(MCPAccessDenied):
                service.runbook_execute(
                    self._identity(), ["isolate.runbook"], "uptime", "1", confirm=False
                )
            queued = service.runbook_execute(
                self._identity(), ["isolate.runbook"], "uptime", "1", confirm=True
            )["job"]
            self.assertEqual(queued["type"], "runbook")
            self.assertEqual(queued["policy_action"], "runbook")
            self.assertEqual(service.runbook_list(self._identity(), ["isolate.runbook"])["count"], 15)
            self.assertEqual(service.runbook_show(
                self._identity(), ["isolate.runbook"], "uptime"
            )["runbook"]["class"], "read_only")

            with mock.patch(
                "isolate_jobs.build_ssh_argv",
                return_value=[sys.executable, "-c", "print('up 10 days')"],
            ):
                completed = execute_job(redis, config, queued)
            self.assertEqual(completed["status"], "completed")
            self.assertIn("up 10 days", service.command_job_output(
                self._identity(), ["isolate.runbook"], queued["id"]
            )["output"])

            queued = service.runbook_execute(
                self._identity(), ["isolate.runbook"], "uptime", "1", confirm=True
            )["job"]
            grant["allowed_actions"] = ["ssh"]
            redis.set("grant_1", json.dumps(grant))
            with mock.patch("isolate_jobs.subprocess.Popen") as popen:
                failed = execute_job(redis, config, queued)
            self.assertEqual(failed["status"], "failed")
            self.assertIn("authorization changed", failed["error"])
            popen.assert_not_called()

    def test_operational_runbooks_require_separate_enable_scope_and_action(self):
        with tempfile.TemporaryDirectory(prefix="isolate-operational-jobs-") as jobs_path:
            config = self._config(jobs_path)
            config["runbooks"]["enabled"] = True
            redis = self._redis()
            grant = json.loads(redis.get("grant_1"))
            grant["allowed_actions"] = ["ssh", "runbook", "operate"]
            redis.set("grant_1", json.dumps(grant))
            service = IsolateMCPService(config, redis)

            with self.assertRaises(MCPAccessDenied):
                service.runbook_execute(
                    self._identity(), ["isolate.operate"], "service-restart", "1",
                    parameters={"service": "nginx"}, confirm=True,
                )
            config["runbooks"]["operational"]["enabled"] = True
            with self.assertRaises(MCPAccessDenied):
                service.runbook_execute(
                    self._identity(), ["isolate.runbook"], "service-restart", "1",
                    parameters={"service": "nginx"}, confirm=True,
                )
            queued = service.runbook_execute(
                self._identity(), ["isolate.operate"], "service-restart", "1",
                parameters={"service": "nginx"}, confirm=True,
            )["job"]
            self.assertEqual(queued["runbook_class"], "operational")
            self.assertEqual(queued["policy_action"], "operate")

    def test_command_job_authorization_lifecycle_and_output(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-jobs-") as jobs_path:
            config = self._config(jobs_path)
            config["command_execution"]["enabled"] = True
            redis = self._redis()
            grant = json.loads(redis.get("grant_1"))
            grant["allowed_actions"] = ["ssh", "command"]
            redis.set("grant_1", json.dumps(grant))
            service = IsolateMCPService(config, redis)

            with self.assertRaises(MCPAccessDenied):
                service.command_job_create(self._identity(), ["isolate.execute"], "1", "uptime", confirm=False)
            with self.assertRaises(JobError):
                service.command_job_create(self._identity(), ["isolate.execute"], "1", "rm -rf /", confirm=True)
            queued = service.command_job_create(
                self._identity(), ["isolate.execute"], "1", "uptime", confirm=True
            )["job"]
            self.assertEqual(queued["status"], "queued")
            self.assertEqual(service.command_job_list(self._identity(), ["isolate.execute"])["count"], 1)
            with self.assertRaises(MCPAccessDenied):
                service.command_job_show({"username": "demo.bailey", "groups": []}, ["isolate.read"], queued["id"])

            with mock.patch(
                "isolate_jobs.build_ssh_argv",
                return_value=[sys.executable, "-c", "print('up 10 days')"],
            ):
                completed = execute_job(redis, config, queued)
            self.assertEqual(completed["status"], "completed")
            output = service.command_job_output(self._identity(), ["isolate.execute"], queued["id"])
            self.assertIn("up 10 days", output["output"])
            tampered_output_record = get_job(redis, queued["id"])
            tampered_output_record["output_path"] = config["command_execution"]["signing_key_file"]
            redis.set("job_{}".format(queued["id"]), json.dumps(tampered_output_record))
            safe_output = service.command_job_output(self._identity(), ["isolate.execute"], queued["id"])
            self.assertIn("up 10 days", safe_output["output"])
            self.assertNotIn("test-only-command-job-signing", safe_output["output"])

            config["command_execution"]["max_output_bytes"] = 5
            limited = service.command_job_create(
                self._identity(), ["isolate.execute"], "1", "uptime", confirm=True
            )["job"]
            with mock.patch(
                "isolate_jobs.build_ssh_argv",
                return_value=[sys.executable, "-c", "print('x' * 1000)"],
            ):
                limited_result = execute_job(redis, config, limited)
            self.assertEqual(limited_result["status"], "failed")
            self.assertTrue(limited_result["output_truncated"])
            self.assertLessEqual(limited_result["output_bytes"], 5)

            second = service.command_job_create(
                self._identity(), ["isolate.execute"], "1", "whoami", confirm=True
            )["job"]
            cancelled = service.command_job_cancel(
                self._identity(), ["isolate.execute"], second["id"], confirm=True
            )["job"]
            self.assertEqual(cancelled["status"], "cancelled")

    def test_arbitrary_command_mode_still_requires_command_grant(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-jobs-") as jobs_path:
            config = self._config(jobs_path)
            config["command_execution"].update({"enabled": True, "allow_arbitrary_commands": True})
            redis = self._redis()
            service = IsolateMCPService(config, redis)
            with self.assertRaises(PolicyDenied):
                service.command_job_create(
                    self._identity(), ["isolate.execute"], "1", "journalctl -u nginx | tail", confirm=True
                )
            grant = json.loads(redis.get("grant_1"))
            grant["allowed_actions"] = ["ssh", "command"]
            redis.set("grant_1", json.dumps(grant))
            job = service.command_job_create(
                self._identity(), ["isolate.execute"], "1", "journalctl -u nginx | tail", confirm=True
            )["job"]
            self.assertEqual(job["status"], "queued")

    def test_worker_revalidates_command_grant_before_ssh(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-jobs-") as jobs_path:
            config = self._config(jobs_path)
            config["command_execution"]["enabled"] = True
            redis = self._redis()
            grant = json.loads(redis.get("grant_1"))
            grant["allowed_actions"] = ["ssh", "command"]
            redis.set("grant_1", json.dumps(grant))
            service = IsolateMCPService(config, redis)
            job = service.command_job_create(
                self._identity(), ["isolate.execute"], "1", "uptime", confirm=True
            )["job"]
            grant["allowed_actions"] = ["ssh"]
            redis.set("grant_1", json.dumps(grant))
            with mock.patch("isolate_jobs.subprocess.Popen") as popen:
                failed = execute_job(redis, config, job)
            self.assertEqual(failed["status"], "failed")
            self.assertIn("authorization changed", failed["error"])
            popen.assert_not_called()

    def test_worker_rejects_tampered_job_signature(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-jobs-") as jobs_path:
            config = self._config(jobs_path)
            config["command_execution"]["enabled"] = True
            redis = self._redis()
            grant = json.loads(redis.get("grant_1"))
            grant["allowed_actions"] = ["ssh", "command"]
            redis.set("grant_1", json.dumps(grant))
            service = IsolateMCPService(config, redis)
            job = service.command_job_create(
                self._identity(), ["isolate.execute"], "1", "uptime", confirm=True
            )["job"]
            job["command"] = "whoami"
            redis.set("job_{}".format(job["id"]), json.dumps(job))
            with mock.patch("isolate_jobs.subprocess.Popen") as popen:
                failed = execute_job(redis, config, job)
            self.assertEqual(failed["status"], "failed")
            self.assertIn("signature is invalid", failed["error"])
            popen.assert_not_called()

    def test_mcp_operations_emit_redacted_audit_records(self):
        with tempfile.TemporaryDirectory(prefix="isolate-mcp-audit-") as root:
            config = self._config(os.path.join(root, "logs"))
            audit_path = os.path.join(root, "audit.jsonl")
            config["logging"]["sinks"] = [{"type": "jsonl", "path": audit_path}]
            service = IsolateMCPService(config, self._redis())
            service.inventory_search(self._identity(), query="api")
            with open(audit_path, "r", encoding="utf-8") as audit_f:
                record = json.loads(audit_f.readline())
            self.assertEqual(record["event"], "mcp_tool_call")
            self.assertEqual(record["tool"], "inventory_search")
            self.assertEqual(record["username"], "demo.alex")
            self.assertNotIn("token", record)
            self.assertNotIn("query", record)

    def test_token_scopes_and_strict_mcp_audience(self):
        self.assertEqual(token_scopes({"scope": "openid isolate.read isolate.read"}), ["isolate.read", "openid"])
        config = self._config("unused")
        verifier = KeycloakMCPTokenVerifier(config)
        claims = {
            "sub": "sub-1",
            "azp": "desktop-client",
            "aud": ["isolate-mcp"],
            "exp": 2000000000,
            "scope": "isolate.read isolate.self-service",
        }
        with mock.patch("isolate_mcp.verify_jwt_claims", return_value=claims):
            data = verifier.verified_token_data("signed-token")
        self.assertEqual(data["subject"], "sub-1")
        self.assertIn("isolate.read", data["scopes"])
        claims["aud"] = ["another-api"]
        claims["azp"] = "isolate-mcp"
        with mock.patch("isolate_mcp.verify_jwt_claims", return_value=claims):
            self.assertIsNone(verifier.verified_token_data("wrong-audience"))

    def test_mcp_config_validation_fails_closed(self):
        config = self._config("unused")
        self.assertTrue(validate_config(config)["valid"])
        config["mcp"]["expected_audience"] = None
        self.assertFalse(validate_config(config)["valid"])
        config["mcp"]["expected_audience"] = "isolate-mcp"
        config["mcp"]["public_url"] = "http://mcp.example.org/mcp"
        self.assertFalse(validate_config(config)["valid"])

    def test_command_execution_config_is_fail_closed(self):
        config = self._config(os.path.abspath("unused"))
        config["command_execution"].update({
            "enabled": True,
            "allow_arbitrary_commands": True,
        })
        validation = validate_config(config)
        self.assertTrue(validation["valid"], validation["errors"])
        self.assertIn("arbitrary remote command execution is enabled", validation["warnings"])
        config["command_execution"]["allowed_groups"] = []
        self.assertFalse(validate_config(config)["valid"])

    def test_runbook_config_is_fail_closed(self):
        config = self._config(os.path.abspath("unused"))
        config["runbooks"]["enabled"] = True
        validation = validate_config(config)
        self.assertTrue(validation["valid"], validation["errors"])
        config["runbooks"]["read_only"]["allowed_groups"] = []
        self.assertFalse(validate_config(config)["valid"])
        config["runbooks"]["read_only"]["allowed_groups"] = ["Demo-DevOps"]
        config["runbooks"]["operational"]["enabled"] = True
        validation = validate_config(config)
        self.assertTrue(validation["valid"], validation["errors"])
        self.assertIn("operational runbooks are enabled", validation["warnings"])

    @unittest.skipUnless(has_mcp_v2(), "MCP SDK v2 is not installed")
    def test_official_sdk_server_registers_phase_three_surface(self):
        from mcp.server.transport_security import TransportSecuritySettings
        from starlette.testclient import TestClient

        with tempfile.TemporaryDirectory(prefix="isolate-mcp-sdk-") as logs:
            redis = self._redis()
            config = self._config(logs)
            config["runbooks"]["enabled"] = True
            server = create_mcp_server(config, redis)
            app = server.streamable_http_app(
                stateless_http=True,
                json_response=True,
                transport_security=TransportSecuritySettings(
                    allowed_hosts=["testserver"],
                    allowed_origins=[],
                ),
            )
            paths = {getattr(route, "path", None) for route in app.routes}
            self.assertIn("/mcp", paths)
            self.assertIn("/health", paths)
            self.assertIn("/.well-known/oauth-protected-resource/mcp", paths)
            with TestClient(app) as client:
                self.assertEqual(client.get("/health").status_code, 200)
                response = client.post("/mcp", json={})
                claims = {
                    "iss": "https://id.example.org/realms/demo",
                    "sub": "sub-1",
                    "preferred_username": "demo.alex",
                    "groups": ["Demo-DevOps", "Demo-Security"],
                    "aud": ["isolate-mcp"],
                    "azp": "test-client",
                    "scope": "isolate.read isolate.self-service isolate.inventory.write isolate.policy.read isolate.execute isolate.runbook isolate.operate",
                    "exp": 2000000000,
                }
                meta = {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"},
                }
                payload = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "inventory_search", "arguments": {}, "_meta": meta},
                }
                list_payload = {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/list",
                    "params": {"_meta": meta},
                }
                preview_payload = {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "inventory_host_add",
                        "arguments": {
                            "project": "payments-prod",
                            "name": "api-2",
                            "ip": "10.0.0.3",
                            "user": "support",
                        },
                        "_meta": meta,
                    },
                }
                runbook_payload = {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": "runbook_list", "arguments": {}, "_meta": meta},
                }
                with mock.patch("isolate_mcp.verify_jwt_claims", return_value=claims):
                    authorized = client.post(
                        "/mcp",
                        json=payload,
                        headers={
                            "Authorization": "Bearer signed-token",
                            "MCP-Protocol-Version": "2026-07-28",
                            "Mcp-Method": "tools/call",
                            "Mcp-Name": "inventory_search",
                        },
                    )
                    listed = client.post(
                        "/mcp",
                        json=list_payload,
                        headers={
                            "Authorization": "Bearer signed-token",
                            "MCP-Protocol-Version": "2026-07-28",
                            "Mcp-Method": "tools/list",
                        },
                    )
                    previewed = client.post(
                        "/mcp",
                        json=preview_payload,
                        headers={
                            "Authorization": "Bearer signed-token",
                            "MCP-Protocol-Version": "2026-07-28",
                            "Mcp-Method": "tools/call",
                            "Mcp-Name": "inventory_host_add",
                        },
                    )
                    runbooks = client.post(
                        "/mcp",
                        json=runbook_payload,
                        headers={
                            "Authorization": "Bearer signed-token",
                            "MCP-Protocol-Version": "2026-07-28",
                            "Mcp-Method": "tools/call",
                            "Mcp-Name": "runbook_list",
                        },
                    )
            self.assertEqual(response.status_code, 401)
            self.assertIn("resource_metadata=", response.headers.get("www-authenticate", ""))
            self.assertEqual(authorized.status_code, 200)
            hosts = authorized.json()["result"]["structuredContent"]["hosts"]
            self.assertEqual([host["server_id"] for host in hosts], ["1"])
            self.assertEqual(listed.status_code, 200)
            tool_names = {tool["name"] for tool in listed.json()["result"]["tools"]}
            self.assertTrue({
                "access_request_list",
                "access_request_show",
                "access_request_comment",
                "access_request_approve",
                "access_request_deny",
                "inventory_host_add",
                "inventory_host_update",
                "grant_list",
                "grant_show",
                "project_set_list",
                "project_set_show",
                "policy_preview",
                "command_job_create",
                "command_job_list",
                "command_job_show",
                "command_job_output",
                "command_job_cancel",
                "runbook_list",
                "runbook_show",
                "runbook_execute",
            }.issubset(tool_names))
            self.assertEqual(previewed.status_code, 200)
            self.assertFalse(previewed.json()["result"]["structuredContent"]["applied"])
            self.assertIsNone(redis.get("server_10001"))
            self.assertEqual(runbooks.status_code, 200)
            self.assertEqual(runbooks.json()["result"]["structuredContent"]["count"], 15)

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

    def test_git_prune_preserves_temporary_break_glass_grants(self):
        redis = self._current_redis()
        redis.set("grant_3", json.dumps({
            "schema_version": 2, "subject": "user", "name": "alice", "project": "payments-prod",
            "remote_user": "dba", "sudo_mode": "none", "allowed_actions": ["ssh"],
            "temporary": True, "expires_at": 4102444800, "request_id": "9",
        }))
        bundle = export_bundle(redis)
        bundle["grants"] = [row for row in bundle["grants"] if row["id"] == "1"]
        changes = apply_bundle(redis, bundle, prune=True)
        self.assertEqual([row["id"] for row in changes["grant_remove"]], ["2"])
        self.assertIsNotNone(redis.get("grant_3"))

    def test_blast_radius_reports_gained_and_lost_access(self):
        redis = self._current_redis()
        bundle = export_bundle(redis)
        bundle["grants"] = [{
            "schema_version": 2, "subject": "group", "name": "DBA", "project": "payments-prod",
            "remote_user": "dba", "sudo_mode": "none", "allowed_actions": ["ssh"],
        }]
        radius = blast_radius(redis, bundle, [{
            "server_id": "10001", "server_name": "db01", "project_name": "payments-prod",
        }], prune=True)
        self.assertEqual(radius["counts"]["gained"], 1)
        self.assertEqual(radius["counts"]["lost"], 1)

    def test_policy_approval_attestation_is_bound_to_bundle_and_branch(self):
        tmpdir = os.path.join(ROOT, ".tmp-policy-approval-{}".format(uuid.uuid4().hex))
        os.makedirs(tmpdir)
        try:
            key_path = os.path.join(tmpdir, "approval.key")
            bundle_path = os.path.join(tmpdir, "policy.json")
            with open(key_path, "wb") as key_f:
                key_f.write(b"test-policy-approval-key-at-least-32-bytes")
            bundle = {"schema_version": 2, "project_sets": [], "grants": []}
            with open(bundle_path, "w", encoding="utf-8") as bundle_f:
                json.dump(bundle, bundle_f)
            config = {"policy_as_code": {
                "require_pr_approval": True, "approval_key_file": key_path, "minimum_approvals": 2,
            }}
            attestation = create_approval_attestation(
                config, bundle_path, "main", ["reviewer.one", "reviewer.two"], pr_url="https://git.example/pr/7"
            )
            verified = verify_approval_attestation(
                config, attestation, "a" * 40, "main", policy_sha256=attestation["policy_sha256"]
            )
            self.assertTrue(verified["valid"])
            tampered = dict(attestation, approvals=["attacker"])
            with self.assertRaises(GitOpsError):
                verify_approval_attestation(config, tampered, "a" * 40, "main", policy_sha256=attestation["policy_sha256"])
            with self.assertRaises(GitOpsError):
                verify_approval_attestation(config, attestation, "a" * 40, "main", policy_sha256="0" * 64)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @unittest.skipUnless(shutil.which("git") and isolate_policy_bundle.yaml is not None, "git or PyYAML is not installed")
    def test_signed_git_sync_drift_snapshot_and_rollback(self):
        tmpdir = os.path.join(ROOT, ".tmp-policy-git-{}".format(uuid.uuid4().hex))
        source = os.path.join(tmpdir, "source")
        checkout = os.path.join(tmpdir, "checkout")
        backups = os.path.join(tmpdir, "backups")
        key_path = os.path.join(tmpdir, "approval.key")
        os.makedirs(source)
        try:
            with open(key_path, "wb") as key_f:
                key_f.write(b"test-policy-approval-key-at-least-32-bytes")
            bundle_path = os.path.join(source, "policy.json")
            bundle = {"schema_version": 2, "project_sets": [], "grants": [{
                "schema_version": 2, "subject": "group", "name": "Support", "project": "prod",
                "remote_user": "support", "sudo_mode": "none", "allowed_actions": ["ssh"],
            }]}
            with open(bundle_path, "w", encoding="utf-8") as bundle_f:
                json.dump(bundle, bundle_f, indent=2, sort_keys=True)
            config = {"policy_as_code": {
                "enabled": True, "repository": source, "checkout_path": checkout, "branch": "main",
                "git_bundle_path": "policy.json", "git_binary": shutil.which("git"), "git_timeout": 30,
                "prune": True, "require_pr_approval": True, "approval_attestation_path": "policy.approval.json",
                "approval_key_file": key_path, "minimum_approvals": 1, "backup_dir": backups,
                "require_confirmation": True,
            }}
            attestation = create_approval_attestation(config, bundle_path, "main", ["reviewer.one"])
            with open(os.path.join(source, "policy.approval.json"), "w", encoding="utf-8") as approval_f:
                json.dump(attestation, approval_f, indent=2, sort_keys=True)
            subprocess.run([shutil.which("git"), "init", "-b", "main"], cwd=source, check=True, stdout=subprocess.DEVNULL)
            subprocess.run([shutil.which("git"), "add", "policy.json", "policy.approval.json"], cwd=source, check=True)
            subprocess.run([
                shutil.which("git"), "-c", "user.name=Test Reviewer", "-c", "user.email=test@example.org",
                "commit", "-m", "test: approved policy",
            ], cwd=source, check=True, stdout=subprocess.DEVNULL)

            redis = FakeRedis()
            status = git_policy_status(config, redis)
            self.assertTrue(status["drift"])
            applied = sync_git_policy(config, redis, dry_run=False, confirmed=True)
            self.assertEqual(applied["change_count"], 1)
            self.assertEqual(json.loads(redis.get("grant_1"))["remote_user"], "support")
            self.assertFalse(git_policy_status(config, redis)["drift"])
            revisions = list_policy_snapshots(config)
            self.assertEqual(len(revisions), 1)
            rollback_policy(config, redis, revisions[0]["revision_id"], confirmed=True)
            self.assertIsNone(redis.get("grant_1"))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


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

    def test_termination_alert_delivery_and_risk_classification(self):
        redis = FakeRedis()
        record = mark_session_start(redis, "conn-2", {
            "username": "alice", "project": "vip-prod", "server_vip": True,
            "remote_user": "root", "sudo_mode": "sudo-i", "source_ip": "203.0.113.10",
        }, ttl=120)
        requested = request_session_termination(redis, "conn-2", {"username": "security.admin"}, "incident")
        self.assertTrue(requested["terminate_requested"])
        self.assertEqual(requested["terminate_requested_by"], "security.admin")
        self.assertEqual(redis.ttls["active_session_conn-2"], 120000)

        marked = mark_alert_delivery(redis, "conn-2", "vip_session", {
            "sent": [{"type": "telegram", "status": 200}], "errors": [],
        })
        self.assertTrue(marked["alert_deliveries"][0]["ok"])
        config = {"session_control": {"alerts": {
            "enabled": True, "vip": True, "privileged": True, "unusual_source": True,
            "trusted_source_cidrs": ["10.0.0.0/8"], "long_session_seconds": 60,
        }}}
        self.assertEqual(
            initial_session_alerts(config, record),
            ["vip_session", "privileged_session", "unusual_source_ip"],
        )
        record["started_at"] = 1
        self.assertEqual(long_session_alert(config, record, 62), "long_session")
        self.assertTrue(source_is_unusual("not-an-ip", ["10.0.0.0/8"]))

    def test_session_notification_contains_dashboard_link(self):
        notice = build_session_notification(
            {"dashboard": {"public_url": "https://bastion.example.org"}},
            "vip_session",
            {"connection_id": "conn-3", "username": "alice", "project": "prod"},
        )
        self.assertEqual(notice["payload"]["dashboard_url"], "https://bastion.example.org/session/conn-3")


class DashboardOperationsDataTest(unittest.TestCase):
    def _job_config(self, root):
        key_path = os.path.join(root, "job.key")
        with open(key_path, "wb") as key_f:
            key_f.write(b"x" * 64)
        return {
            "command_execution": {
                "signing_key_file": key_path,
                "jobs_path": os.path.join(root, "jobs"),
                "default_timeout": 60,
                "max_timeout": 900,
                "allowed_groups": ["DevOps"],
            },
            "runbooks": {
                "enabled": True,
                "max_fleet_hosts": 10,
                "read_only": {"allowed_groups": ["DevOps"], "allow_sudo": False, "require_confirmation": True},
                "operational": {"enabled": False, "allowed_groups": []},
            },
            "policy": {"fallback_remote_user": None},
            "ssh": {"default_sudo_mode": "none"},
            "logging": {"sinks": []},
        }

    def _seed_hosts_and_grant(self, redis):
        for host_id in ("1", "2"):
            redis.set("server_{}".format(host_id), json.dumps({
                "server_id": int(host_id), "project_name": "prod", "server_ip": "10.0.0.{}".format(host_id),
                "server_port": 22, "server_name": "node{}".format(host_id), "server_user": "support",
            }))
        redis.set("grant_1", json.dumps({
            "id": "1", "subject": "group", "name": "DevOps", "project": "prod",
            "remote_user": "support", "sudo_mode": "none", "allowed_actions": ["ssh", "runbook"],
        }))

    def test_fleet_progress_and_retry_replace_failed_attempt(self):
        root = os.path.join(ROOT, ".tmp-dashboard-jobs-{}".format(uuid.uuid4().hex))
        os.makedirs(root)
        try:
            redis = FakeRedis()
            self._seed_hosts_and_grant(redis)
            config = self._job_config(root)
            identity = {"username": "admin", "keycloak_sub": "sub", "groups": ["DevOps"], "roles": []}
            fleet = create_runbook_fleet(redis, config, identity, "uptime", ["1", "2"], confirmed=True)
            self.assertEqual(fleet["count"], 2)
            self.assertEqual(fleet["jobs"][0]["schema_version"], 2)
            self.assertTrue(verify_job_signature(fleet["jobs"][0], config))
            failed = fleet["jobs"][0]
            failed.update({"status": "failed", "finished_at": 100, "error": "network"})
            redis.set("job_{}".format(failed["id"]), json.dumps(failed))
            summary = fleet_progress(list_jobs(redis, limit=100))
            self.assertEqual(summary[0]["total"], 2)
            self.assertEqual(summary[0]["failed"], 1)

            retried = retry_job(redis, config, failed["id"], {"username": "security.admin"})
            self.assertEqual(retried["retry_of"], failed["id"])
            self.assertEqual(retried["attempt"], 2)
            summary = fleet_progress(list_jobs(redis, limit=100))[0]
            self.assertEqual(summary["total"], 2)
            self.assertEqual(summary["failed"], 0)
            self.assertEqual(summary["queued"], 2)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_alert_aggregation_and_state(self):
        redis = FakeRedis()
        redis.set("job_7", json.dumps({
            "id": "7", "status": "failed", "type": "runbook", "username": "alice",
            "project": "prod", "host_id": "1", "created_at": 10, "finished_at": 11, "error": "timeout",
        }))
        mark_session_start(redis, "conn-risk", {
            "username": "alice", "project": "prod", "host_id": "1", "server_vip": True,
            "remote_user": "root", "sudo_mode": "sudo-i", "source_ip": "203.0.113.8", "started_at": 1,
        })
        config = {"session_control": {"alerts": {
            "enabled": True, "vip": True, "privileged": True, "unusual_source": True,
            "trusted_source_cidrs": ["10.0.0.0/8"], "long_session_seconds": 60,
        }}}
        alerts = collect_alerts(redis, config, now=100)
        kinds = {row["kind"] for row in alerts}
        self.assertTrue({"failed_job", "vip_session", "privileged_session", "unusual_source_ip", "long_session"}.issubset(kinds))
        selected = next(row for row in alerts if row["kind"] == "failed_job")
        update_alert_state(redis, selected["id"], {"username": "admin"}, "acknowledge", "investigating", now=101)
        refreshed = next(row for row in collect_alerts(redis, config, now=102) if row["id"] == selected["id"])
        self.assertEqual(refreshed["status"], "acknowledged")
        self.assertEqual(refreshed["comments"][0]["text"], "investigating")

    def test_access_matrix_findings_and_preview(self):
        hosts = [{"server_id": 1, "project_name": "prod", "server_name": "web", "server_ip": "10.0.0.1"}]
        grants = [
            {"id": "1", "subject": "group", "name": "DevOps", "project": "prod", "remote_user": "support", "sudo_mode": "none", "allowed_actions": ["ssh"]},
            {"id": "2", "subject": "group", "name": "DevOps", "project": "prod", "remote_user": "root", "sudo_mode": "sudo-i", "allowed_actions": ["ssh"]},
        ]
        matrix = build_access_matrix(grants, {}, hosts, defaults={})
        self.assertEqual(matrix["rows"][0]["cells"]["prod"]["state"], "allowed")
        self.assertIn("conflict", {row["type"] for row in matrix["findings"]})
        preview = preview_grant_change([], {}, hosts, {
            "subject": "group", "name": "Support", "project": "prod", "remote_user": "support",
            "sudo_mode": "none", "allowed_actions": ["ssh"],
        })
        self.assertEqual(preview["counts"]["gained"], 1)


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

    def test_bulk_update_validates_all_hosts_before_writing(self):
        redis = FakeRedis()
        for host_id in ("1", "2"):
            redis.set("server_{}".format(host_id), json.dumps({
                "server_id": int(host_id), "project_name": "prod", "server_ip": "10.0.0.{}".format(host_id),
                "server_name": "node{}".format(host_id), "server_user": "support",
            }))
        updated = bulk_update_hosts(redis, ["1", "2"], {"server_services": "nginx"}, updated_by="admin")
        self.assertEqual(len(updated), 2)
        self.assertEqual(get_host(redis, "2")["server_services"], "nginx")
        before = redis.get("server_1")
        with self.assertRaises(HostValidationError):
            bulk_update_hosts(redis, ["1", "missing"], {"server_user": "dba"}, updated_by="admin")
        self.assertEqual(redis.get("server_1"), before)

    def test_host_optimistic_revision_rejects_stale_web_edit(self):
        redis = FakeRedis()
        redis.set("server_1", json.dumps({
            "server_id": 1, "project_name": "prod", "server_ip": "10.0.0.1",
            "server_name": "node1", "server_user": "support",
        }))
        revision = get_host(redis, "1")["_revision"]
        update_host(redis, "1", {"server_note": "new"}, updated_by="one")
        with self.assertRaises(HostValidationError):
            update_host(redis, "1", {"server_note": "stale"}, updated_by="two", expected_revision=revision)


class AccessPackageTest(unittest.TestCase):
    @staticmethod
    def package(remote_user="support", status="enabled"):
        return {
            "name": "Support Read-Only",
            "description": "Reusable support profile",
            "status": status,
            "access": [{
                "id": "prod-support",
                "project_set": "prod-apps",
                "remote_user": remote_user,
                "sudo_mode": "none",
                "allowed_actions": ["ssh", "runbook"],
            }],
            "lifecycle": {"default_ttl": "7d", "max_ttl": "30d", "permanent_allowed": True},
            "approval": {"required": True, "admin_groups": ["DevSecOps"], "ticket_required": True},
        }

    def test_assignment_materializes_grant_and_policy_resolves(self):
        redis = FakeRedis()
        redis.set("project_set_prod-apps", json.dumps({"name": "prod-apps", "projects": ["payments-prod"], "project_globs": []}))
        package = create_package(redis, self.package(), actor="admin", now=100)
        assignment, changes = assign_package(
            redis, package["name"], "group", "Support-L2", actor="admin", ttl="2h", ticket="CHG-1042", now=100,
        )

        self.assertEqual(changes["count"], 1)
        self.assertEqual(assignment["expires_at"], 7300)
        grants = load_grants(redis)
        generated = grants[0]
        self.assertEqual(generated["managed_by"], "access_package")
        self.assertEqual(generated["package_id"], package["id"])
        with mock.patch("isolate_policy.time.time", return_value=200):
            decision = resolve_grant(
                {"username": "demo.alex", "groups": ["Support-L2"], "roles": []},
                project="payments-prod", host={"server_id": "10703"}, grants=grants,
                project_sets=load_project_sets(redis), defaults={},
            )
        self.assertEqual(decision["remote_user"], "support")
        self.assertIn("runbook", decision["allowed_actions"])

    def test_preview_update_and_rollback_preserve_managed_grant_id(self):
        redis = FakeRedis()
        package = create_package(redis, self.package(), actor="admin", now=100)
        assignment, _ = assign_package(redis, package["id"], "group", "Support-L2", actor="admin", ticket="CHG-1", now=100)
        original_grant_id = assignment["grant_ids"][0]
        redis.set("grant_99", json.dumps({
            "subject": "user", "name": "manual.user", "project": "sandbox",
            "remote_user": "dev", "sudo_mode": "none", "allowed_actions": ["ssh"],
        }))

        preview = preview_package_update(redis, package["id"], self.package(remote_user="l2-support"), actor="admin", now=200)
        self.assertEqual(preview["grant_change_count"], 1)
        self.assertEqual(json.loads(redis.get("grant_{}".format(original_grant_id)))["remote_user"], "support")
        updated, _ = update_package(
            redis, package["id"], self.package(remote_user="l2-support"), actor="admin",
            expected_revision=1, now=200,
        )
        refreshed = list_assignments(redis, package=package["id"])[0]
        self.assertEqual(refreshed["grant_ids"], [original_grant_id])
        self.assertEqual(json.loads(redis.get("grant_{}".format(original_grant_id)))["remote_user"], "l2-support")
        self.assertIsNotNone(redis.get("grant_99"))

        rolled_back, _ = rollback_package(redis, package["id"], 1, actor="admin", expected_revision=2, now=300)
        self.assertEqual(rolled_back["revision"], 3)
        self.assertEqual(json.loads(redis.get("grant_{}".format(original_grant_id)))["remote_user"], "support")
        self.assertEqual([row["revision"] for row in list_package_revisions(redis, package["id"])] , [3, 2, 1])
        self.assertEqual(updated["revision"], 2)

    def test_unassign_and_package_validation(self):
        redis = FakeRedis()
        package = create_package(redis, self.package(), actor="admin", now=100)
        with self.assertRaises(AccessPackageError):
            assign_package(redis, package["id"], "group", "Support-L2", actor="admin", now=100)
        assignment, _ = assign_package(redis, package["id"], "group", "Support-L2", actor="admin", ticket="CHG-1", now=100)
        revoked, deleted = unassign_package(redis, assignment["id"], actor="admin", now=200)
        self.assertEqual(revoked["status"], "revoked")
        self.assertEqual(deleted, 1)
        self.assertEqual(load_grants(redis), [])
        with self.assertRaises(AccessPackageError):
            create_package(redis, self.package(), actor="admin")
        with self.assertRaises(AccessPackageError):
            list_assignments(redis, package="missing")

    def test_multi_approval_blocks_direct_assignment(self):
        redis = FakeRedis()
        payload = self.package()
        payload["approval"]["minimum_approvals"] = 2
        package = create_package(redis, payload, actor="admin")
        with self.assertRaises(AccessPackageError):
            assign_package(redis, package["id"], "group", "DBA", actor="admin", ticket="CHG-2")

    def test_gitops_prune_preserves_package_grants_and_referenced_sets(self):
        redis = FakeRedis()
        redis.set("project_set_prod-apps", json.dumps({"schema_version": 2, "name": "prod-apps", "projects": ["prod"], "project_globs": []}))
        package = create_package(redis, self.package(), actor="admin")
        assign_package(redis, package["id"], "group", "Support-L2", actor="admin", ticket="CHG-3")

        changes = plan_bundle(redis, {"schema_version": 2, "project_sets": [], "grants": []}, prune=True)

        self.assertEqual(changes["grant_remove"], [])
        self.assertEqual(changes["project_set_remove"], [])

    def test_assignment_conflict_is_rejected_before_grants_are_written(self):
        redis = FakeRedis()
        first = create_package(redis, self.package(), actor="admin")
        assign_package(redis, first["id"], "group", "Support-L2", actor="admin", ticket="CHG-4")
        second_payload = self.package(remote_user="dev")
        second_payload["name"] = "Conflicting Support"
        second = create_package(redis, second_payload, actor="admin")

        with self.assertRaises(AccessPackageError):
            assign_package(redis, second["id"], "group", "Support-L2", actor="admin", ticket="CHG-5")

        self.assertEqual(len(load_grants(redis)), 1)
        self.assertEqual(list_assignments(redis, package=second["id"]), [])


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

    def test_command_audit_environment_is_explicitly_allowlisted(self):
        argv = build_ssh_argv(
            {"binary": "/usr/bin/ssh", "config_path": "/tmp/ssh_config", "allowed_extra_args": []},
            {"hostname": "host.example.com", "user": "support", "port": 22},
            send_env=["ISOLATE_CONNECTION_ID", "ISOLATE_PROJECT"],
        )
        self.assertIn("SendEnv=ISOLATE_CONNECTION_ID ISOLATE_PROJECT", argv)
        with self.assertRaises(SSHArgumentError):
            build_ssh_argv(
                {"binary": "/usr/bin/ssh", "config_path": "/tmp/ssh_config", "allowed_extra_args": []},
                {"hostname": "host.example.com"}, send_env=["LD_PRELOAD"],
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
                        "server_name": "control-plane",
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
            self.assertEqual(rows[0]["server_name"], "control-plane")
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

    def test_merges_legacy_split_connection_events(self):
        tmpdir = os.path.join(ROOT, ".tmp-history-split-{}".format(uuid.uuid4().hex))
        try:
            self._write_session(tmpdir, "alice", "login-session", [{
                "ts": 100,
                "event": "policy_selected",
                "session_id": "login-session",
                "connection_id": "conn-split",
                "username": "alice",
                "groups": ["Support"],
                "project": "prod",
                "host_id": "10001",
                "target_host": "10.0.0.1",
                "remote_user": "support",
            }])
            self._write_session(tmpdir, "alice", "conn-split", [{
                "ts": 101,
                "event": "ssh_end",
                "session_id": "conn-split",
                "connection_id": "conn-split",
                "username": "alice",
                "exit_code": 0,
                "raw_log_path": os.path.join(tmpdir, "alice", "raw.log"),
            }])

            rows = read_history(tmpdir, {"username": "alice", "groups": []})

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["project"], "prod")
            self.assertEqual(rows[0]["result"], "exit=0")
            details = find_session(tmpdir, "conn-split")
            self.assertEqual([event["event"] for event in details["events"]], ["policy_selected", "ssh_end"])
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

    def test_command_audit_rejects_spoofed_session_context(self):
        tmpdir = os.path.join(ROOT, ".tmp-command-context-{}".format(uuid.uuid4().hex))
        try:
            self._write_session(tmpdir, "alice", "session-1", [{
                "event": "ssh_start", "connection_id": "conn-1", "session_id": "session-1",
                "username": "alice", "project": "prod", "host_id": "10001",
            }])
            with self.assertRaises(CommandAuditError):
                append_command_event(
                    tmpdir, "conn-1", "whoami", project="other", host_id="10001",
                    config={"command_audit": {"enabled": True}},
                )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_command_audit_cli_requires_active_or_recent_session(self):
        tmpdir = os.path.join(ROOT, ".tmp-command-active-{}".format(uuid.uuid4().hex))
        try:
            self._write_session(tmpdir, "alice", "session-1", [{
                "event": "ssh_start", "connection_id": "conn-1", "session_id": "session-1",
                "username": "alice", "project": "prod", "host_id": "10001",
            }])
            redis = FakeRedis()
            args = SimpleNamespace(
                connection_id="conn-1", command="whoami", cwd="/tmp", exit_code=0,
                project="prod", host_id="10001", shell="bash", source="target-shell-hook",
            )
            config = {"logging": {"base_path": tmpdir}, "command_audit": {
                "enabled": True, "require_active_session": True, "completion_grace_seconds": 30,
            }}
            with mock.patch.object(isolate, "redis_client", return_value=redis), mock.patch.object(
                isolate, "_effective_username", return_value="auth"
            ), redirect_stderr(StringIO()):
                self.assertEqual(isolate.cmd_command_log_append(args, config), 2)
            mark_session_start(redis, "conn-1", {"username": "alice"})
            with mock.patch.object(isolate, "redis_client", return_value=redis), mock.patch.object(
                isolate, "_effective_username", return_value="auth"
            ), redirect_stdout(StringIO()):
                self.assertIsNone(isolate.cmd_command_log_append(args, config))

            with mock.patch.object(isolate, "_effective_username", return_value="alice"), redirect_stderr(StringIO()):
                self.assertEqual(isolate.cmd_command_log_append(args, config), 2)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_session_rejects_raw_path_outside_user_log_directory(self):
        tmpdir = os.path.join(ROOT, ".tmp-unsafe-raw-{}".format(uuid.uuid4().hex))
        try:
            outside = os.path.join(tmpdir, "outside.log")
            os.makedirs(tmpdir)
            with open(outside, "w", encoding="utf-8") as raw_f:
                raw_f.write("1000.000000\nsecret")
            self._write_session(tmpdir, "alice", "session-1", [{
                "event": "ssh_end", "connection_id": "conn-1", "session_id": "session-1",
                "username": "alice", "raw_log_path": outside, "exit_code": 0,
            }])
            self.assertIsNone(find_session(tmpdir, "conn-1")["raw_log_path"])
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


class OperationsConvenienceFeaturesTest(unittest.TestCase):
    def test_maintenance_is_compatible_and_expires_automatically(self):
        redis = FakeRedis()
        redis.set("server_10001", json.dumps({
            "server_id": 10001, "project_name": "prod", "server_name": "api",
            "server_ip": "192.0.2.10", "server_user": "support",
        }))
        legacy = get_host(redis, "10001")
        self.assertFalse(legacy["maintenance_active"])
        updated = update_host(redis, "10001", {
            "maintenance_enabled": True, "maintenance_until": 4102444800, "maintenance_reason": "CHG-100",
        }, updated_by="admin")
        self.assertTrue(is_host_in_maintenance(updated, now=1000))
        self.assertFalse(is_host_in_maintenance(updated, now=4102444801))
        self.assertEqual(updated["maintenance_marker"], "MAINT")

    def test_announcements_are_scoped_active_and_removable(self):
        redis = FakeRedis()
        global_notice = create_announcement(redis, "Global notice", "admin", expires_at=2000)
        project_notice = create_announcement(redis, "Payments maintenance", "admin", project="payments", severity="warning", expires_at=2000)
        create_announcement(redis, "Other project", "admin", project="search", expires_at=2000)
        rows = list_announcements(redis, project="payments", host="10001", active_only=True, now=1000)
        self.assertEqual({row["id"] for row in rows}, {global_notice["id"], project_notice["id"]})
        self.assertEqual(delete_announcement(redis, project_notice["id"])["deleted"], True)
        with self.assertRaises(AnnouncementError):
            create_announcement(redis, "", "admin")

    def test_connectivity_check_is_non_interactive_and_cached(self):
        redis = FakeRedis()
        connection = SimpleNamespace(close=lambda: None)
        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        host = {"server_id": "10001", "project_name": "prod", "server_name": "api", "server_ip": "192.0.2.10", "server_port": 22, "server_user": "support"}
        runner = mock.Mock(return_value=completed)
        result = check_host(
            host, {"ssh": {"binary": "/usr/bin/ssh"}}, timeout=2, ssh_auth=True,
            connector=mock.Mock(return_value=connection),
            resolver=mock.Mock(return_value=[(None, None, None, None, ("192.0.2.10", 22))]), runner=runner,
        )
        self.assertTrue(result["ok"])
        argv = runner.call_args.args[0]
        self.assertIn("BatchMode=yes", argv)
        self.assertEqual(argv[-2:], ["support@192.0.2.10", "true"])
        save_check(redis, result, ttl=600)
        self.assertEqual(get_last_check(redis, "10001")["ssh"], "ok")

    def test_json_csv_and_matrix_exports_preserve_structured_values(self):
        rows = [{"id": "1", "groups": ["DevOps", "DBA"], "note": "hello,world"}]
        csv_text, csv_type = render_export(rows, "csv")
        json_text, json_type = render_export(rows, "json")
        self.assertEqual(csv_type, "text/csv")
        self.assertIn('"[""DevOps"", ""DBA""]"', csv_text)
        self.assertIn("hello,world", csv_text)
        self.assertEqual(json_type, "application/json")
        self.assertEqual(json.loads(json_text)[0]["groups"], ["DevOps", "DBA"])
        flat = flatten_access_matrix({
            "projects": ["prod"],
            "rows": [{"subject": "group", "name": "DevOps", "cells": {"prod": {"state": "allowed", "allowed_hosts": 1, "total_hosts": 1, "remote_users": ["support"], "sudo_modes": ["none"], "actions": ["ssh"]}}}],
        })
        self.assertEqual(flat[0]["remote_users"], ["support"])

    def test_user_activity_summary_joins_audit_and_access_data(self):
        tmpdir = tempfile.mkdtemp(prefix="isolate-activity-")
        try:
            session_dir = os.path.join(tmpdir, "demo.alex", "session-1")
            os.makedirs(session_dir)
            events = [
                {"event": "policy_selected", "ts": 1000, "username": "demo.alex", "groups": ["DevOps"], "project": "prod", "host_id": "10001", "connection_id": "conn-1"},
                {"event": "ssh_end", "ts": 1001, "username": "demo.alex", "project": "prod", "host_id": "10001", "connection_id": "conn-1", "exit_code": 1},
            ]
            with open(os.path.join(session_dir, "session.jsonl"), "w", encoding="utf-8") as output:
                for event in events:
                    output.write(json.dumps(event) + "\n")
            result = user_activity_summary(
                tmpdir, "demo.alex", active_sessions=[{"username": "demo.alex"}],
                grants=[{"subject": "group", "name": "DevOps"}], access_requests=[{"requester": "demo.alex", "created_at": 1}],
            )
            self.assertEqual(result["metrics"]["connections"], 1)
            self.assertEqual(result["metrics"]["recent_failures"], 1)
            self.assertEqual(result["metrics"]["active_sessions"], 1)
            self.assertEqual(result["top_projects"][0]["project"], "prod")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class DashboardTest(unittest.TestCase):
    def test_dashboard_admin_check(self):
        config = {"dashboard": {"admin_groups": ["DevOps"]}}
        self.assertTrue(is_dashboard_admin({"groups": ["DevOps"]}, config))
        self.assertFalse(is_dashboard_admin({"groups": ["DBA"]}, config))

    def test_dashboard_packages_documentation_locales_and_build_info(self):
        try:
            app = isolate_web.create_app({
                "schema_version": 2,
                "data_root": ROOT,
                "build": {"version": "2.1.0-test", "revision": "abcdef1234567890", "built_at": "2026-09-10T10:00:00Z"},
                "dashboard": {"admin_groups": ["DevOps"], "public_url": "http://bastion.example.org", "default_locale": "en"},
                "access_packages": {"enabled": True, "max_rules": 50, "max_assignments_per_operation": 100},
                "keycloak": {"issuer": "http://keycloak", "client_id": "isolate"},
                "logging": {"base_path": "/tmp/no-history", "sinks": []},
            })
        except ImportError as exc:
            self.skipTest(str(exc))
        redis = FakeRedis()
        app.config["TESTING"] = True
        with mock.patch.object(isolate_web, "redis_client", return_value=redis):
            client = app.test_client()
            with client.session_transaction() as sess:
                sess["identity"] = {"username": "admin", "groups": ["DevOps"]}
                sess["csrf_token"] = "csrf"
            response = client.post("/packages", data={
                "csrf_token": "csrf", "action": "create", "confirm": "true",
                "name": "Support Read-Only", "description": "Demo profile", "status": "enabled",
                "access_json": json.dumps([{
                    "id": "prod", "project": "payments-prod", "remote_user": "support",
                    "sudo_mode": "none", "allowed_actions": ["ssh"],
                }]),
                "default_ttl": "7d", "max_ttl": "30d", "permanent_allowed": "true",
                "minimum_approvals": "1",
            })
            self.assertEqual(response.status_code, 200)
            self.assertIn("Support Read-Only", response.get_data(as_text=True))
            self.assertIsNotNone(get_package(redis, "Support Read-Only"))

            russian = client.get("/docs?lang=ru")
            self.assertEqual(russian.status_code, 200)
            russian_text = russian.get_data(as_text=True)
            self.assertIn('<html lang="ru">', russian_text)
            self.assertIn("Документация Isolate", russian_text)
            self.assertIn("Пакеты доступа", russian_text)
            self.assertIn("2.1.0-test", russian_text)
            self.assertIn("abcdef123456", russian_text)
            self.assertIn('class="locale-switch"', russian_text)

            access = client.get("/access")
            self.assertIn("Об этой странице", access.get_data(as_text=True))
            english = client.get("/docs?lang=en")
            self.assertIn("Access packages", english.get_data(as_text=True))

    def test_build_info_prefers_release_environment(self):
        with mock.patch.dict(os.environ, {
            "ISOLATE_VERSION": "2.1.5", "ISOLATE_BUILD_SHA": "1234567890abcdef",
            "ISOLATE_BUILD_DATE": "2026-09-10T12:00:00Z",
        }):
            info = get_build_info({"schema_version": 2, "data_root": ROOT}, started_at=0.1)
        self.assertEqual(info["version"], "2.1.5")
        self.assertEqual(info["revision_short"], "1234567890ab")
        self.assertEqual(info["built_at"], "2026-09-10T12:00:00Z")

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
            ticket="INC-1",
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
        self.assertIn('class="theme-switch"', text)
        self.assertIn('data-theme-choice="dark"', text)
        self.assertIn("About this page", text)
        self.assertIn("Review temporary access requests", text)
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

    def test_history_enriches_legacy_rows_with_inventory_host_name(self):
        tmpdir = os.path.join(ROOT, ".tmp-dashboard-history-{}".format(uuid.uuid4().hex))
        try:
            session_dir = os.path.join(tmpdir, "admin", "session-history")
            os.makedirs(session_dir)
            with open(os.path.join(session_dir, "session.jsonl"), "w", encoding="utf-8") as session_f:
                session_f.write(json.dumps({
                    "event": "policy_selected", "ts": 10.0, "username": "admin",
                    "project": "prod", "host_id": "10007", "target_host": "10.0.0.7",
                    "remote_user": "support", "connection_id": "conn-history",
                    "session_id": "session-history",
                }) + "\n")
            redis = FakeRedis()
            redis.set("server_10007", json.dumps({
                "server_id": "10007", "project_name": "prod", "server_ip": "10.0.0.7",
                "server_name": "api-primary", "server_user": "support",
            }))
            try:
                app = isolate_web.create_app({
                    "dashboard": {"admin_groups": ["DevOps"], "public_url": "http://bastion.example.org"},
                    "keycloak": {"issuer": "http://keycloak", "client_id": "isolate"},
                    "logging": {"base_path": tmpdir},
                })
            except ImportError as exc:
                self.skipTest(str(exc))
            app.config["TESTING"] = True
            with mock.patch.object(isolate_web, "redis_client", return_value=redis):
                client = app.test_client()
                with client.session_transaction() as sess:
                    sess["identity"] = {"username": "admin", "groups": ["DevOps"]}
                response = client.get("/history")

            self.assertEqual(response.status_code, 200)
            text = response.get_data(as_text=True)
            self.assertIn("api-primary", text)
            self.assertIn("host name", text)
            self.assertIn("Search audited SSH connections", text)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

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
            self.assertIn('/static/vendor/xterm/xterm.mjs', replay_text)
            static_response = client.get('/static/vendor/xterm/xterm.mjs')
            self.assertEqual(static_response.status_code, 200)
            static_response.close()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_live_session_and_admin_termination(self):
        tmpdir = os.path.join(ROOT, ".tmp-dashboard-live-{}".format(uuid.uuid4().hex))
        raw_path = os.path.join(tmpdir, "alice", "session-1", "raw.log")
        try:
            try:
                app = isolate_web.create_app({
                    "dashboard": {"admin_groups": ["DevOps"], "public_url": "http://bastion.example.org"},
                    "session_control": {"enabled": True, "terminate_enabled": True, "live_tail_bytes": 4096},
                    "access": {"default_ttl": "2h", "max_ttl": "24h"},
                    "keycloak": {"issuer": "http://keycloak", "client_id": "isolate"},
                    "logging": {"base_path": tmpdir},
                })
            except ImportError as exc:
                self.skipTest(str(exc))
            os.makedirs(os.path.dirname(raw_path))
            with open(raw_path, "w", encoding="utf-8") as raw_f:
                raw_f.write("1000.000000\n\033[31mactive\033[0m\n")
            with open(os.path.join(os.path.dirname(raw_path), "session.jsonl"), "w", encoding="utf-8") as session_f:
                session_f.write(json.dumps({
                    "event": "ssh_start", "username": "alice", "connection_id": "conn-live",
                    "session_id": "session-1", "project": "prod", "host_id": "1", "raw_log_path": raw_path,
                }) + "\n")
            redis = FakeRedis()
            mark_session_start(redis, "conn-live", {"username": "alice", "project": "prod", "raw_log_path": raw_path})
            app.config["TESTING"] = True
            with mock.patch.object(isolate_web, "redis_client", return_value=redis):
                client = app.test_client()
                with client.session_transaction() as sess:
                    sess["identity"] = {"username": "admin", "groups": ["DevOps"]}
                    sess["csrf_token"] = "csrf"
                live = client.get("/session/conn-live/live.json")
                self.assertTrue(live.get_json()["active"])
                self.assertIn("active", live.get_json()["plain"])
                page = client.get("/session/conn-live/live").get_data(as_text=True)
                self.assertIn("xterm.mjs", page)
                response = client.post("/sessions/conn-live/terminate", data={
                    "csrf_token": "csrf", "confirm": "true", "reason": "security incident",
                })
            self.assertEqual(response.status_code, 302)
            self.assertTrue(get_session(redis, "conn-live")["terminate_requested"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_dashboard_inventory_policy_bulk_and_simulator(self):
        tmpdir = os.path.join(ROOT, ".tmp-dashboard-admin-{}".format(uuid.uuid4().hex))
        os.makedirs(tmpdir)
        try:
            try:
                app = isolate_web.create_app({
                    "dashboard": {"admin_groups": ["DevOps"], "public_url": "http://bastion.example.org"},
                    "access": {"default_ttl": "2h", "max_ttl": "24h"},
                    "keycloak": {"issuer": "http://keycloak", "client_id": "isolate"},
                    "logging": {"base_path": tmpdir},
                    "policy": {"fallback_remote_user": None}, "ssh": {},
                    "policy_as_code": {"enforce_git": False, "backup_dir": tmpdir},
                })
            except ImportError as exc:
                self.skipTest(str(exc))
            redis = FakeRedis()
            app.config["TESTING"] = True
            with mock.patch.object(isolate_web, "redis_client", return_value=redis), mock.patch.object(isolate_web, "save_policy_snapshot", return_value={}):
                client = app.test_client()
                with client.session_transaction() as sess:
                    sess["identity"] = {"username": "admin", "groups": ["DevOps"]}
                    sess["csrf_token"] = "csrf"
                inventory = client.post("/inventory", data={
                    "csrf_token": "csrf", "confirm": "true", "action": "add", "project": "prod",
                    "name": "web01", "ip": "10.0.0.1", "port": "22", "user": "support",
                })
                self.assertEqual(inventory.status_code, 200)
                host_id = list_hosts(redis)[0]["server_id"]
                grant = client.post("/grants", data={
                    "csrf_token": "csrf", "confirm": "true", "action": "grant_save",
                    "subject": "group", "name": "DevOps", "selector_type": "project",
                    "selector_value": "prod", "remote_user": "support", "sudo_mode": "none",
                    "allowed_actions": "ssh",
                })
                self.assertEqual(grant.status_code, 200)
                simulator = client.get("/policy/simulate?groups=DevOps&project=prod&host={}".format(host_id))
            self.assertIn("ALLOWED", simulator.get_data(as_text=True))
            self.assertEqual(len(list_grant_records(redis)), 1)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_jobs_alerts_and_access_matrix_pages(self):
        tmpdir = os.path.join(ROOT, ".tmp-dashboard-operations-{}".format(uuid.uuid4().hex))
        os.makedirs(tmpdir)
        try:
            try:
                app = isolate_web.create_app({
                    "dashboard": {"admin_groups": ["DevOps"], "public_url": "http://bastion.example.org"},
                    "session_control": {"alerts": {"enabled": True, "long_session_seconds": 60}},
                    "access": {"default_ttl": "2h", "max_ttl": "24h"},
                    "keycloak": {"issuer": "http://keycloak", "client_id": "isolate"},
                    "logging": {"base_path": tmpdir},
                    "policy": {"fallback_remote_user": None}, "ssh": {},
                    "runbooks": {"enabled": False},
                    "command_execution": {"jobs_path": os.path.join(tmpdir, "jobs")},
                })
            except ImportError as exc:
                self.skipTest(str(exc))
            redis = FakeRedis()
            redis.set("server_1", json.dumps({
                "server_id": 1, "project_name": "prod", "server_ip": "10.0.0.1",
                "server_name": "web", "server_user": "support",
            }))
            redis.set("grant_1", json.dumps({
                "subject": "group", "name": "DevOps", "project": "prod", "remote_user": "support",
                "sudo_mode": "none", "allowed_actions": ["ssh"],
            }))
            redis.set("job_7", json.dumps({
                "id": "7", "status": "failed", "type": "runbook", "runbook_id": "uptime",
                "username": "alice", "project": "prod", "host_id": "1", "created_at": 10,
                "finished_at": 11, "error": "network",
            }))
            app.config["TESTING"] = True
            with mock.patch.object(isolate_web, "redis_client", return_value=redis):
                client = app.test_client()
                with client.session_transaction() as sess:
                    sess["identity"] = {"username": "admin", "groups": ["DevOps"]}
                    sess["csrf_token"] = "csrf"
                jobs = client.get("/jobs")
                job_details = client.get("/job/7")
                alerts = client.get("/alerts")
                matrix = client.get("/policy/matrix")
                alert_id = collect_alerts(redis, app.config.get("ISOLATE_CONFIG", {
                    "session_control": {"alerts": {"enabled": True, "long_session_seconds": 60}}
                }))[0]["id"]
                acknowledge = client.post("/alerts", data={
                    "csrf_token": "csrf", "confirm": "true", "alert_id": alert_id,
                    "action": "acknowledge", "comment": "investigating",
                })
                preview = client.post("/policy/matrix", data={
                    "csrf_token": "csrf", "subject": "group", "name": "Support",
                    "selector_type": "project", "selector_value": "prod", "remote_user": "support",
                    "sudo_mode": "none", "allowed_actions": "ssh",
                })

            self.assertEqual(jobs.status_code, 200)
            self.assertIn("Jobs &amp; Runbooks", jobs.get_data(as_text=True))
            self.assertIn("network", job_details.get_data(as_text=True))
            self.assertEqual(alerts.status_code, 200)
            self.assertIn("Failed job 7", alerts.get_data(as_text=True))
            self.assertEqual(acknowledge.status_code, 200)
            self.assertIn("acknowledged", acknowledge.get_data(as_text=True))
            self.assertEqual(matrix.status_code, 200)
            self.assertIn("Access Matrix", matrix.get_data(as_text=True))
            self.assertIn("group:DevOps", matrix.get_data(as_text=True))
            self.assertIn("Blast radius preview", preview.get_data(as_text=True))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


    def test_dashboard_announcements_exports_and_maintenance_inventory(self):
        try:
            app = isolate_web.create_app({
                "dashboard": {"admin_groups": ["DevOps"], "public_url": "http://bastion.example.org"},
                "access": {"admin_groups": ["DevOps"]},
                "announcements": {"enabled": True, "max_active": 10},
                "connectivity": {"default_timeout": 1, "result_ttl": 600},
                "keycloak": {"issuer": "http://keycloak", "client_id": "isolate"},
                "logging": {"base_path": "/tmp/no-history"},
            })
        except ImportError as exc:
            self.skipTest(str(exc))
        redis = FakeRedis()
        redis.set("server_10001", json.dumps({
            "server_id": 10001, "project_name": "prod", "server_name": "api", "server_ip": "192.0.2.10",
            "server_port": 22, "server_user": "support", "maintenance_enabled": True,
            "maintenance_until": 4102444800, "maintenance_reason": "CHG-100",
        }))
        app.config["TESTING"] = True
        with mock.patch.object(isolate_web, "redis_client", return_value=redis):
            client = app.test_client()
            with client.session_transaction() as sess:
                sess["identity"] = {"username": "admin", "groups": ["DevOps"]}
                sess["csrf_token"] = "csrf"
            created = client.post("/announcements", data={
                "csrf_token": "csrf", "action": "add", "confirm": "true", "text": "Deploy window",
                "project": "prod", "severity": "warning", "ttl": "2h",
            })
            inventory = client.get("/inventory")
            csv_export = client.get("/export/inventory?format=csv")
            json_export = client.get("/export/inventory?format=json")
        self.assertEqual(created.status_code, 200)
        self.assertIn("Deploy window", created.get_data(as_text=True))
        self.assertIn("MAINT", inventory.get_data(as_text=True))
        self.assertIn("CHG-100", inventory.get_data(as_text=True))
        self.assertEqual(csv_export.status_code, 200)
        self.assertIn("attachment; filename=isolate-inventory.csv", csv_export.headers["Content-Disposition"])
        self.assertEqual(json.loads(json_export.get_data(as_text=True))[0]["server_id"], "10001")


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
