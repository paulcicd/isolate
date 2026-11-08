"""State routing, CAS/ABA, domain transactions and explicit migration tests."""

import base64
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))

import fakeredis
from redis.exceptions import DataError, WatchError
from isolate_access import (AccessDenied, approve_access_request, create_access_request,
                            revoke_access_request)
from isolate_config import DEFAULT_CONFIG
from isolate_session_approvals import (SessionApprovalDenied, consume_session_approval,
    decide_session_approval, request_session_approval)
from isolate_sessions import mark_session_start, request_session_termination, touch_session
from isolate_state import (AUTHORITY_KEY, FREEZE_KEY, LegacyGuard, MixedStateTransaction,
    SQLState, StateClient, StateError, StateFrozen, StateUnavailable, is_durable_key)
from isolate_state_migration import (MigrationError, SNAPSHOT_LUA, activate_restored,
    cutover, export_snapshot, freeze_source, import_source, plan_migration,
    restore_snapshot, verify_migration, write_snapshot)
from isolate_worker_ownership import claim_job, claim_key, owner_token


class SourceRedis(fakeredis.FakeRedis):
    """Only the maintenance snapshot's wire reply is simulated in unit tests.

    Real EVAL/PEXPIRETIME and concurrent PostgreSQL behavior are exercised by the
    isolated tests/integration/state suite, not claimed by this fake.
    """
    def eval(self, script, count, *args):
        if script != SNAPSHOT_LUA:
            return super().eval(script, count, *args)
        seconds, micros = self.time()
        result = [seconds, micros]
        for key in self.keys():
            kind = self.type(key)
            value = self.get(key) if kind == b"string" else b""
            result.extend((key, kind, value, self.pexpiretime(key)))
        return result


class StateTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = os.path.join(self.directory.name, "state.sqlite3")
        self.options = {"backend": "sqlite", "sqlite_path": self.path}
        self.redis = SourceRedis()
        self.state = SQLState(self.options)
        self.state.initialize()
        self.client = StateClient(self.redis, self.options)

    def test_durable_default_and_ephemeral_allowlist_do_not_read_stale_redis(self):
        durable = ("server_10001", "grant_1", "policy_1", "ssh_config_1", "identity_revocation_abc",
            "isolate_ticket_abc", "job_1", "job_lock_1", "job_execution_claim_1", "offset_job_id",
            "delegated_identity_abc", "recording_session_abc", "session_termination_abc", "future_policy_kind")
        for key in durable:
            with self.subTest(key=key):
                self.assertTrue(is_durable_key(key))
                self.redis.set(key, "stale")
                self.assertIsNone(self.client.get(key))
                self.client.set(key, "SQL")
                self.assertEqual(self.client.get(key), b"SQL")
                self.assertEqual(self.redis.get(key), b"stale")
        for key in ("active_session_abc", "isolate_node_1", "isolate_session_owner_1", "host_check_1", "cache_admission_1", "complete_hosts_prod", "projects_list"):
            self.assertFalse(is_durable_key(key))
            self.client.set(key, "ephemeral")
            self.assertEqual(self.redis.get(key), b"ephemeral")
            self.assertIsNone(self.state.get(key))
        self.assertIn(b"projects_list", self.client.keys("projects_*"))

    def test_atomic_counter_nx_and_single_consumer_across_clients(self):
        def contender(index):
            client = StateClient(self.redis, self.options)
            value = client.incr("offset_job_id")
            won = bool(client.set("isolate_ticket_one", str(index), nx=True, ex=10))
            return value, won
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(contender, range(24)))
        self.assertEqual(sorted(row[0] for row in results), list(range(1, 25)))
        self.assertEqual(sum(row[1] for row in results), 1)
        with ThreadPoolExecutor(max_workers=8) as pool:
            values = list(pool.map(lambda _: StateClient(self.redis, self.options).getdel("isolate_ticket_one"), range(24)))
        self.assertEqual(sum(value is not None for value in values), 1)

    def test_watch_detects_value_aba_and_absent_delete_recreate(self):
        self.client.set("grant_1", "A")
        with self.client.pipeline() as pipe:
            pipe.watch("grant_1")
            self.assertEqual(pipe.get("grant_1"), b"A")
            self.client.set("grant_1", "B")
            self.client.set("grant_1", "A")
            pipe.multi()
            pipe.set("grant_1", "unsafe")
            with self.assertRaises(WatchError):
                pipe.execute()
        with self.client.pipeline() as pipe:
            pipe.watch("grant_missing")
            self.client.set("grant_missing", "once")
            self.client.delete("grant_missing")
            pipe.multi()
            pipe.set("grant_missing", "unsafe")
            with self.assertRaises(WatchError):
                pipe.execute()

    def test_expiry_is_part_of_cas_and_does_not_extend_on_increment(self):
        # Advance the repository clock explicitly: fsync or a loaded CI runner
        # must not consume the test's TTL before the invariant can be asserted.
        with mock.patch.object(self.client.state, "_now", return_value=1000.0) as clock:
            self.client.set("identity_revocation_ttl", "1", px=1000)
            self.assertEqual(self.client.pttl("identity_revocation_ttl"), 1000)
            clock.return_value = 1000.1
            self.client.incr("identity_revocation_ttl")
            remaining = self.client.pttl("identity_revocation_ttl")
            self.assertGreater(remaining, 0)
            self.assertLessEqual(remaining, 900)
            with self.client.pipeline() as pipe:
                pipe.watch("identity_revocation_ttl")
                clock.return_value = 1002.0
                pipe.multi()
                pipe.set("grant_after_expiry", "unsafe")
                with self.assertRaises(WatchError):
                    pipe.execute()
            self.assertEqual(self.client.pttl("identity_revocation_ttl"), -2)
            self.assertTrue(self.client.set("identity_revocation_ttl", "new", nx=True))
            self.assertEqual(self.client.pttl("identity_revocation_ttl"), -1)

    def test_multi_key_failure_rolls_back_and_mixed_backend_transaction_is_rejected(self):
        self.client.set("offset_invalid", "not an integer")
        with self.client.pipeline() as pipe:
            pipe.set("grant_1", "must roll back")
            pipe.incr("offset_invalid")
            with self.assertRaises(DataError):
                pipe.execute()
        self.assertIsNone(self.client.get("grant_1"))
        with self.client.pipeline() as pipe:
            pipe.watch("grant_1")
            pipe.multi()
            pipe.set("grant_1", "must not write")
            with self.assertRaises(MixedStateTransaction):
                pipe.set("active_session_one", "also forbidden")
        self.assertIsNone(self.client.get("grant_1"))
        with self.assertRaises(MixedStateTransaction):
            self.client.delete("grant_1", "active_session_one")

    def test_no_schema_creation_no_sql_fallback_and_raw_backup_is_rejected(self):
        other = SQLState({"backend": "sqlite", "sqlite_path": os.path.join(self.directory.name, "missing.db")})
        with self.assertRaises(StateUnavailable):
            other.get("grant_1")
        self.assertFalse(os.path.exists(other.options["sqlite_path"]))
        self.redis.set("grant_1", "stale allow")
        with mock.patch.object(self.state, "connection", side_effect=StateUnavailable("offline")):
            self.client.state = self.state
            with self.assertRaises(StateUnavailable):
                self.client.get("grant_1")
        with self.assertRaises(StateError):
            self.client.dump("grant_1")

    def test_ephemeral_watch_pipeline_preserves_registry_termination(self):
        mark_session_start(self.client, "one", {"username": "alice"})
        request_session_termination(self.client, "one", {"username": "admin"})
        touch_session(self.client, "one")
        self.assertTrue(json.loads(self.redis.get("active_session_one"))["terminate_requested"])

    def test_existing_access_decision_and_grant_revoke_are_atomic_in_sql(self):
        person = {"username": "alice", "keycloak_sub": "stable-alice"}
        request = create_access_request(self.client, person, "prod", remote_user="support", reason="incident")
        record, grant = approve_access_request(self.client, request["id"], {"username": "admin"}, 600)
        self.assertEqual(record["status"], "approved")
        self.assertEqual(json.loads(self.client.get("grant_" + record["grant_id"])), grant)
        revoke_access_request(self.client, request["id"], {"username": "admin", "groups": ["Admins"]}, admin_groups=["Admins"])
        self.assertIsNone(self.client.get("grant_" + record["grant_id"]))
        self.assertEqual(json.loads(self.client.get("access_request_" + request["id"]))["status"], "revoked")
        self.assertIsNone(self.redis.get("grant_" + record["grant_id"]))

    def test_real_session_approval_is_consumed_once_under_concurrency(self):
        config = {"dashboard": {"admin_groups": ["Admins"]},
                  "session_approval": {"enabled": True, "required_projects": ["prod"]}}
        person = {"username": "alice", "keycloak_sub": "stable-alice", "exp": int(time.time()) + 600}
        host = {"server_id": "10001", "project_name": "prod", "server_ip": "192.0.2.1"}
        decision = {"remote_user": "support", "sudo_mode": "none", "matched_rule": {"id": "1"}}
        request = request_session_approval(self.client, config, person, host, decision, "connection-one")
        decide_session_approval(self.client, config, request["id"], {"username": "admin", "keycloak_sub": "admin-sub", "groups": ["Admins"]})
        def consume(_):
            try:
                return consume_session_approval(StateClient(self.redis, self.options), config,
                    request["id"], person, host, decision, "connection-one")["status"]
            except SessionApprovalDenied:
                return "denied"
        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(consume, range(12)))
        self.assertEqual(statuses.count("active"), 1)

    def test_job_lock_claim_and_permanent_execution_marker_share_sql_transaction(self):
        owner = owner_token()
        self.client.set("job_1", json.dumps({"id": "1", "status": "queued"}))
        self.client.set("job_lock_1", owner, nx=True, ex=600)
        result = claim_job(self.client, "1", owner)
        self.assertEqual(result["status"], "claimed")
        self.assertIsNotNone(self.client.get(claim_key("1")))
        self.assertIsNone(self.redis.get("job_lock_1"))
        self.assertIsNone(claim_job(self.client, "1", owner))


class MigrationTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = SourceRedis()
        self.source.set("server_10001", '{"server_id":10001}')
        self.source.set("offset_server_id", "10001")
        self.source.set("grant_1", '{"remote_user":"support"}')
        self.source.set("offset_grant_id", "1")
        self.source.set("identity_revocation_dead", "123", ex=300)
        self.source.set("isolate_ticket_old", "must not migrate", ex=60)
        self.source.set("active_session_old", "ephemeral")
        self.target = SQLState({"backend": "sqlite", "sqlite_path": os.path.join(self.directory.name, "state.db")})
        self.target.initialize(active=False)

    def test_dry_run_freeze_import_idempotency_checksum_cutover_and_legacy_fencing(self):
        plan = plan_migration(self.source, self.target)
        self.assertTrue(plan["dry_run"])
        self.assertIsNone(self.source.get(FREEZE_KEY))
        with self.assertRaises(MigrationError):
            freeze_source(self.source, "operator")
        freeze_source(self.source, "operator", external_fence=True)
        legacy = LegacyGuard(self.source)
        with self.assertRaises(StateFrozen):
            legacy.get("grant_1")
        with self.assertRaises(StateFrozen):
            legacy.set("grant_1", "bad")
        legacy.set("cache_health", "okay")
        first = import_source(self.source, self.target, external_fence=True)
        self.assertTrue(first["imported"])
        self.assertTrue(import_source(self.source, self.target, external_fence=True)["idempotent"])
        self.assertTrue(verify_migration(self.source, self.target)["verified"])
        with self.assertRaises(StateFrozen):
            self.target.get("grant_1")
        result = cutover(self.source, self.target, "operator", external_fence=True)
        self.assertTrue(result["active"])
        self.assertEqual(self.target.get("grant_1"), b'{"remote_user":"support"}')
        self.assertIsNone(self.target.get("isolate_ticket_old"))
        self.assertIsNotNone(self.source.get(AUTHORITY_KEY))
        self.assertEqual(len(self.target.get("isolate_authority_epoch")), 64)
        self.assertTrue(cutover(self.source, self.target, "operator", external_fence=True)["idempotent"])
        with self.assertRaises(MigrationError):
            import_source(self.source, self.target, external_fence=True)

    def test_changed_source_counter_mismatch_and_sql_tampering_prevent_cutover(self):
        self.source.set("offset_grant_id", "0")
        with self.assertRaises(MigrationError):
            plan_migration(self.source)
        self.source.set("offset_grant_id", "1")
        freeze_source(self.source, "operator", external_fence=True)
        import_source(self.source, self.target, external_fence=True)
        # A direct/pre-upgrade writer is deliberately simulated. The freeze
        # marker cannot stop it; checksum verification must catch the drift.
        self.source.set("grant_1", "changed by old writer")
        with self.assertRaises(MigrationError):
            cutover(self.source, self.target, "operator", external_fence=True)
        self.assertNotEqual(self.target.metadata()["status"], "active")

    def test_sql_snapshot_restores_tombstones_expiry_and_requires_epoch_rotation_activation(self):
        fresh = SQLState({"backend": "sqlite", "sqlite_path": os.path.join(self.directory.name, "live.db")})
        fresh.initialize()
        fresh.set("grant_1", "allow")
        fresh.delete("grant_1")
        fresh.set("identity_revocation_1", "cutoff", ex=300)
        fresh.set("isolate_authority_epoch", "a" * 64)
        output = os.path.join(self.directory.name, "state-backup.json")
        write_snapshot(fresh, output)
        restore_snapshot(self.target, output, external_fence=True)
        self.assertEqual(self.target.metadata()["status"], "restored")
        with self.assertRaises(StateFrozen):
            self.target.get("identity_revocation_1")
        activate_restored(self.target, "operator", "reconciled unknown remote outcomes", external_fence=True)
        self.assertEqual(self.target.get("identity_revocation_1"), b"cutoff")
        self.assertIsNone(self.target.get("grant_1"))
        self.assertNotEqual(self.target.get("isolate_authority_epoch"), b"a" * 64)
        self.assertEqual(export_snapshot(fresh)["records"][0]["revision"], 2)
        with open(output, encoding="utf-8") as source:
            payload = json.load(source)
        payload["records"][0]["value_b64"] = base64.b64encode(b"tampered").decode()
        bad = os.path.join(self.directory.name, "bad.json")
        with open(bad, "w", encoding="utf-8") as target:
            json.dump(payload, target)
        other = SQLState({"backend": "sqlite", "sqlite_path": os.path.join(self.directory.name, "other.db")})
        other.initialize(active=False)
        with self.assertRaises(MigrationError):
            restore_snapshot(other, bad, external_fence=True)


if __name__ == "__main__":
    unittest.main()
