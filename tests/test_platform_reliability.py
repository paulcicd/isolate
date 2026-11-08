"""Cross-component invariants at recovery, admission and evidence boundaries."""

import concurrent.futures
import copy
import json
import os
from pathlib import Path
import sys
import time
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import test_runtime_api_index as runtime_fixtures
import test_recordings as recording_fixtures
from isolate_admission import AdmissionDenied, check_admission
from isolate_connection_auth import ConnectionDenied, authorize_connection, wait_for_connection_approval
from isolate_history import read_history, list_user_profiles, user_activity_summary
from isolate_health import run_health_checks
from isolate_recovery import rotate_authority_epoch
from isolate_replay import find_session
from isolate_runtime import Runtime, RuntimeDenied
from isolate_sessions import get_session, request_session_termination, termination_requested
from isolate_state import SQLState, StateClient, StateUnavailable
from isolate_state_migration import activate_restored, restore_snapshot, write_snapshot


class RecoveryBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.fixture = runtime_fixtures.RuntimeTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config = self.fixture.config
        self.options = {"backend": "sqlite", "sqlite_path": os.path.join(self.fixture.directory.name, "authority.sqlite")}
        SQLState(self.options).initialize()
        self.store = StateClient(self.fixture.redis, self.options)
        self.config["state"] = self.options
        for key in ("server_1", "grant_1"):
            self.store.set(key, self.fixture.redis.get(key))
        self.runtime = Runtime(self.config, self.store)

    def rotate(self):
        return rotate_authority_epoch(self.store, self.config, "fixture-operator", "tested recovery boundary")

    def context(self):
        return self.runtime.consume_ticket(self.runtime.create_ticket(self.fixture.token, "1")["ticket"])

    def test_old_ticket_cannot_adopt_new_epoch_during_slow_authorization(self):
        ticket = self.runtime.create_ticket(self.fixture.token, "1")["ticket"]
        authorize = self.runtime.authorize
        def interleaved(*args, **kwargs):
            self.rotate()
            return authorize(*args, **kwargs)
        with mock.patch.object(self.runtime, "authorize", side_effect=interleaved):
            with self.assertRaises(RuntimeDenied):
                self.runtime.consume_ticket(ticket)

    def test_live_context_cannot_cross_epoch_during_recheck(self):
        context = self.context()
        self.runtime.prepare(context)
        authorize = self.runtime.authorize
        def interleaved(*args, **kwargs):
            self.rotate()
            return authorize(*args, **kwargs)
        try:
            with mock.patch.object(self.runtime, "authorize", side_effect=interleaved):
                with self.assertRaises(RuntimeDenied):
                    self.runtime.start(context)
            self.assertIsNone(get_session(self.store, context["connection_id"]))
        finally:
            self.runtime.finish(context)

    def test_termination_survives_short_heartbeat_and_stale_registry(self):
        context = self.context()
        self.runtime.prepare(context)
        self.runtime.start(context)
        try:
            key = "active_session_" + context["connection_id"]
            stale = json.loads(self.fixture.redis.get(key))
            stale["registry_ttl"] = 1
            self.fixture.redis.set(key, json.dumps(stale))
            request_session_termination(self.store, context["connection_id"], {"username": "operator"})
            self.assertEqual(self.store.ttl("session_termination_" + context["connection_id"]), -1)
            self.fixture.redis.set(key, json.dumps(stale))
            with mock.patch.object(self.store.state, "_now", return_value=time.time() + 120):
                self.assertTrue(termination_requested(self.store, context["connection_id"]))
                with self.assertRaises(RuntimeDenied):
                    self.runtime.recheck(context)
        finally:
            self.runtime.finish(context)

    def test_legacy_pending_approval_is_not_upgraded_across_recovery(self):
        self.config["session_approval"].update(enabled=True, required_projects=["prod"])
        args = SimpleNamespace(host_id="1", hostname=["127.0.0.1"], user=["support"], port=22,
            nosudo=True, project="prod", human_user=None, keycloak_sub=None,
            proxy_host=None, proxy_port=None, proxy_user=None)
        context = authorize_connection(args, self.fixture.token, self.config, self.store, "alice")
        def recovery_config():
            self.rotate()
            return self.config
        with self.assertRaisesRegex(ConnectionDenied, "recovery boundary"):
            wait_for_connection_approval(context, self.config, self.store, "legacy-pending", refresh_config=recovery_config)

    def test_sql_outage_never_uses_leftover_redis_allow_records(self):
        self.assertIsNotNone(self.fixture.redis.get("grant_1"))
        with mock.patch.object(self.store.state, "get", side_effect=StateUnavailable("fixture outage")):
            with self.assertRaises(StateUnavailable):
                self.runtime.create_ticket(self.fixture.token, "1")

    def test_health_distinguishes_sql_authority_failure_from_redis_failure(self):
        valid = {"valid": True, "errors": [], "warnings": []}
        with mock.patch("isolate_health.validate_config", return_value=valid):
            healthy = run_health_checks(self.config, redis_factory=lambda config: self.store)
            self.assertTrue(healthy["checks"]["state"]["ok"])
            self.assertNotIn("epoch", healthy["checks"]["state"])
            with mock.patch.object(self.store.state, "connection", side_effect=StateUnavailable("secret-dsn")):
                unhealthy = run_health_checks(self.config, redis_factory=lambda config: self.store)
            self.assertTrue(unhealthy["checks"]["redis"]["ok"])
            self.assertFalse(unhealthy["checks"]["state"]["ok"])
            self.assertNotIn("secret-dsn", json.dumps(unhealthy))

    def test_snapshot_before_execution_cannot_requeue_an_already_run_job(self):
        self.store.set("job_1", json.dumps({"id": "1", "schema_version": 1, "status": "queued", "timeout": 30}))
        snapshot = os.path.join(self.fixture.directory.name, "before-claim.json")
        write_snapshot(self.store.state, snapshot)
        self.store.set("job_1", json.dumps({"id": "1", "status": "completed"}))
        self.store.set("job_execution_claim_1", "already ran outside the snapshot")
        target_options = {"backend": "sqlite", "sqlite_path": os.path.join(self.fixture.directory.name, "restored.sqlite")}
        target = SQLState(target_options)
        target.initialize(active=False)
        restore_snapshot(target, snapshot, external_fence=True)
        result = activate_restored(target, "operator", "unknown remote outcomes quarantined", external_fence=True)
        self.assertEqual(result["quarantined_jobs"], 1)
        self.assertEqual(json.loads(target.get("job_1"))["status"], "recovery_required")
        self.assertIsNotNone(target.get("job_execution_claim_1"))
        from isolate_jobs import run_worker
        with mock.patch("isolate_jobs.execute_job") as execute:
            run_worker(self.config, StateClient(self.fixture.redis, target_options), once=True)
        execute.assert_not_called()

    def test_shared_admission_is_atomic_between_nodes(self):
        config = {"admission": {"enabled": True, "per_subject_per_minute": 1, "global_per_minute": 100}}
        def attempt(_):
            try:
                check_admission(self.store, config, subject="alice", now=600)
                return True
            except AdmissionDenied:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(8))), 1)

    def test_denied_job_api_cannot_reserve_durable_submission_rows(self):
        with mock.patch.object(self.fixture, "redis", self.store):
            client = self.fixture.app().test_client()
            response = client.post("/api/v1/jobs", json={"type": "command", "host_id": "1", "command": "whoami", "confirm": True},
                headers={"Authorization": "Bearer " + self.fixture.token, "Idempotency-Key": "unprivileged-submission"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.store.keys("job_submission_*"), [])

    def test_unknown_length_and_deep_json_are_bounded_before_parsing(self):
        client = self.fixture.app().test_client()
        headers = {"Authorization": "Bearer " + self.fixture.token}
        too_large = b'{"host_id":"' + b'x' * 5000 + b'"}'
        response = client.post("/api/v1/connections", data=too_large, content_type="application/json", headers=headers,
            environ_overrides={"CONTENT_LENGTH": "", "wsgi.input_terminated": True})
        self.assertEqual(response.status_code, 413)
        nested = '{"host_id":' + '[' * 1500 + '0' + ']' * 1500 + '}'
        response = client.post("/api/v1/connections", data=nested, content_type="application/json", headers=headers)
        self.assertEqual(response.status_code, 400)

    def test_history_storage_outage_is_reported_as_unavailable(self):
        from isolate_recordings import RecordingUnavailable
        self.config["dashboard"]["admin_groups"] = ["Support"]
        client = self.fixture.app().test_client()
        with client.session_transaction() as session:
            session["identity"] = self.runtime.authenticate(self.fixture.token)
        with mock.patch("isolate_web.read_history", side_effect=RecordingUnavailable("fixture outage")), \
                mock.patch("isolate_self_service.read_history", side_effect=RecordingUnavailable("fixture outage")):
            for path in ("/history", "/export/history", "/me/history"):
                with self.subTest(path=path):
                    self.assertEqual(client.get(path).status_code, 503)


class ArchivedEvidenceBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.fixture = recording_fixtures.RecordingsTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.metadata.update(started_at=1000, ended_at=1001, exit_code=0)
        self.fixture.capture()
        self.fixture.archive.flush_once()
        self.fixture.session.unlink()
        self.fixture.terminal.unlink()
        self.reader = self.fixture.reader()
        patcher = mock.patch("isolate_recordings.RecordingArchive", return_value=self.reader)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_published_evidence_wins_over_forged_legacy_log(self):
        legacy = self.fixture.directory / "legacy" / "forger" / "fake"
        legacy.mkdir(parents=True)
        (legacy / "session.jsonl").write_text(json.dumps({"event": "ssh_start", "connection_id": "connection-1",
            "session_id": "connection-1", "project": "forged", "username": "forger", "ts": 1000}) + "\n")
        seen = []
        details = find_session(str(legacy.parent.parent), "connection-1", archive_config=self.fixture.config,
            state_client=self.fixture.redis, authorize_archive=lambda metadata: seen.append(metadata["project"]) or True)
        self.assertEqual(seen, ["payments"])
        self.assertEqual(details["summary"]["project"], "payments")
        with self.assertRaises(ValueError):
            find_session(str(legacy.parent.parent), "connection-1", archive_config=self.fixture.config,
                state_client=self.fixture.redis, authorize_archive=lambda metadata: False)

    def test_remote_history_is_scoped_and_does_not_download_terminal_chunks(self):
        self.fixture.s3.requests.clear()
        identity = {"username": "alice", "keycloak_sub": "stable-alice", "groups": []}
        rows = read_history(str(self.fixture.directory / "missing-local-node"), identity,
            archive_config=self.fixture.config, state_client=self.fixture.redis)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["project"], "payments")
        self.assertFalse(any(operation == "get" and "/chunks/" in key for operation, key in self.fixture.s3.requests))
        before = len(self.fixture.s3.requests)
        self.assertEqual(read_history(str(self.fixture.directory / "missing-local-node"),
            {"username": "mallory", "keycloak_sub": "other", "groups": []}, archive_config=self.fixture.config,
            state_client=self.fixture.redis), [])
        self.assertEqual(len(self.fixture.s3.requests), before)

    def test_profiles_and_activity_survive_loss_of_origin_logs(self):
        base = str(self.fixture.directory / "missing-local-node")
        profiles = list_user_profiles(base, self.fixture.config, self.fixture.redis)
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["username"], "alice")
        self.assertEqual(profiles[0]["connection_count"], 1)
        activity = user_activity_summary(base, "alice", archive_config=self.fixture.config, state_client=self.fixture.redis)
        self.assertEqual(activity["metrics"]["connections"], 1)
        self.assertEqual(activity["recent_sessions"][0]["project"], "payments")


if __name__ == "__main__":
    unittest.main()
