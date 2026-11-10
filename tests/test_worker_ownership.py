"""Exercise WATCH conflicts and independent workers sharing one Redis server."""

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))

import fakeredis
import isolate_jobs as jobs
from isolate_dashboard_data import fleet_progress
import isolate_sessions as sessions
import isolate_worker_ownership as ownership


class InterleaveRedis:
    """Inject another real Redis transaction immediately before EXEC once."""
    def __init__(self, redis, before_execute):
        self.redis = redis
        self.before_execute = before_execute

    def __getattr__(self, name):
        return getattr(self.redis, name)

    def pipeline(self):
        outer = self
        pipe = self.redis.pipeline()

        class Pipeline:
            def __enter__(self):
                pipe.__enter__()
                return self

            def __exit__(self, *args):
                return pipe.__exit__(*args)

            def __getattr__(self, name):
                return getattr(pipe, name)

            def execute(self):
                callback = outer.before_execute
                outer.before_execute = None
                if callback:
                    callback()
                return pipe.execute()

        return Pipeline()


class WorkerOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.server = fakeredis.FakeServer()
        self.redis = fakeredis.FakeRedis(server=self.server, decode_responses=True)
        self.other = fakeredis.FakeRedis(server=self.server, decode_responses=True)

    def queued(self):
        self.redis.set("job_1", json.dumps({"id": "1", "status": "queued", "timeout": 30}))
        self.redis.set("job_lock_1", "owner-1", ex=60)

    def test_delayed_worker_cannot_finish_after_lease_loss_or_quarantine(self):
        self.queued()
        ownership.claim_job(self.redis, '1', 'owner-1')
        self.other.delete('job_lock_1')
        with self.assertRaises(ownership.JobOwnershipError):
            ownership.update_owned_job(self.redis, '1', 'owner-1', {'status': 'completed', 'exit_code': 0})
        self.other.set('job_lock_1', 'recovery-operator', ex=60)
        quarantined = ownership.mark_recovery_required(self.other, '1', 'recovery-operator')
        self.assertEqual(quarantined['status'], 'recovery_required')
        # Even reacquiring a lock with the old token cannot undo quarantine.
        self.other.set('job_lock_1', 'owner-1', ex=60)
        with self.assertRaises(ownership.JobOwnershipError):
            ownership.update_owned_job(self.redis, '1', 'owner-1', {'status': 'completed', 'exit_code': 0})
        self.assertEqual(jobs.get_job(self.other, '1')['status'], 'recovery_required')

    def test_durable_claim_allows_only_one_racing_executor(self):
        self.queued()
        barrier = threading.Barrier(2)

        def execute(client):
            barrier.wait(timeout=5)
            return ownership.claim_job(client, "1", "owner-1")

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(execute, (self.redis, self.other)))
        self.assertEqual(sum(item is not None for item in results), 1)
        self.assertEqual(self.redis.ttl(ownership.claim_key("1")), -1)
        self.assertEqual(jobs.get_job(self.redis, "1")["status"], "claimed")

    def test_old_owner_cannot_release_or_claim_successors_lock(self):
        self.queued()
        self.other.set("job_lock_1", "owner-2", ex=60)
        self.assertFalse(ownership.release_lock(self.redis, "job_lock_1", "owner-1"))
        with self.assertRaises(ownership.JobOwnershipError):
            ownership.claim_job(self.redis, "1", "owner-1")
        self.assertEqual(self.redis.get("job_lock_1"), "owner-2")
        self.assertTrue(ownership.release_lock(self.other, "job_lock_1", "owner-2"))

    def test_crash_after_claim_requires_inspection_instead_of_reexecution(self):
        self.queued()
        ownership.claim_job(self.redis, "1", "owner-1")
        # Simulate expiration/loss of the old worker lease on another machine.
        self.other.delete("job_lock_1")
        record = jobs.get_job(self.other, "1")
        with mock.patch.object(jobs.subprocess, "Popen") as popen, mock.patch.object(jobs, "_audit"):
            result = jobs.execute_job(self.other, {}, record)
        self.assertEqual(result["status"], "recovery_required")
        popen.assert_not_called()
        self.assertIsNotNone(self.redis.get(ownership.claim_key("1")))
        self.assertNotIn("recovery_required", jobs.FAILED_JOB_STATUSES)

    def test_worker_loop_surfaces_orphan_running_jobs_without_executing_them(self):
        self.redis.set("job_1", json.dumps({"id": "1", "status": "running", "timeout": 30}))
        with mock.patch.object(jobs.subprocess, "Popen") as popen, mock.patch.object(jobs, "_audit"):
            jobs.run_worker({}, self.redis, once=True)
        popen.assert_not_called()
        self.assertEqual(jobs.get_job(self.redis, "1")["status"], "recovery_required")
        self.assertIsNotNone(self.redis.get(ownership.claim_key("1")))

    def test_recovery_fleet_is_never_reported_as_completed_or_retriable(self):
        result = fleet_progress([
            {"id": "1", "fleet_id": "fleet-1", "host_id": "42", "status": "recovery_required"},
            {"id": "2", "fleet_id": "fleet-1", "host_id": "43", "status": "claimed"},
        ])[0]
        self.assertEqual(result["status"], "recovery_required")
        self.assertEqual(result["recovery_required"], 1)
        self.assertEqual(result["claimed"], 1)
        self.assertEqual(result["finished"], 0)
        self.assertEqual(result["failed_job_ids"], [])

    def test_running_worker_update_keeps_concurrent_cancel_request(self):
        self.queued()
        ownership.claim_job(self.redis, "1", "owner-1")
        wrapper = InterleaveRedis(self.redis, lambda: jobs.request_job_cancel(
            self.other, "1", {"username": "security"}))
        result = ownership.update_owned_job(wrapper, "1", "owner-1", {"status": "running"})
        self.assertTrue(result["cancel_requested"])
        self.assertEqual(result["cancel_requested_by"], "security")

    def test_completed_job_cannot_be_resurrected_by_stale_cancellation(self):
        self.queued()
        ownership.claim_job(self.redis, "1", "owner-1")
        wrapper = InterleaveRedis(self.redis, lambda: ownership.update_owned_job(
            self.other, "1", "owner-1", {"status": "completed", "exit_code": 0}))
        with self.assertRaises(jobs.JobError):
            jobs.request_job_cancel(wrapper, "1", {"username": "security"})
        self.assertEqual(jobs.get_job(self.redis, "1")["status"], "completed")

    def test_cancelled_queued_job_cannot_be_claimed(self):
        self.queued()
        jobs.request_job_cancel(self.other, "1", {"username": "security"})
        self.assertIsNone(ownership.claim_job(self.redis, "1", "owner-1"))
        self.assertIsNone(self.redis.get(ownership.claim_key("1")))

    def test_unattended_jobs_cannot_bypass_central_identity_lifecycle(self):
        host, decision = {"project_name": "production"}, {"remote_user": "support", "sudo_mode": "none"}
        for option in ("backchannel_logout", "introspection"):
            config = {"identity_security": {option: {"enabled": True}}}
            with self.subTest(option=option), self.assertRaisesRegex(jobs.JobError, "delegated Keycloak"):
                jobs.create_command_job(self.redis, config, {}, host, decision, "id")
        config = {"identity_security": {"step_up": {"enabled": True, "required_projects": ["production"]}}}
        with self.assertRaisesRegex(jobs.JobError, "step-up"):
            jobs.create_command_job(self.redis, config, {}, host, decision, "id")


class SessionRegistryTransactionsTest(unittest.TestCase):
    def setUp(self):
        server = fakeredis.FakeServer()
        self.redis = fakeredis.FakeRedis(server=server, decode_responses=True)
        self.other = fakeredis.FakeRedis(server=server, decode_responses=True)
        sessions.mark_session_start(self.redis, "connection-1", {"username": "alice"})

    def test_heartbeat_keeps_concurrent_termination_request(self):
        wrapper = InterleaveRedis(self.redis, lambda: sessions.request_session_termination(
            self.other, "connection-1", {"username": "security"}, "INC-42"))
        result = sessions.touch_session(wrapper, "connection-1", now=1234)
        self.assertTrue(result["terminate_requested"])
        self.assertEqual(result["terminate_reason"], "INC-42")
        self.assertEqual(result["heartbeat_at"], 1234)
        self.assertGreater(self.redis.ttl("active_session_connection-1"), 0)

    def test_stale_heartbeat_cannot_resurrect_completed_session(self):
        wrapper = InterleaveRedis(self.redis, lambda: sessions.mark_session_end(
            self.other, "connection-1", exit_code=7))
        self.assertIsNone(sessions.touch_session(wrapper, "connection-1"))
        result = sessions.get_session(self.redis, "connection-1")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["exit_code"], 7)
        self.assertLessEqual(self.redis.ttl("active_session_connection-1"), 3600)

    def test_alert_delivery_keeps_concurrent_termination_request(self):
        wrapper = InterleaveRedis(self.redis, lambda: sessions.request_session_termination(
            self.other, "connection-1", {"username": "security"}))
        result = sessions.mark_alert_delivery(wrapper, "connection-1", "vip", {"sent": ["test-sink"]})
        self.assertTrue(result["terminate_requested"])
        self.assertEqual(result["alert_deliveries"][0]["alert"], "vip")


if __name__ == "__main__":
    unittest.main()
