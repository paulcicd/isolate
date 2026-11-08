"""Publication, cross-node replay and fail-closed evidence integrity tests."""

import copy
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))

from botocore.exceptions import ClientError
import fakeredis
from isolate_logging import SessionLogger
from isolate_recordings import RecordingArchive, RecordingError, RecordingIntegrityError, RecordingUnavailable
from isolate_replay import find_archived_session, parse_raw_replay


class MemoryS3:
    def __init__(self):
        self.objects = {}
        self.offline = False
        self.requests = []

    def put_object(self, **options):
        self.requests.append(("put", options["Key"]))
        if self.offline:
            raise OSError("synthetic storage outage")
        if options["Key"] in self.objects and options.get("IfNoneMatch") == "*":
            raise ClientError({"Error": {"Code": "PreconditionFailed"}, "ResponseMetadata": {"HTTPStatusCode": 412}}, "PutObject")
        self.objects[options["Key"]] = bytes(options["Body"])
        return {"ETag": "synthetic"}

    def get_object(self, **options):
        self.requests.append(("get", options["Key"]))
        if self.offline or options["Key"] not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}, "ResponseMetadata": {"HTTPStatusCode": 404}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[options["Key"]])}


class RecordingsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.logs = self.directory / "logs"
        self.logs.mkdir()
        self.logs.chmod(0o700)
        self.key = self.directory / "manifest.key"
        self.key.write_bytes(b"synthetic-private-manifest-key-32-bytes")
        self.key.chmod(0o600)
        self.config = {"data_root": str(self.directory), "logging": {"base_path": str(self.logs)}, "recordings": {
            "enabled": True, "backend": "s3", "bucket": "recording-test", "prefix": "tests", "chunk_bytes": 1024,
            "capture_path": str(self.logs), "signing_key_file": str(self.key), "outbox_path": str(self.directory / "outbox"), "cache_path": str(self.directory / "cache")}}
        self.redis = fakeredis.FakeRedis()
        self.s3 = MemoryS3()
        self.archive = RecordingArchive(self.config, self.s3, self.redis)
        self.metadata = {"username": "alice", "keycloak_sub": "stable-alice", "project": "payments", "host_id": "42", "protocol": "ssh"}
        self.session = self.logs / "session.jsonl"
        self.terminal = self.logs / "target.log"
        self.session.write_text(json.dumps(dict(self.metadata, event="ssh_start", session_id="connection-1", ts=1000,
            connection_id="connection-1", raw_log_path=str(self.terminal))) + "\n", encoding="utf-8")
        self.terminal.write_bytes(b"1000.000000\nhello\r\n")

    def capture(self, close=True):
        self.archive.enqueue_file("connection-1", "session.jsonl", str(self.session), self.metadata)
        return self.archive.enqueue_file("connection-1", "terminal.log", str(self.terminal), closed=close)

    def reader(self):
        options = copy.deepcopy(self.config)
        options["recordings"].update(cache_path=str(self.directory / "reader-cache"), outbox_path=str(self.directory / "reader-outbox"))
        return RecordingArchive(options, self.s3, self.redis)

    def test_cross_node_materialization_survives_loss_of_original_files(self):
        manifest = self.capture()
        result = self.archive.flush_once()
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["pending"], 0)
        shutil.rmtree(self.logs)
        shutil.rmtree(self.directory / "outbox")
        reader = self.reader()
        description = reader.describe("connection-1")
        self.assertTrue(description["complete"])
        self.assertEqual(description["metadata"]["keycloak_sub"], "stable-alice")
        materialized = reader.materialize("connection-1", expected_revision=description["revision"])
        self.assertEqual(materialized["manifest"], manifest)
        self.assertEqual(parse_raw_replay(materialized["raw_log_path"])["plain"], "hello\r\n")

    def test_live_publication_is_explicitly_incomplete_and_advances(self):
        self.capture(close=False)
        self.archive.flush_once()
        before = self.reader().describe("connection-1")
        self.assertFalse(before["complete"])
        with self.terminal.open("ab") as output:
            output.write(b"1001.000000\nnext\r\n")
        self.archive.enqueue_file("connection-1", "terminal.log", str(self.terminal), closed=True)
        self.archive.flush_once()
        latest = self.reader().describe("connection-1")
        self.assertGreater(latest["revision"], before["revision"])
        with self.assertRaises(RecordingUnavailable):
            self.reader().materialize("connection-1", expected_revision=before["revision"])
        result = self.reader().materialize("connection-1")
        self.assertTrue(result["complete"])
        self.assertIn("next", parse_raw_replay(result["raw_log_path"])["plain"])

    def test_outage_restart_and_retry_are_durable_and_idempotent(self):
        self.capture()
        self.s3.offline = True
        failed = self.archive.flush_once()
        self.assertGreater(failed["failed"], 0)
        self.assertGreater(failed["pending"], 0)
        self.assertIsNone(self.redis.get("recording_head_connection-1"))
        self.s3.offline = False
        restarted = RecordingArchive(self.config, self.s3, self.redis)
        self.assertEqual(restarted.flush_once()["pending"], 0)
        keys = set(self.s3.objects)
        self.assertEqual(restarted.flush_once()["published"], 0)
        self.assertEqual(set(self.s3.objects), keys)

    def test_queue_descriptor_is_repaired_after_process_crash(self):
        manifest = self.capture()
        for path in (self.directory / "outbox" / "pending").iterdir():
            path.unlink()
        self.assertEqual(self.archive.flush_once()["published"], 1)
        self.assertEqual(self.reader().describe("connection-1")["revision"], manifest["revision"])

    def test_corrupt_and_missing_chunks_are_detected(self):
        self.capture()
        self.archive.flush_once()
        terminal = self.reader()._manifest("connection-1")["files"]["terminal.log"]["chunks"][0]
        key = self.archive._chunk_key(terminal["sha256"])
        original = self.s3.objects[key]
        self.s3.objects[key] = original[:-1]
        with self.assertRaises(RecordingIntegrityError):
            self.reader().materialize("connection-1")
        del self.s3.objects[key]
        with self.assertRaises(RecordingUnavailable):
            self.reader().materialize("connection-1")

    def test_signed_manifest_rollback_cannot_replace_authority_pointer(self):
        first = self.capture(close=False)
        self.archive.flush_once()
        old_objects = dict(self.s3.objects)
        self.archive.enqueue_file("connection-1", "terminal.log", str(self.terminal), closed=True)
        self.archive.flush_once()
        pointer = json.loads(self.redis.get("recording_head_connection-1"))
        latest_key = self.archive._manifest_key("connection-1", pointer["revision"], pointer["manifest_sha256"])
        old_manifest = next(data for key, data in old_objects.items() if "/sessions/" in key)
        self.s3.objects[latest_key] = old_manifest
        with self.assertRaises(RecordingIntegrityError):
            self.reader().describe("connection-1")

    def test_authority_outage_never_uses_an_older_cached_recording(self):
        self.capture()
        self.archive.flush_once()
        reader = self.reader()
        reader.materialize("connection-1")
        with mock.patch.object(self.redis, "get", side_effect=OSError("authority outage")):
            with self.assertRaises(RecordingUnavailable):
                reader.materialize("connection-1")

    def test_source_truncation_or_same_size_tampering_is_detected(self):
        self.capture(close=False)
        original = self.terminal.read_bytes()
        self.terminal.write_bytes(b"changed" + original[7:])
        with self.assertRaises(RecordingIntegrityError):
            self.archive.enqueue_file("connection-1", "terminal.log", str(self.terminal), closed=True)
        self.terminal.write_bytes(b"short")
        with self.assertRaises(RecordingIntegrityError):
            self.archive.enqueue_file("connection-1", "terminal.log", str(self.terminal))

    def test_caller_cannot_escape_paths_or_change_authorization_metadata(self):
        self.capture(close=False)
        for value in ("../escape", "/absolute", "a/b", "a\\b", "", "a?query"):
            with self.subTest(value=value), self.assertRaises(RecordingError):
                self.archive.materialize(value)
        with self.assertRaises(RecordingError):
            self.archive.enqueue_file("connection-2", "session.jsonl", str(self.key), self.metadata)
        with self.assertRaises(RecordingIntegrityError):
            self.archive.enqueue_file("connection-1", "terminal.log", str(self.terminal), dict(self.metadata, project="other"))

    def test_immutable_object_conflict_is_detected_without_overwrite(self):
        manifest = self.capture()
        chunk = manifest["files"]["terminal.log"]["chunks"][0]
        key = self.archive._chunk_key(chunk["sha256"])
        self.s3.objects[key] = b"corrupted-existing-object"
        result = self.archive.flush_once()
        self.assertGreater(result["failed"], 0)
        self.assertEqual(self.s3.objects[key], b"corrupted-existing-object")

    def test_different_producer_cannot_overwrite_a_published_revision(self):
        self.archive.enqueue_file("connection-1", "session.jsonl", str(self.session), self.metadata)
        self.archive.flush_once()
        other = self.reader()
        with self.session.open("a", encoding="utf-8") as output:
            output.write(json.dumps({"event": "different"}) + "\n")
        other.enqueue_file("connection-1", "session.jsonl", str(self.session), self.metadata)
        result = other.flush_once()
        self.assertEqual(result["failed"], 1)
        self.assertEqual(json.loads(self.redis.get("recording_head_connection-1"))["revision"], 1)

    def test_manifest_signing_key_rotation_preserves_readability(self):
        self.capture()
        self.archive.flush_once()
        new_key = self.directory / "new.key"
        new_key.write_bytes(b"new-private-manifest-signing-key-at-least-32-bytes")
        new_key.chmod(0o600)
        config = copy.deepcopy(self.config)
        config["recordings"].update(signing_key_file=str(new_key), signing_key_id="recordings-v2",
            verification_key_files={"recordings-v1": str(self.key)})
        self.assertTrue(RecordingArchive(config, self.s3, self.redis).describe("connection-1")["complete"])
        del config["recordings"]["verification_key_files"]
        with self.assertRaises(RecordingIntegrityError):
            RecordingArchive(config, self.s3, self.redis).describe("connection-1")

    def test_shared_replay_checks_permission_before_fetching_contents(self):
        self.capture()
        self.archive.flush_once()
        shutil.rmtree(self.logs)
        self.s3.requests.clear()
        with mock.patch("isolate_recordings.RecordingArchive.client", new_callable=mock.PropertyMock, return_value=self.s3):
            with self.assertRaises(RecordingError):
                find_archived_session(self.config, "connection-1", self.redis, authorize=lambda metadata: False)
            self.assertFalse(any("/chunks/" in key for method, key in self.s3.requests if method == "get"))
            details = find_archived_session(self.config, "connection-1", self.redis,
                authorize=lambda metadata: metadata["keycloak_sub"] == "stable-alice")
        self.assertTrue(details["archive_complete"])
        self.assertEqual(parse_raw_replay(details["raw_log_path"])["plain"], "hello\r\n")

    def test_logger_archives_events_and_raw_recording_without_inline_credentials(self):
        logger = SessionLogger(str(self.logs), {"username": "alice", "keycloak_sub": "stable-alice"},
            session_id="logger-1", archive_config=self.config, state_client=self.redis)
        logger.event_durable("ssh_start", project="payments", host_id="42")
        logger.archive_file(str(self.terminal))
        logger.event("ssh_end", project="payments", exit_code=0)
        manifest = logger.close_archive(str(self.terminal))
        self.assertTrue(manifest["complete"])
        self.assertEqual(set(manifest["files"]), {"session.jsonl", "terminal.log"})
        self.assertNotIn(str(self.logs), json.dumps(manifest))
        self.assertEqual(self.archive.flush_once()["failed"], 0)

    def test_disable_is_a_noop_and_insecure_endpoint_is_refused(self):
        disabled = RecordingArchive({})
        self.assertIsNone(disabled.enqueue_file("any", "session.jsonl", "not-a-path"))
        self.assertEqual(disabled.flush_once()["published"], 0)
        for endpoint in ("http://minio.example", "https://token:secret@minio.example", "https://minio.example/?token=x"):
            config = copy.deepcopy(self.config)
            config["recordings"]["endpoint_url"] = endpoint
            with self.assertRaises(RecordingError):
                RecordingArchive(config, self.s3, self.redis)


if __name__ == "__main__":
    unittest.main()
