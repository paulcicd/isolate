"""Real HTTPS MinIO + PostgreSQL publication and cross-node replay checks."""

import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "shared"))

import boto3
from botocore.config import Config
import fakeredis
from isolate_recordings import RecordingArchive, RecordingIntegrityError, RecordingUnavailable
from isolate_replay import parse_raw_replay
from isolate_state import SQLState, StateClient


def main():
    client = boto3.client("s3", endpoint_url="https://minio:9000", region_name="us-east-1", verify="/fixtures/ca.pem",
        config=Config(signature_version="s3v4", connect_timeout=3, read_timeout=5, retries={"max_attempts": 1},
            s3={"addressing_style": "path"}))
    deadline = time.monotonic() + 90
    while True:
        try:
            client.list_buckets()
            break
        except Exception:
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)
    client.create_bucket(Bucket="recording-test")
    with tempfile.TemporaryDirectory(prefix="isolate-recordings-") as temporary:
        directory = Path(temporary)
        private_key = directory / "manifest.key"
        private_key.write_bytes(b"isolated-recording-manifest-private-test-key-at-least-32-bytes")
        private_key.chmod(0o600)
        dsn = directory / "postgres.dsn"
        dsn.write_text("postgresql://recording_test:isolated-recording-database-password@postgres/recording_test", encoding="utf-8")
        dsn.chmod(0o600)
        state_options = {"backend": "postgresql", "dsn_file": str(dsn), "require_tls": False}  # isolated test network
        SQLState(state_options).initialize()
        state = StateClient(fakeredis.FakeRedis(), state_options)
        capture = directory / "capture"
        capture.mkdir(mode=0o700)
        session = capture / "session.jsonl"
        terminal = capture / "terminal.log"
        metadata = {"username": "alice", "keycloak_sub": "stable-alice", "project": "payments",
                    "host_id": "42", "protocol": "ssh", "started_at": 1000}
        session.write_text(json.dumps(dict(metadata, event="ssh_start", session_id="integration-1", connection_id="integration-1", ts=1000)) + "\n", encoding="utf-8")
        terminal.write_bytes(b"1000.000000\nfirst line\r\n")
        config = {"data_root": str(directory), "state": state_options, "recordings": {
            "enabled": True, "bucket": "recording-test", "endpoint_url": "https://minio:9000", "ca_bundle": "/fixtures/ca.pem",
            "capture_path": str(capture), "outbox_path": str(directory / "outbox-a"), "cache_path": str(directory / "cache-a"),
            "signing_key_file": str(private_key), "chunk_bytes": 1024}}
        producer = RecordingArchive(config, client, state)
        producer.enqueue_file("integration-1", "session.jsonl", str(session), metadata)
        producer.enqueue_file("integration-1", "terminal.log", str(terminal))
        assert producer.flush_once()["failed"] == 0
        assert not producer.describe("integration-1")["complete"]
        print("PASS: real verified HTTPS S3 conditional writes and PostgreSQL publication of live chunks", flush=True)
        # An unavailable object store leaves a durable outbox and no unbacked
        # authority pointer. A fresh publisher retries the same immutable data.
        with terminal.open("ab") as output:
            output.write(b"1001.000000\nlast line\r\n")
        producer.enqueue_file("integration-1", "terminal.log", str(terminal), closed=True)
        class Offline:
            def put_object(self, **kwargs):
                raise OSError("isolated synthetic network outage")
        producer._client = Offline()
        assert producer.flush_once()["pending"] > 0
        producer = RecordingArchive(config, client, state)
        assert producer.flush_once()["pending"] == 0
        assert producer.flush_once()["published"] == 0
        print("PASS: durable outbox survives outage/restart and retries idempotently", flush=True)
        other_config = copy.deepcopy(config)
        other_config["recordings"].update(outbox_path=str(directory / "outbox-b"), cache_path=str(directory / "cache-b"))
        shutil.rmtree(capture)
        shutil.rmtree(directory / "outbox-a")
        consumer = RecordingArchive(other_config, client, StateClient(fakeredis.FakeRedis(), state_options))
        description = consumer.describe("integration-1")
        restored = consumer.materialize("integration-1", expected_revision=description["revision"])
        assert restored["complete"]
        assert parse_raw_replay(restored["raw_log_path"])["plain"] == "first line\r\nlast line\r\n"
        print("PASS: second node reconstructs complete recording after origin files and spool are gone", flush=True)
        chunk = restored["manifest"]["files"]["terminal.log"]["chunks"][0]
        client.delete_object(Bucket="recording-test", Key=consumer._chunk_key(chunk["sha256"]))
        try:
            consumer.materialize("integration-1")
        except RecordingUnavailable:
            pass
        else:
            raise AssertionError("deleted evidence was not detected")
        print("PASS: missing evidence is detected even with an older local cache", flush=True)
        bad = copy.deepcopy(other_config)
        bad["recordings"]["ca_bundle"] = None
        try:
            RecordingArchive(bad, state_client=state).describe("integration-1")
        except RecordingUnavailable:
            pass
        else:
            raise AssertionError("untrusted HTTPS leaf was accepted")
        print("PASS: untrusted S3 TLS endpoint is rejected", flush=True)
        print("ALL SHARED RECORDING INTEGRATION CHECKS PASSED", flush=True)


if __name__ == "__main__":
    main()
