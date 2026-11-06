import gzip
import json
import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))

import isolate_audit_export
from isolate_audit import append_jsonl_record, prepare_and_dispatch, verify_audit_record
from isolate_audit_export import AuditExporter
from isolate_logging import SessionLogger


def write_concurrent_records(path, worker):
    write = os.write
    # Force short writes to exercise the cross-process lock, not just O_APPEND.
    with mock.patch.object(os, "write", side_effect=lambda fd, data: write(fd, data[:97])):
        for n in range(20):
            append_jsonl_record(path, {"event": "command", "worker": worker, "n": n, "command": "x" * 2048})


class AuditExportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs = self.root / "logs"
        self.spool = self.root / "spool"
        self.state = self.root / "state"
        self.output = self.spool / "events.jsonl"
        self.logs.mkdir()
        self.spool.mkdir()

    def exporter(self, **kwargs):
        return AuditExporter(self.logs, self.spool, self.output, self.state, **kwargs)

    def append(self, path, record):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")

    def read(self):
        return [json.loads(line) for line in self.output.read_text().splitlines()]

    def test_backfills_new_sessions_and_resumes_after_restart(self):
        source = self.logs / "alice" / "s1" / "session.jsonl"
        self.append(source, {"event": "ssh_start", "ts": 1})
        with self.exporter() as exporter:
            self.assertEqual(exporter.run_once(), {"exported": 1, "errors": 0})
            self.assertEqual(exporter.run_once()["exported"], 0)
        self.append(source, {"event": "ssh_end", "ts": 2})
        self.append(self.logs / "bob" / "s2" / "session.jsonl", {"event": "command", "command": "uname -a"})
        with self.exporter() as exporter:
            self.assertEqual(exporter.run_once()["exported"], 2)
        self.assertEqual(len(self.read()), 3)

    def test_deduplicates_session_and_spool_without_modifying_signature(self):
        key = self.root / "key"
        key.write_bytes(b"test-key\n")
        cfg = {"integrity": {"enabled": True, "key_file": str(key)},
               "sinks": [{"type": "jsonl", "path": str(self.spool / "audit.jsonl")}]}
        record = SessionLogger(str(self.logs), {"username": "alice", "session_id": "s1"}, logging_config=cfg).event("ssh_start")
        self.assertTrue(record["event_id"])
        with self.exporter() as exporter:
            self.assertEqual(exporter.run_once()["exported"], 1)
        self.assertEqual(self.read(), [record])
        self.assertTrue(verify_audit_record(self.read()[0], b"test-key"))

    def test_incomplete_source_line_waits_for_newline(self):
        source = self.spool / "audit.jsonl"
        source.write_bytes(b'{"event":"command","command":"echo hello')
        with self.exporter() as exporter:
            self.assertEqual(exporter.run_once()["exported"], 0)
            with source.open("ab") as stream:
                stream.write(b'"}\n')
            self.assertEqual(exporter.run_once()["exported"], 1)
        self.assertEqual(self.read()[0]["command"], "echo hello")

    def test_batches_drain_unchanged_file(self):
        for i in range(5):
            self.append(self.spool / "audit.jsonl", {"event": "command", "ts": i})
        with self.exporter(batch_size=2) as exporter:
            self.assertEqual([exporter.run_once()["exported"] for _ in range(4)], [2, 2, 1, 0])
        self.assertEqual(len(self.read()), 5)

    def test_reads_rotated_gzip_input_and_reopens_rotated_output(self):
        self.append(self.spool / "audit.jsonl", {"event": "ssh_start"})
        with self.exporter() as exporter:
            exporter.run_once()
            (self.spool / "audit.jsonl").rename(self.spool / "audit.jsonl.1")
            with gzip.open(self.spool / "audit.jsonl.2.gz", "wb") as stream:
                stream.write(b'{"event":"ssh_end"}\n')
            self.output.rename(self.spool / "events.jsonl.1")
            self.assertEqual(exporter.run_once()["exported"], 1)
        self.assertEqual(self.read(), [{"event": "ssh_end"}])

    def test_output_error_never_advances_source_checkpoint(self):
        self.append(self.spool / "audit.jsonl", {"event": "command"})
        with self.exporter() as exporter:
            with mock.patch.object(isolate_audit_export, "_write_all", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    exporter.run_once()
        with self.exporter() as exporter:
            self.assertEqual(exporter.run_once()["exported"], 1)
        self.assertEqual(len(self.read()), 1)

    def test_crash_after_output_before_checkpoint_replays_with_same_event_id(self):
        event = prepare_and_dispatch({"event": "ssh_start"}, {})
        self.append(self.spool / "audit.jsonl", event)
        # Simulate the acknowledged duplicate window: output is durable, DB is not.
        self.append(self.output, event)
        with self.exporter() as exporter:
            exporter.run_once()
        self.assertEqual([record["event_id"] for record in self.read()], [event["event_id"]] * 2)

    def test_partial_output_tail_repaired_before_replay(self):
        self.append(self.output, {"event": "previous"})
        with self.output.open("ab") as stream:
            stream.write(b'{"event":"comm')
        self.append(self.spool / "audit.jsonl", {"event": "command"})
        with self.exporter() as exporter:
            exporter.run_once()
        self.assertEqual(self.read(), [{"event": "previous"}, {"event": "command"}])

    def test_invalid_record_reports_error_without_skipping_it(self):
        source = self.spool / "audit.jsonl"
        source.write_bytes(b'not-json\n{"event":"command"}\n')
        with self.exporter() as exporter:
            with self.assertLogs("isolate-audit-export", level="ERROR"):
                self.assertEqual(exporter.run_once(), {"exported": 0, "errors": 1})
            self.assertIsNone(exporter.db.execute("SELECT offset FROM positions").fetchone())

    def test_oversized_for_wazuh_event_is_preserved_and_reported(self):
        record = {"event": "command", "command": "x" * (64 * 1024)}
        self.append(self.spool / "audit.jsonl", record)
        with self.exporter() as exporter:
            with self.assertLogs("isolate-audit-export", level="WARNING"):
                self.assertEqual(exporter.run_once()["exported"], 1)
        self.assertEqual(self.read(), [record])

    @unittest.skipUnless(os.name == "posix", "Linux source symlink handling")
    def test_rejects_session_directory_symlink_and_output_symlink(self):
        elsewhere = self.root / "elsewhere"
        self.append(elsewhere / "s1" / "session.jsonl", {"event": "command"})
        (self.logs / "alice").symlink_to(elsewhere, target_is_directory=True)
        with self.exporter() as exporter:
            with self.assertLogs("isolate-audit-export", level="ERROR"):
                self.assertEqual(exporter.run_once()["exported"], 0)
        self.output.unlink()
        self.output.symlink_to(elsewhere / "s1" / "session.jsonl")
        with self.assertRaises(OSError):
            self.exporter()

    def test_one_process_owns_state(self):
        with self.exporter():
            with self.assertRaises(OSError):
                self.exporter()

    def test_short_writes_are_completed(self):
        written = []

        def short_write(fd, payload):
            count = min(len(payload), 3)
            written.append(bytes(payload[:count]))
            return count

        with mock.patch.object(os, "write", side_effect=short_write):
            isolate_audit_export._write_all(123, b"hello world")
        self.assertEqual(b"".join(written), b"hello world")

    @unittest.skipUnless(os.name == "posix", "Linux concurrent audit writers")
    def test_concurrent_writers_keep_each_json_record_intact(self):
        path = self.spool / "audit.jsonl"
        processes = [multiprocessing.get_context("fork").Process(target=write_concurrent_records, args=(str(path), worker))
                     for worker in range(4)]
        try:
            for process in processes:
                process.start()
            for process in processes:
                process.join(15)
                self.assertEqual(process.exitcode, 0)
            with self.exporter() as exporter:
                self.assertEqual(exporter.run_once(), {"exported": 80, "errors": 0})
            self.assertEqual({(r["worker"], r["n"]) for r in self.read()},
                             {(worker, n) for worker in range(4) for n in range(20)})
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join()


if __name__ == "__main__":
    unittest.main()
