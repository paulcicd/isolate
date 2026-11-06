import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))

from isolate_audit import verify_audit_record
from isolate_audit_export import AuditExporter
from isolate_health import validate_config
from isolate_logging import SessionLogger
from isolate_managed_shell import ManagedAuditError, audit_mode, remote_command, run_managed_shell
from isolate_ssh import build_ssh_argv


class RecordingAudit:
    def __init__(self):
        self.events = []

    def event_durable(self, name, **fields):
        self.events.append((name, fields))


class ManagedShellTest(unittest.TestCase):
    def setUp(self):
        self.audit = RecordingAudit()
        self.metadata = {"username": "alice", "keycloak_sub": "kc-alice", "connection_id": "conn-1",
                         "host_id": "17", "remote_user": "support", "sudo_mode": "none", "target_host": "192.0.2.17"}
        self.config = {"command_audit": {"enabled": True, "mode": "managed"}}

    def run_shell(self, text, execute=None, audit=None, before=None, control=None, **options):
        config = {"command_audit": dict(self.config["command_audit"], **options)}
        execute = execute or mock.Mock(return_value=0)
        return run_managed_shell(["ssh", "-T", "-n", "192.0.2.17"], io.StringIO(), audit or self.audit,
                                 self.metadata, config, execute, before or (lambda: False), control or (lambda: False),
                                 input_stream=io.StringIO(text), output_stream=io.StringIO())

    def test_records_entire_command_before_execution_and_result_after(self):
        commands = ["printf '%s\\n' 'one'; false", "cd /tmp && pwd", "  echo 'привет мир'  "]
        def execute(argv, raw, control, stdin_null):
            self.assertTrue(stdin_null)
            self.assertEqual(self.audit.events[-1][0], "command_start")
            command = self.audit.events[-1][1]["command"]
            self.assertEqual(shlex.split(argv[-1]), ["/bin/sh", "-c", command])
            return 7
        self.assertEqual(self.run_shell("\n".join(commands) + "\n", execute=execute), 0)
        completed = [e for name, e in self.audit.events if name == "command"]
        self.assertEqual([e["command"] for e in completed], commands)
        self.assertEqual([e["sequence"] for e in completed], [1, 2, 3])
        for event in completed:
            self.assertEqual(event["exitcode"], 7)
            self.assertEqual(event["exit_code"], 7)
            self.assertTrue(event["exit_code_known"])
            self.assertTrue(event["timestamp"].endswith("Z"))
            self.assertEqual(event["keycloak_sub"], "kc-alice")
            self.assertEqual(event["audit_scope"], "submitted_command")

    def test_audit_failure_prevents_execution(self):
        audit, execute = mock.Mock(), mock.Mock()
        audit.event_durable.side_effect = OSError("disk full")
        with self.assertRaises(ManagedAuditError):
            self.run_shell("touch /tmp/must-not-exist\n", execute=execute, audit=audit)
        execute.assert_not_called()

    def test_completion_audit_failure_prevents_next_command(self):
        audit, execute = mock.Mock(), mock.Mock(return_value=0)
        audit.event_durable.side_effect = [{}, OSError("disk full")]
        with self.assertRaises(ManagedAuditError):
            self.run_shell("echo one\necho two\n", execute=execute, audit=audit)
        self.assertEqual(execute.call_count, 1)

    def test_revoked_access_records_denied_command_and_does_not_run(self):
        execute = mock.Mock()
        self.assertEqual(self.run_shell("whoami\n", execute=execute, before=lambda: True), 143)
        execute.assert_not_called()
        self.assertEqual(self.audit.events[-1][1]["command_status"], "denied")
        self.assertIsNone(self.audit.events[-1][1]["exitcode"])

    def test_ssh_255_is_unknown_and_stops_remaining_input(self):
        execute = mock.Mock(return_value=255)
        self.assertEqual(self.run_shell("whoami\nid\n", execute=execute), 255)
        self.assertEqual(execute.call_count, 1)
        event = self.audit.events[-1][1]
        self.assertEqual(event["ssh_returncode"], 255)
        self.assertIsNone(event["exitcode"])
        self.assertFalse(event["exit_code_known"])

    def test_cancellation_is_not_reported_as_remote_exit_code(self):
        def execute(argv, raw, control, stdin_null):
            self.assertTrue(control())
            return 143
        self.assertEqual(self.run_shell("sleep 60\n", execute=execute, control=lambda: True), 143)
        self.assertEqual(self.audit.events[-1][1]["command_status"], "unknown")
        self.assertIsNone(self.audit.events[-1][1]["exitcode"])

    def test_timeout_interrupts_command(self):
        def execute(argv, raw, control, stdin_null):
            self.assertTrue(control())
            return 143
        with mock.patch("isolate_managed_shell.time.monotonic", side_effect=[0, 2, 2]):
            self.assertEqual(self.run_shell("sleep 60\n", execute=execute, command_timeout_seconds=1), 143)
        self.assertEqual(self.audit.events[-1][1]["reason"], "timeout")

    def test_exit_is_audited_and_eof_does_not_create_a_fake_command(self):
        execute = mock.Mock()
        self.assertEqual(self.run_shell("exit\n", execute=execute), 0)
        execute.assert_not_called()
        self.assertEqual(self.audit.events[-1][1]["execution_kind"], "session_exit")
        self.assertEqual(self.audit.events[-1][1]["exitcode"], 0)
        self.audit.events.clear()
        self.assertEqual(self.run_shell(""), 0)
        self.assertEqual(self.audit.events, [])

    def test_oversized_input_never_executes_a_prefix_or_remainder(self):
        execute = mock.Mock()
        self.assertEqual(self.run_shell("x" * 10 + "\necho forbidden\n", execute=execute, max_command_length=4), 2)
        execute.assert_not_called()
        self.assertEqual(self.audit.events[-1][0], "command_rejected")
        self.assertTrue(self.audit.events[-1][1]["command_truncated"])
        self.assertFalse(self.audit.events[-1][1]["audit_complete"])

    def test_oversized_whitespace_prefix_cannot_hide_the_rest_of_a_line(self):
        execute = mock.Mock()
        self.assertEqual(self.run_shell(" " * 12 + "echo forbidden\n", execute=execute, max_command_length=4), 2)
        execute.assert_not_called()

    def test_real_logger_requires_successful_sink_and_fsync_despite_best_effort_defaults(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for fail_at_sync in (False, True):
                with self.subTest(fail_at_sync=fail_at_sync):
                    logging = {"fail_closed": False, "sinks": [{"type": "jsonl", "path": str(root / "spool.jsonl")}]}
                    if not fail_at_sync:
                        logging["sinks"][0]["path"] = str(root)
                    logger = SessionLogger(str(root / "logs"), {"username": "alice"}, session_id="s1", logging_config=logging)
                    execute = mock.Mock()
                    patch = mock.patch("isolate_audit.os.fsync", side_effect=OSError("sync failed")) if fail_at_sync else mock.patch.dict(os.environ, {})
                    with patch, self.assertRaises(ManagedAuditError):
                        self.run_shell("echo forbidden\n", execute=execute, audit=logger)
                    execute.assert_not_called()

    def test_missing_trusted_identity_is_denied(self):
        self.metadata.pop("keycloak_sub")
        with self.assertRaises(ManagedAuditError):
            self.run_shell("id\n")

    def test_managed_mode_must_be_explicit_and_enabled(self):
        self.assertEqual(audit_mode({}), "target-hooks")
        with self.assertRaises(ManagedAuditError):
            audit_mode({"command_audit": {"mode": "managed", "enabled": False}})
        self.assertFalse(validate_config({"command_audit": {"mode": "managed", "enabled": False}})["valid"])

    def test_managed_ssh_explicitly_disables_tty_stdin_and_connection_reuse(self):
        argv = build_ssh_argv({"managed_commands": True}, {"hostname": "192.0.2.17"})
        for flag in ("-T", "-n", "StdinNull=yes", "RequestTTY=no", "ControlPath=none", "ForwardAgent=no", "ClearAllForwardings=yes"):
            self.assertIn(flag, argv)
        self.assertNotIn("-tt", argv)
        self.assertEqual(shlex.split(remote_command("echo 'one two'", "sudo-i")),
                         ["sudo", "-n", "-i", "--", "/bin/sh", "-c", "echo 'one two'"])

    @unittest.skipUnless(os.name == "posix", "Execute real POSIX shell commands")
    def test_real_commands_reach_shared_feed_with_signatures_and_actual_status(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            logs, spool = root / "logs", root / "spool"
            spool.mkdir()
            key = root / "key"
            key.write_bytes(b"test-key")
            cfg = {"integrity": {"enabled": True, "key_file": str(key)},
                   "sinks": [{"type": "jsonl", "path": str(spool / "audit.jsonl")}]}
            logger = SessionLogger(str(logs), {"username": "alice", "keycloak_sub": "kc-alice"},
                                   session_id="conn-1", logging_config=cfg)
            def execute(argv, raw, control, stdin_null):
                # Execute the exact remote command string locally as the SSH
                # server's command shell would. No real target host is needed.
                return subprocess.run(["/bin/sh", "-c", argv[-1]], stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).returncode
            text = "printf '%s' 'one two'; exit 7\nread ignored\n"
            self.assertEqual(self.run_shell(text, execute=execute, audit=logger), 0)
            with AuditExporter(logs, spool, spool / "events.jsonl", root / "state") as exporter:
                self.assertEqual(exporter.run_once()["exported"], 4)
            records = [json.loads(line) for line in (spool / "events.jsonl").read_text().splitlines()]
            self.assertTrue(all(verify_audit_record(record, b"test-key") for record in records))
            finished = [r for r in records if r["event"] == "command"]
            self.assertEqual([r["exitcode"] for r in finished], [7, 1])
            self.assertEqual(finished[0]["command"], "printf '%s' 'one two'; exit 7")
