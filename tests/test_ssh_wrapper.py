import importlib.util
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WRAPPER_PATH = os.path.join(ROOT, "wrappers", "ssh.py")
sys.path.insert(0, os.path.join(ROOT, "shared"))
# Load the cross-platform logger before the wrapper's Linux-only grp shim.
import isolate_logging
try:
    import grp
    INJECTED_GRP = False
except ImportError:
    INJECTED_GRP = True
if INJECTED_GRP:
    sys.modules["grp"] = SimpleNamespace(getgrnam=lambda _name: SimpleNamespace(gr_gid=0))
SPEC = importlib.util.spec_from_file_location("isolate_ssh_wrapper", WRAPPER_PATH)
ssh_wrapper = importlib.util.module_from_spec(SPEC)
PREVIOUS_CWD = os.getcwd()
try:
    SPEC.loader.exec_module(ssh_wrapper)
finally:
    os.chdir(PREVIOUS_CWD)
    if INJECTED_GRP:
        del sys.modules["grp"]


class RecordingAudit:
    def __init__(self):
        self.events = []

    def event(self, event_type, **fields):
        self.events.append((event_type, fields))


class SSHWrapperAuditTest(unittest.TestCase):
    def test_managed_session_rechecks_before_each_command_and_never_falls_back(self):
        config = {"command_audit": {"enabled": True, "mode": "managed"}}
        def managed(*argv, before_execute, control):
            for _ in range(3):
                self.assertFalse(before_execute())
            return 0
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ssh_wrapper, "run_managed_shell", side_effect=managed), \
                mock.patch.object(ssh_wrapper, "trusted_config", return_value=config), \
                mock.patch.object(ssh_wrapper, "recheck_connection") as recheck, \
                mock.patch.object(ssh_wrapper, "_run_pty_command") as pty, \
                mock.patch.object(ssh_wrapper, "_run_pipe_command") as pipe:
            self.assertEqual(ssh_wrapper.run_command(["ssh"], os.path.join(directory, "raw.log"), RecordingAudit(), {},
                             config=config, authorization={"deadline": 9999999999}), 0)
        self.assertEqual(recheck.call_count, 3)
        pty.assert_not_called()
        pipe.assert_not_called()

    def test_managed_audit_failure_closes_without_an_interactive_fallback(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ssh_wrapper, "run_managed_shell", side_effect=ssh_wrapper.ManagedAuditError("disk full")), \
                mock.patch.object(ssh_wrapper, "_run_pty_command") as pty, \
                mock.patch.object(ssh_wrapper, "_run_pipe_command") as pipe:
            result = ssh_wrapper.run_command(["ssh"], os.path.join(directory, "raw.log"), RecordingAudit(), {},
                         config={"command_audit": {"enabled": True, "mode": "managed"}})
        self.assertEqual(result, 2)
        pty.assert_not_called()
        pipe.assert_not_called()

    def test_revocation_closes_session_even_if_revocation_audit_fails(self):
        audit = RecordingAudit()
        original_event = audit.event
        def event(name, **fields):
            if name == "session_authorization_revoked":
                raise OSError("audit unavailable")
            original_event(name, **fields)
        audit.event = event
        def run(argv, raw_log, control):
            self.assertTrue(control())
            return 143
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ssh_wrapper, "_redis_client", return_value=object()), \
                mock.patch.object(ssh_wrapper, "mark_session_start", return_value={}), \
                mock.patch.object(ssh_wrapper, "initial_session_alerts", return_value=[]), \
                mock.patch.object(ssh_wrapper, "mark_session_end"), \
                mock.patch.object(ssh_wrapper, "trusted_config", return_value={}), \
                mock.patch.object(ssh_wrapper, "recheck_connection", side_effect=ssh_wrapper.ConnectionDenied("grant revoked")), \
                mock.patch.object(ssh_wrapper, "_run_pipe_command", side_effect=run), \
                mock.patch.object(ssh_wrapper, "_run_pty_command", side_effect=run):
            result = ssh_wrapper.run_command(["ssh"], os.path.join(directory, "raw.log"), audit,
                {"connection_id": "conn"}, config={"session_control": {}}, authorization={"deadline": 9999999999})
        self.assertEqual(result, 143)
        self.assertEqual(audit.events[-1][0], "ssh_end")

    def test_pipe_control_failure_does_not_leave_an_orphan_ssh_process(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        with mock.patch.object(ssh_wrapper.subprocess, "Popen", return_value=proc), \
                mock.patch.object(ssh_wrapper, "_terminate_child") as terminate:
            with self.assertRaises(RuntimeError):
                ssh_wrapper._run_pipe_command(["ssh"], mock.Mock(), control=mock.Mock(side_effect=RuntimeError("audit unavailable")))
        terminate.assert_called_once_with(proc)
        proc.stdout.close.assert_called_once()

    def test_exit_preserves_status_and_closes_session_for_pipe_and_pty(self):
        for is_tty in (False, True):
            for exit_code in (0, 1, 143):
                with self.subTest(is_tty=is_tty, exit_code=exit_code), tempfile.TemporaryDirectory() as directory:
                    audit = RecordingAudit()
                    raw_path = os.path.join(directory, "raw.log")
                    metadata = {"connection_id": "conn-1", "raw_log_path": "stale.log"}
                    with mock.patch.object(ssh_wrapper.sys.stdin, "isatty", return_value=is_tty), \
                            mock.patch.object(ssh_wrapper.sys.stdout, "isatty", return_value=is_tty), \
                            mock.patch.object(ssh_wrapper, "_run_pipe_command", return_value=exit_code), \
                            mock.patch.object(ssh_wrapper, "_run_pty_command", return_value=exit_code), \
                            mock.patch.object(ssh_wrapper, "_redis_client", return_value=object()), \
                            mock.patch.object(ssh_wrapper, "mark_session_start", return_value={}), \
                            mock.patch.object(ssh_wrapper, "initial_session_alerts", return_value=[]), \
                            mock.patch.object(ssh_wrapper, "mark_session_end") as end:
                        result = ssh_wrapper.run_command(["ssh", "example"], raw_path, audit, metadata, config={"session_control": {}})
                    self.assertEqual(result, exit_code)
                    self.assertEqual(audit.events[-1][1]["raw_log_path"], raw_path)
                    end.assert_called_once_with(mock.ANY, "conn-1", exit_code=exit_code)
                    self.assertEqual(metadata["raw_log_path"], "stale.log")

    def test_ssh_end_does_not_duplicate_raw_log_path(self):
        audit = RecordingAudit()
        metadata = {"connection_id": "conn-1", "raw_log_path": "stale.log"}
        with tempfile.NamedTemporaryFile(delete=False) as raw_log:
            raw_path = raw_log.name
        try:
            with mock.patch.object(ssh_wrapper, "_run_pipe_command", return_value=0), \
                    mock.patch.object(ssh_wrapper, "_run_pty_command", return_value=0):
                result = ssh_wrapper.run_command(["ssh", "example"], raw_path, audit, metadata)

            self.assertEqual(result, 0)
            self.assertEqual([name for name, _ in audit.events], ["ssh_start", "ssh_end"])
            self.assertEqual(audit.events[-1][1]["raw_log_path"], raw_path)
        finally:
            os.unlink(raw_path)


if __name__ == "__main__":
    unittest.main()
