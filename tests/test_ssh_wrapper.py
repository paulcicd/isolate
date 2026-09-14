import importlib.util
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WRAPPER_PATH = os.path.join(ROOT, "wrappers", "ssh.py")
INJECTED_GRP = "grp" not in sys.modules
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
