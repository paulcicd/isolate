import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix", "Target shell hooks run on Linux")
class CommandAuditHooksTest(unittest.TestCase):
    def check_hook(self, shell, hook, callback):
        executable = shutil.which(shell)
        if executable is None:
            self.skipTest("{} is not installed".format(shell))
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            cwd = directory / "project's directory"
            cwd.mkdir()
            captured = directory / "ssh-argv.json"
            fake_ssh = directory / "ssh"
            fake_ssh.write_text("#!{}\nimport json, os, sys\nfrom pathlib import Path\n"
                                "Path(os.environ['CAPTURE']).write_text(json.dumps(sys.argv[1:]))\n".format(sys.executable))
            fake_ssh.chmod(0o700)
            command = "printf '%s\\n' 'hello world'; echo \"$HOME\"\necho `id`; # проверка"
            env = dict(os.environ, PATH=str(directory) + os.pathsep + os.environ["PATH"], CAPTURE=str(captured),
                       ISOLATE_CONNECTION_ID="connection-1", ISOLATE_AUDIT_BASTION="audit@bastion",
                       ISOLATE_HOST_ID="host-1", ISOLATE_PROJECT="project 'one'", TEST_COMMAND=command)
            script = '. {}; trap - DEBUG; __isolate_audit_last_command="$TEST_COMMAND"; {}; wait'.format(
                shlex.quote(str(ROOT / "scripts" / hook)), callback)
            subprocess.run([executable, "-c", script], cwd=str(cwd), env=env, check=True, timeout=5)
            deadline = time.monotonic() + 3
            while not captured.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            argv = json.loads(captured.read_text())
            self.assertEqual(argv[-3:-1], ["--", "audit@bastion"])
            remote = shlex.split(argv[-1])
            self.assertEqual(remote[:3], ["isolate", "command-log", "append"])
            fields = dict(arg[2:].split("=", 1) for arg in remote[3:])
            self.assertEqual(fields["command"], command)
            self.assertEqual(fields["cwd"], str(cwd))
            self.assertEqual(fields["project"], "project 'one'")
            self.assertEqual(fields["connection-id"], "connection-1")

    def test_bash_preserves_command_and_metadata_arguments(self):
        self.check_hook("bash", "target-command-audit.bash", "__isolate_audit_prompt")

    def test_zsh_preserves_command_and_metadata_arguments(self):
        self.check_hook("zsh", "target-command-audit.zsh", "__isolate_audit_precmd")


if __name__ == "__main__":
    unittest.main()
