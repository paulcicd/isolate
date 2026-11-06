"""Managed command input: audit durably before SSH exec, never forward stdin.

The scope is each submitted command string. This is not a syscall recorder or a
persistent remote shell; scripts and children are covered by their submitted
invocation, not expanded into individual source statements.
"""

import shlex
import sys
import time
import uuid

from isolate_command_events import command_fields


class ManagedAuditError(Exception):
    pass


def audit_mode(config):
    options = (config or {}).get("command_audit", {}) or {}
    if not isinstance(options, dict):
        raise ManagedAuditError("invalid command audit configuration")
    mode = options.get("mode", "target-hooks")
    if mode not in ("target-hooks", "managed"):
        raise ManagedAuditError("invalid command audit mode")
    if mode == "managed" and options.get("enabled", False) is not True:
        raise ManagedAuditError("managed command audit must be enabled")
    return mode


def remote_command(command, sudo_mode="none"):
    if sudo_mode not in ("none", "sudo-i"):
        raise ManagedAuditError("unsupported sudo mode")
    invocation = "/bin/sh -c " + shlex.quote(command)
    return "sudo -n -i -- " + invocation if sudo_mode == "sudo-i" else invocation


def run_managed_shell(argv, raw_log, audit, metadata, config, execute,
                      before_execute, control, input_stream=None, output_stream=None):
    options = config.get("command_audit", {}) or {}
    try:
        maximum = int(options.get("max_command_length", 4096))
        timeout = float(options.get("command_timeout_seconds", 300))
    except (TypeError, ValueError) as exc:
        raise ManagedAuditError("invalid managed command limits") from exc
    if not 1 <= maximum <= 4096 or not 0 <= timeout <= 86400:
        raise ManagedAuditError("invalid managed command limits")
    for field in ("username", "keycloak_sub", "host_id", "connection_id"):
        if not metadata.get(field):
            raise ManagedAuditError("managed audit requires trusted {}".format(field))
    source = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    output.write("Isolate managed commands: every submitted command is audited before execution.\n"
                 "Each command uses a new remote shell; cwd/environment reset between commands.\n"
                 "Remote stdin is closed: no interactive programs. Use exit or Ctrl+D to leave.\n")
    output.flush()
    sequence = 0

    def emit(name, command, at, **fields):
        values = dict(metadata)
        values.update(fields)
        values.update(source="isolate-managed", audit_scope="submitted_command", audit_complete=not fields.get("command_truncated", False),
                      stdin_policy="closed", cwd=None, cwd_policy="remote-home-per-command", shell="/bin/sh")
        try:
            return audit.event_durable(name, **command_fields(command, at=at, **values))
        except (Exception, KeyboardInterrupt) as exc:
            raise ManagedAuditError("cannot persist command audit; session closed") from exc

    while True:
        try:
            output.write("isolate> ")
            output.flush()
            # A bound prevents untrusted input from exhausting service memory.
            line = source.readline(maximum + 2)
        except KeyboardInterrupt:
            return 130
        if not line:
            return 0
        command = line[:-1] if line.endswith("\n") else line
        if command.endswith("\r"):
            command = command[:-1]
        if not command.strip() and len(command) <= maximum:
            continue
        sequence += 1
        captured = time.time()
        command_id = str(uuid.uuid4())
        common = {"command_id": command_id, "sequence": sequence, "submitted_at": captured}
        if len(command) > maximum or "\x00" in command:
            # Never execute a prefix or consume the remainder as another command.
            emit("command_rejected", command[:maximum], captured, **common,
                 command_status="rejected", reason="invalid_or_oversized_input",
                 command_truncated=len(command) > maximum)
            return 2
        emit("command_start", command, captured, **common, command_status="submitted", command_truncated=False)
        if before_execute():
            emit("command", command, captured, **common, command_status="denied", reason="authorization_or_session_revoked")
            return 143
        if command.strip() == "exit":
            emit("command", command, captured, **common, command_status="completed", exit_code=0,
                 execution_kind="session_exit", finished_at=time.time(), duration=0.0)
            return 0
        started = time.monotonic()
        interrupted = {"reason": None}

        def check_control():
            if control():
                interrupted["reason"] = "authorization_or_session_revoked"
            elif timeout and time.monotonic() - started >= timeout:
                interrupted["reason"] = "timeout"
            return interrupted["reason"] is not None

        try:
            result = execute(argv + [remote_command(command, metadata.get("sudo_mode", "none"))],
                             raw_log, control=check_control, stdin_null=True)
        except KeyboardInterrupt:
            interrupted["reason"] = "interrupted"
            result = None
        except OSError as exc:
            emit("command", command, captured, **common, command_status="launch_failed",
                 reason=type(exc).__name__, finished_at=time.time(), duration=round(time.monotonic() - started, 3))
            return 2
        known = result is not None and 0 <= result < 255 and not interrupted["reason"]
        emit("command", command, captured, **common,
             exit_code=result if known else None, ssh_returncode=result,
             command_status="completed" if known else "unknown",
             reason=interrupted["reason"] or (None if known else "ssh_error_or_remote_exit_255"),
             finished_at=time.time(), duration=round(time.monotonic() - started, 3),
             result_scope="ssh_remote_exec")
        if not known:
            return 143 if interrupted["reason"] else 255
