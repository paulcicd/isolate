"""Common, backwards-compatible fields for structured command events."""

from datetime import datetime, timezone
import time


def command_fields(command, exit_code=None, at=None, **fields):
    at = time.time() if at is None else at
    fields.update(
        ts=at,
        timestamp=datetime.fromtimestamp(at, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        command=command,
        exitcode=exit_code,
        exit_code=exit_code,
        exit_code_known=exit_code is not None,
    )
    return fields
