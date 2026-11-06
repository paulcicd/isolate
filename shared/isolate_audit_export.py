#!/usr/bin/env python3
"""Export retained audit events to one JSONL feed with durable read positions.

Source files remain authoritative. Checkpoints commit only after output fsync:
a crash in between can repeat events, but cannot acknowledge unwritten output.
No parsing of raw terminal recordings and no changes to signed event contents.
"""

import argparse
import contextlib
import gzip
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import signal
import sqlite3
import stat
import time


LOG = logging.getLogger("isolate-audit-export")
MAX_LINE = 1024 * 1024


class AuditExportError(Exception):
    pass


def _open_regular(path, flags, mode=0o640):
    fd = os.open(str(path), flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0), mode)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise AuditExportError("not a regular file: {}".format(path))
    return fd


def _write_all(fd, payload):
    view = memoryview(payload)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError("short audit feed write")
        view = view[count:]


class AuditExporter:
    def __init__(self, logs, spool, output, state, batch_size=1000):
        self.logs = Path(logs).resolve()
        self.spool = Path(spool).resolve()
        self.output = Path(output).absolute()
        self.state = Path(state).absolute()
        self.batch_size = batch_size
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        if self.output.parent.resolve() == self.spool and self.output.name.startswith("audit.jsonl"):
            raise AuditExportError("output must not overlap the runtime audit.jsonl source")
        self.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock_fd = _open_regular(self.state / "export.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            # Deployment target is Linux; one owner must hold the state/feed.
            if os.name == "posix":
                import fcntl
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:  # Windows development/test environment
                import msvcrt
                os.lseek(self.lock_fd, 0, os.SEEK_SET)
                msvcrt.locking(self.lock_fd, msvcrt.LK_NBLCK, 1)
            self.db = sqlite3.connect(str(self.state / "positions.sqlite3"))
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("CREATE TABLE IF NOT EXISTS positions ("
                            "path TEXT PRIMARY KEY, device TEXT, inode TEXT, "
                            "offset INTEGER, size INTEGER, mtime INTEGER)")
            self.db.execute("CREATE TABLE IF NOT EXISTS exported (digest TEXT PRIMARY KEY)")
            self.db.commit()
            self._repair_output_tail()
        except Exception:
            self.close()
            raise

    def close(self):
        if getattr(self, "db", None) is not None:
            self.db.close()
            self.db = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _repair_output_tail(self):
        fd = _open_regular(self.output, os.O_RDWR | os.O_CREAT)
        try:
            size = os.lseek(fd, 0, os.SEEK_END)
            end = size
            while end:
                start = max(0, end - 65536)
                os.lseek(fd, start, os.SEEK_SET)
                chunk = os.read(fd, end - start)
                newline = chunk.rfind(b"\n")
                if newline >= 0:
                    end = start + newline + 1
                    break
                end = start
            if end != size:
                LOG.warning("Removing %s incomplete bytes from audit feed tail", size - end)
                os.ftruncate(fd, end)
                os.fsync(fd)
        finally:
            os.close(fd)

    def sources(self):
        candidates = list(self.logs.glob("*/*/session.jsonl"))
        candidates += list(self.spool.glob("audit.jsonl*"))
        for path in sorted(candidates):
            if path.name != "session.jsonl" and not re.fullmatch(r"audit\.jsonl(?:\.\d+(?:\.gz)?)?", path.name):
                continue
            root = self.logs if path.name == "session.jsonl" else self.spool
            # Never follow a session directory/file symlink to another source.
            relative = path.relative_to(root)
            if any((root / Path(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts) + 1)):
                LOG.error("Ignoring audit source symlink: %s", path)
                continue
            if path.is_file():
                yield path

    def _open_source(self, path):
        if os.name != "posix":
            return _open_regular(path, os.O_RDONLY)
        root = self.logs if path.name == "session.jsonl" else self.spool
        parts = path.relative_to(root).parts
        directory = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise AuditExportError("not a regular file: {}".format(path))
            return fd
        finally:
            os.close(directory)

    def _read_batch(self, path):
        fd = self._open_source(path)
        with contextlib.ExitStack() as stack:
            raw = stack.enter_context(os.fdopen(fd, "rb"))
            info = os.fstat(raw.fileno())
            saved = self.db.execute("SELECT device, inode, offset, size, mtime FROM positions WHERE path=?",
                                    (str(path),)).fetchone()
            compressed = path.suffix == ".gz"
            offset = 0
            if saved and saved[:2] == (str(info.st_dev), str(info.st_ino)):
                if saved[3:] == (info.st_size, info.st_mtime_ns):
                    return None
                if compressed or info.st_size >= saved[2]:
                    offset = saved[2]
            stream = stack.enter_context(gzip.GzipFile(fileobj=raw)) if compressed else raw
            stream.seek(offset)
            records = []
            for _ in range(self.batch_size):
                line = stream.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE:
                    raise AuditExportError("audit record exceeds size limit at {}:{}".format(path, offset))
                if not line.endswith(b"\n"):
                    break  # A writer may still be completing this record.
                if line.strip():
                    try:
                        record = json.loads(line)
                        if not isinstance(record, dict) or not isinstance(record.get("event"), str):
                            raise ValueError("missing event")
                        payload = json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
                    except (ValueError, UnicodeError, RecursionError) as exc:
                        # Do not print event contents: commands may contain secrets.
                        raise AuditExportError("invalid audit record at {}:{}".format(path, offset)) from exc
                    if len(payload) > 60 * 1024:
                        LOG.warning("Audit record exceeds 60 KiB; check SIEM message limits at %s:%s", path, offset)
                    records.append((hashlib.sha256(payload).hexdigest(), payload + b"\n"))
                offset = stream.tell()
            # A full batch must be revisited even when the source stat is unchanged.
            reached_end = not stream.peek(1) if hasattr(stream, "peek") else False
            return info, offset, records, reached_end

    def _publish(self, path, batch):
        info, offset, records, reached_end = batch
        sent = 0
        with self.db:
            fd = _open_regular(self.output, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
            try:
                for digest, payload in records:
                    if self.db.execute("INSERT OR IGNORE INTO exported VALUES (?)", (digest,)).rowcount:
                        _write_all(fd, payload)
                        sent += 1
                os.fsync(fd)
            finally:
                os.close(fd)
            self.db.execute("INSERT OR REPLACE INTO positions VALUES (?, ?, ?, ?, ?, ?)",
                            (str(path), str(info.st_dev), str(info.st_ino), offset,
                             info.st_size if reached_end else -1, info.st_mtime_ns))
        return sent

    def run_once(self):
        sent, errors = 0, 0
        for path in self.sources():
            try:
                batch = self._read_batch(path)
            except FileNotFoundError:  # Retention/rotation raced with discovery.
                continue
            except (OSError, ValueError, AuditExportError) as exc:
                LOG.error("Cannot read audit source: %s", exc)
                errors += 1
                continue
            if batch is not None:
                # Output/DB errors are fatal: restart repairs any incomplete tail.
                sent += self._publish(path, batch)
        return {"exported": sent, "errors": errors}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs", default="/opt/auth/logs")
    parser.add_argument("--spool", default="/opt/auth/spool")
    parser.add_argument("--output", default="/opt/auth/spool/events.jsonl")
    parser.add_argument("--state", default="/var/lib/isolate/audit-export")
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if args.interval <= 0:
        parser.error("--interval must be positive")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with AuditExporter(args.logs, args.spool, args.output, args.state) as exporter:
        while not stopping:
            result = exporter.run_once()
            if args.once:
                print(json.dumps(result))
                return 1 if result["errors"] else 0
            time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
