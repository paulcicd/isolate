"""Authoritative SQL state behind the existing Redis-shaped domain interface.

Domain values retain their current byte/JSON representation for rolling code
migration. PostgreSQL commits, not Redis cache updates, decide access. Only an
explicit list of disposable registry/lease/cache keys remains in Redis. Every
other key, including newly introduced domain keys, is durable by default.

WATCH is optimistic: it records SQL revisions and logical expiry. EXEC locks
all participating keys and compares those stamps before one SQL transaction.
Tombstones retain revisions, so delete/recreate and absent-key ABA are detected.
PostgreSQL advisory transaction locks also cover absent rows; a SELECT FOR
UPDATE on a missing row alone would not make SET NX or GETDEL atomic.
"""

import contextlib
import fnmatch
import hashlib
import json
import math
import os
import secrets
import sqlite3
import stat
import time
import uuid
from datetime import timedelta

from redis.exceptions import DataError, RedisError, WatchError


SCHEMA_VERSION = 1
FREEZE_KEY = "isolate_state_migration_freeze"
AUTHORITY_KEY = "isolate_state_authority"
EPHEMERAL_PREFIXES = ("active_session_", "isolate_session_owner_", "isolate_node_",
                      "host_check_", "complete_hosts_", "cache_")
EPHEMERAL_KEYS = frozenset(("projects_list",))


class StateError(RedisError):
    pass


class StateUnavailable(StateError):
    pass


class MixedStateTransaction(StateError):
    pass


class StateFrozen(StateError):
    pass


def key_text(key):
    if isinstance(key, bytes):
        key = key.decode("utf-8")
    elif isinstance(key, int) and not isinstance(key, bool):
        key = str(key)
    if not isinstance(key, str) or not key or len(key) > 4096 or "\x00" in key:
        raise DataError("state keys must be nonempty UTF-8 strings of at most 4096 characters")
    return key


def is_durable_key(key):
    key = key_text(key)
    return not (key in EPHEMERAL_KEYS or key.startswith(EPHEMERAL_PREFIXES))


def _bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value).encode("ascii")
    raise DataError("state values must be bytes, strings, or numbers")


def _seconds(value, milliseconds=False):
    if isinstance(value, timedelta):
        result = value.total_seconds()
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        result = float(value) / (1000 if milliseconds else 1)
    else:
        raise DataError("expiry must be a finite numeric duration")
    if not math.isfinite(result):
        raise DataError("expiry must be a finite numeric duration")
    return result


def _protected_dsn(path):
    if not path or not os.path.isabs(path):
        raise StateUnavailable("state.dsn_file must be an absolute protected file")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, encoding="utf-8") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or os.path.islink(path):
                raise StateUnavailable("state DSN must be a regular file")
            if os.name == "posix" and (info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o077):
                raise StateUnavailable("state DSN requires root/service ownership and private permissions")
            value = source.read(16385).strip()
            if not value or len(value) > 16384:
                raise StateUnavailable("state DSN file is empty or too large")
            return value
    except StateError:
        raise
    except (OSError, UnicodeError) as exc:
        raise StateUnavailable("cannot read state DSN") from exc


class SQLState:
    """Small key/value repository with SQL transactions and explicit schema init."""

    def __init__(self, options):
        self.options = dict(options or {})
        self.backend = self.options.get("backend", "postgresql")
        if self.backend not in ("postgresql", "sqlite"):
            raise StateError("SQL state backend must be postgresql or sqlite")
        self.marker = "%s" if self.backend == "postgresql" else "?"

    @contextlib.contextmanager
    def connection(self, write=False, require_active=True, check_schema=True):
        conn = None
        try:
            if self.backend == "postgresql":
                import psycopg
                from psycopg.rows import dict_row
                dsn = _protected_dsn(self.options.get("dsn_file"))
                if self.options.get("require_tls", True):
                    from psycopg.conninfo import conninfo_to_dict
                    info = conninfo_to_dict(dsn)
                    host = str(info.get("host", ""))
                    if (host and not host.startswith("/") or info.get("hostaddr")) and info.get("sslmode") != "verify-full":
                        raise StateUnavailable("network SQL authority requires sslmode=verify-full; only isolated tests may explicitly disable require_tls")
                tls_options = {"sslmode": "verify-full"} if self.options.get("require_tls", True) else {}
                conn = psycopg.connect(dsn, **tls_options,
                    connect_timeout=max(1, min(30, int(self.options.get("connect_timeout", 5)))),
                    row_factory=dict_row)
                conn.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                # Each operation obtains fresh committed rows after acquiring
                # key locks. All writers in this repository use the same locks.
                conn.execute("SET LOCAL lock_timeout = '5000ms'")
                conn.execute("SET LOCAL statement_timeout = '15000ms'")
                if write:
                    conn.execute("SET LOCAL synchronous_commit = 'on'")
            else:
                path = self.options.get("sqlite_path")
                if not path or not os.path.isabs(path) or path == ":memory:":
                    raise StateUnavailable("state.sqlite_path must be an absolute file path")
                if not check_schema:
                    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
                uri = "file:" + path.replace("\\", "/") + "?mode=rw" if check_schema else path
                conn = sqlite3.connect(uri, timeout=5, isolation_level=None, uri=check_schema)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA busy_timeout=5000")
                conn.execute("PRAGMA synchronous=FULL")
                conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            if check_schema:
                self._check_schema(conn, require_active=require_active)
            yield conn
            conn.commit()
        except (StateError, WatchError, DataError):
            if conn is not None:
                conn.rollback()
            raise
        except Exception as exc:
            if conn is not None:
                conn.rollback()
            # DSNs and connection errors can contain credentials. The public
            # exception is deliberately stable and never falls back to Redis.
            raise StateUnavailable("authoritative SQL state is unavailable") from exc
        finally:
            if conn is not None:
                conn.close()

    def _check_schema(self, conn, require_active=True):
        rows = conn.execute("SELECT name, value FROM isolate_state_meta").fetchall()
        meta = {row["name"]: row["value"] for row in rows}
        if meta.get("schema_version") != str(SCHEMA_VERSION):
            raise StateUnavailable("state schema is missing or incompatible; initialize explicitly")
        if require_active and meta.get("status") != "active":
            raise StateFrozen("SQL authority has not passed cutover checks")
        return meta

    def initialize(self, active=True):
        with self.connection(write=True, check_schema=False) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS isolate_state_meta (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
            existing = conn.execute("SELECT value FROM isolate_state_meta WHERE name='schema_version'").fetchone()
            if existing and existing["value"] != str(SCHEMA_VERSION):
                raise StateError("unsupported state schema version")
            value_type = "BYTEA" if self.backend == "postgresql" else "BLOB"
            conn.execute("CREATE TABLE IF NOT EXISTS isolate_state_records ("
                "key TEXT PRIMARY KEY, value " + value_type + ", revision BIGINT NOT NULL, "
                "expires_at DOUBLE PRECISION, updated_at DOUBLE PRECISION NOT NULL)")
            conn.execute("CREATE INDEX IF NOT EXISTS isolate_state_expiry ON isolate_state_records(expires_at)")
            defaults = {"schema_version": str(SCHEMA_VERSION), "generation": uuid.uuid4().hex,
                        "status": "active" if active else "initialized"}
            for name, value in defaults.items():
                conn.execute("INSERT INTO isolate_state_meta(name,value) VALUES (" + self.marker + "," + self.marker + ") "
                    "ON CONFLICT(name) DO NOTHING", (name, value))
            return self._check_schema(conn, require_active=False)

    def metadata(self):
        with self.connection(require_active=False) as conn:
            metadata = self._check_schema(conn, require_active=False)
            epoch = self._row(conn, "isolate_authority_epoch")
            if self._visible(epoch, self._now(conn)):
                metadata["epoch"] = bytes(epoch["value"]).decode()
            return metadata

    def _now(self, conn):
        if self.backend == "postgresql":
            return float(conn.execute("SELECT EXTRACT(EPOCH FROM clock_timestamp()) AS now").fetchone()["now"])
        return time.time()

    def _lock(self, conn, keys):
        if self.backend == "postgresql":
            for key in sorted(set(keys)):
                lock_id = int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big", signed=True)
                conn.execute("SELECT pg_advisory_xact_lock(" + self.marker + ")", (lock_id,))

    def _row(self, conn, key):
        return conn.execute("SELECT value,revision,expires_at FROM isolate_state_records WHERE key=" + self.marker, (key,)).fetchone()

    @staticmethod
    def _visible(row, now):
        return bool(row is not None and row["value"] is not None
                    and (row["expires_at"] is None or row["expires_at"] > now))

    def _stamp(self, row, now):
        return (int(row["revision"]) if row is not None else 0, self._visible(row, now))

    def _put(self, conn, key, value, row, now, expiry=None):
        revision = (int(row["revision"]) if row is not None else 0) + 1
        conn.execute("INSERT INTO isolate_state_records(key,value,revision,expires_at,updated_at) VALUES (" +
            ",".join([self.marker] * 5) + ") ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
            "revision=excluded.revision, expires_at=excluded.expires_at, updated_at=excluded.updated_at",
            (key, value, revision, expiry, now))

    def snapshot_key(self, key):
        key = key_text(key)
        with self.connection() as conn:
            row, now = self._row(conn, key), self._now(conn)
            return self._stamp(row, now)

    def get(self, key):
        key = key_text(key)
        with self.connection() as conn:
            row = self._row(conn, key)
            return bytes(row["value"]) if self._visible(row, self._now(conn)) else None

    def _apply(self, conn, operation, args, kwargs):
        key = key_text(args[0])
        row, now = self._row(conn, key), self._now(conn)
        visible = self._visible(row, now)
        if operation == "get":
            return bytes(row["value"]) if visible else None
        if operation == "set":
            value = _bytes(args[1])
            nx, xx = kwargs.get("nx", False), kwargs.get("xx", False)
            ex, px = kwargs.get("ex"), kwargs.get("px")
            if nx and xx or ex is not None and px is not None:
                raise DataError("SET options are mutually exclusive")
            expiry = None
            if ex is not None or px is not None:
                seconds = _seconds(ex if ex is not None else px, milliseconds=px is not None)
                if seconds <= 0:
                    raise DataError("SET expiry must be positive")
                expiry = now + seconds
            if nx and visible or xx and not visible:
                return None
            self._put(conn, key, value, row, now, expiry)
            return True
        if operation == "getdel":
            if not visible:
                return None
            value = bytes(row["value"])
            self._put(conn, key, None, row, now)
            return value
        if operation == "delete":
            if visible:
                self._put(conn, key, None, row, now)
            return int(visible)
        if operation == "incr":
            amount = args[1] if len(args) > 1 else 1
            if isinstance(amount, bool) or not isinstance(amount, int):
                raise DataError("increment must be an integer")
            try:
                raw = bytes(row["value"]) if visible else b"0"
                current = int(raw)
                if raw != str(current).encode():
                    raise ValueError()
            except ValueError as exc:
                raise DataError("value is not an integer") from exc
            result = current + amount
            if not -(2 ** 63) <= result < 2 ** 63:
                raise DataError("increment would overflow signed 64-bit integer")
            self._put(conn, key, str(result).encode(), row, now, row["expires_at"] if visible else None)
            return result
        if operation in ("expire", "pexpire"):
            if not visible:
                return False
            duration = _seconds(args[1], milliseconds=operation == "pexpire")
            self._put(conn, key, bytes(row["value"]) if duration > 0 else None, row, now,
                      now + duration if duration > 0 else None)
            return True
        if operation in ("pttl", "ttl"):
            if not visible:
                return -2
            if row["expires_at"] is None:
                return -1
            return max(0, int((row["expires_at"] - now) * (1000 if operation == "pttl" else 1)))
        raise StateError("unsupported SQL state operation")

    def execute(self, commands, watched=None, require_active=True):
        keys = set(watched or {})
        for operation, args, _ in commands:
            if operation == "delete":
                keys.update(key_text(key) for key in args)
            else:
                keys.add(key_text(args[0]))
        with self.connection(write=True, require_active=require_active) as conn:
            self._lock(conn, keys)
            now = self._now(conn)
            for key, stamp in (watched or {}).items():
                if self._stamp(self._row(conn, key), now) != stamp:
                    raise WatchError("authoritative state changed while watched")
            results = []
            for operation, args, kwargs in commands:
                if operation == "delete":
                    results.append(sum(self._apply(conn, operation, (key,), kwargs) for key in args))
                else:
                    results.append(self._apply(conn, operation, args, kwargs))
            return results

    def set(self, key, value, ex=None, px=None, nx=False, xx=False):
        return self.execute([("set", (key, value), {"ex": ex, "px": px, "nx": nx, "xx": xx})])[0]

    def getdel(self, key):
        return self.execute([("getdel", (key,), {})])[0]

    def incr(self, key, amount=1):
        return self.execute([("incr", (key, amount), {})])[0]

    def delete(self, *keys):
        return self.execute([("delete", keys, {})])[0] if keys else 0

    def expire(self, key, seconds):
        return self.execute([("expire", (key, seconds), {})])[0]

    def pexpire(self, key, milliseconds):
        return self.execute([("pexpire", (key, milliseconds), {})])[0]

    def pttl(self, key):
        return self.execute([("pttl", (key,), {})])[0]

    def ttl(self, key):
        return self.execute([("ttl", (key,), {})])[0]

    def scan_iter(self, match="*", count=1000):
        pattern = key_text(match)
        cursor = ""
        page = max(1, min(5000, int(count or 1000)))
        while True:
            with self.connection() as conn:
                now = self._now(conn)
                rows = conn.execute("SELECT key FROM isolate_state_records WHERE key>" + self.marker +
                    " AND value IS NOT NULL AND (expires_at IS NULL OR expires_at>" + self.marker +
                    ") ORDER BY key LIMIT " + self.marker, (cursor, now, page)).fetchall()
            if not rows:
                return
            for row in rows:
                cursor = row["key"]
                if fnmatch.fnmatchcase(cursor, pattern):
                    yield cursor.encode()
            if len(rows) < page:
                return

    def keys(self, pattern="*"):
        return list(self.scan_iter(pattern))

    def rotate_epoch(self):
        epoch = secrets.token_hex(32)
        self.set("isolate_authority_epoch", epoch)
        return epoch


class StateClient:
    """Route authoritative domain records to SQL and disposable keys to Redis."""

    def __init__(self, redis, options):
        self.redis = redis
        self.state = SQLState(options)
        self.state_backend = self.state.backend

    def get(self, key):
        return (self.state if is_durable_key(key) else self.redis).get(key)

    def set(self, key, value, **kwargs):
        return (self.state if is_durable_key(key) else self.redis).set(key, value, **kwargs)

    def getdel(self, key):
        return (self.state if is_durable_key(key) else self.redis).getdel(key)

    def incr(self, key, amount=1):
        return (self.state if is_durable_key(key) else self.redis).incr(key, amount)

    def delete(self, *keys):
        domains = {is_durable_key(key) for key in keys}
        if len(domains) > 1:
            raise MixedStateTransaction("atomic delete cannot mix SQL authority and Redis ephemeral keys")
        return (self.state if True in domains else self.redis).delete(*keys) if keys else 0

    def expire(self, key, seconds):
        return (self.state if is_durable_key(key) else self.redis).expire(key, seconds)

    def pexpire(self, key, milliseconds):
        return (self.state if is_durable_key(key) else self.redis).pexpire(key, milliseconds)

    def pttl(self, key):
        return (self.state if is_durable_key(key) else self.redis).pttl(key)

    def ttl(self, key):
        return (self.state if is_durable_key(key) else self.redis).ttl(key)

    def exists(self, *keys):
        return sum(self.get(key) is not None for key in keys)

    def scan_iter(self, match="*", count=1000, **kwargs):
        pattern = key_text(match)
        # Explicit ephemeral-only scans need not touch an unavailable SQL DB;
        # they are used for closing local streams and observing registry state.
        prefix = pattern
        for character in "*?[":
            prefix = prefix.split(character, 1)[0]
        ephemeral_only = any(prefix.startswith(item) for item in EPHEMERAL_PREFIXES) or pattern in EPHEMERAL_KEYS
        if not ephemeral_only:
            yield from self.state.scan_iter(pattern, count)
        redis_possible = (ephemeral_only or not prefix or any(item.startswith(prefix) for item in EPHEMERAL_PREFIXES)
                          or any(fnmatch.fnmatchcase(item, pattern) for item in EPHEMERAL_KEYS))
        if redis_possible:
            for key in self.redis.scan_iter(match=pattern, count=count, **kwargs):
                if not is_durable_key(key):
                    yield key

    def keys(self, pattern="*"):
        return list(self.scan_iter(pattern))

    def pipeline(self, transaction=True, **kwargs):
        return StatePipeline(self, transaction=transaction)

    def ping(self):
        self.state.metadata()
        with self.state.connection():
            pass
        return bool(self.redis.ping())

    def state_epoch(self):
        self.state.set("isolate_authority_epoch", secrets.token_hex(32), nx=True)
        raw = self.state.get("isolate_authority_epoch")
        if raw is None:
            raise StateUnavailable("state epoch is unavailable")
        return raw.decode()

    def metadata(self):
        return self.state.metadata()

    def close(self):
        if hasattr(self.redis, "close"):
            self.redis.close()

    def dump(self, key):
        if is_durable_key(key):
            raise StateError("SQL authority requires native PostgreSQL backup or isolate-state export, not Redis DUMP")
        return self.redis.dump(key)

    def eval(self, *args, **kwargs):
        raise StateError("Redis Lua cannot operate on authoritative SQL state")


class StatePipeline:
    def __init__(self, client, transaction=True):
        self.client, self.transaction = client, transaction
        self.domain = None
        self.watched = {}
        self.commands = []
        self.explicit_multi = False
        self.redis_pipeline = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.reset()

    def _route(self, keys):
        routes = {is_durable_key(key) for key in keys}
        if len(routes) > 1 or routes and self.domain is not None and self.domain not in routes:
            raise MixedStateTransaction("one atomic transaction cannot mix SQL authority and Redis ephemeral keys")
        if routes:
            self.domain = routes.pop()
        if self.domain is False and self.redis_pipeline is None:
            self.redis_pipeline = self.client.redis.pipeline(transaction=self.transaction)

    def watch(self, *keys):
        if self.explicit_multi or self.commands:
            raise StateError("WATCH must precede queued writes")
        self._route(keys)
        if self.domain is False:
            return self.redis_pipeline.watch(*keys)
        for key in keys:
            key = key_text(key)
            self.watched.setdefault(key, self.client.state.snapshot_key(key))
        return True

    def unwatch(self):
        if self.redis_pipeline is not None:
            self.redis_pipeline.unwatch()
        self.watched.clear()
        return True

    def multi(self):
        self.explicit_multi = True
        if self.redis_pipeline is not None:
            self.redis_pipeline.multi()
        return self

    def _command(self, operation, args, kwargs):
        self._route(args if operation == "delete" else args[:1])
        if self.domain is False:
            result = getattr(self.redis_pipeline, operation)(*args, **kwargs)
            return self if result is self.redis_pipeline else result
        if self.watched and not self.explicit_multi:
            if operation == "get":
                return self.client.state.get(args[0])
            if operation in ("pttl", "ttl"):
                return getattr(self.client.state, operation)(*args, **kwargs)
            raise StateError("writes in WATCH mode require MULTI")
        self.commands.append((operation, args, kwargs))
        return self

    def get(self, key):
        return self._command("get", (key,), {})

    def set(self, key, value, **kwargs):
        return self._command("set", (key, value), kwargs)

    def getdel(self, key):
        return self._command("getdel", (key,), {})

    def delete(self, *keys):
        return self._command("delete", keys, {})

    def incr(self, key, amount=1):
        return self._command("incr", (key, amount), {})

    def expire(self, key, seconds):
        return self._command("expire", (key, seconds), {})

    def pexpire(self, key, milliseconds):
        return self._command("pexpire", (key, milliseconds), {})

    def pttl(self, key):
        return self._command("pttl", (key,), {})

    def ttl(self, key):
        return self._command("ttl", (key,), {})

    def execute(self, raise_on_error=True):
        try:
            if self.domain is False:
                return self.redis_pipeline.execute(raise_on_error=raise_on_error)
            return self.client.state.execute(self.commands, self.watched)
        finally:
            self.reset()

    def reset(self):
        if self.redis_pipeline is not None:
            self.redis_pipeline.reset()
        self.domain = None
        self.watched.clear()
        self.commands.clear()
        self.explicit_multi = False
        self.redis_pipeline = None


class LegacyGuard:
    """Cooperative fence for upgraded legacy clients during explicit cutover.

    It cannot fence pre-upgrade/direct Redis clients: stop those writers and
    revoke their ACL before migration. The migration command requires explicit
    acknowledgement of that external fence.
    """

    state_backend = "redis"

    def __init__(self, redis):
        self.redis = redis

    def _check(self, keys, write=False):
        if any(is_durable_key(key) for key in keys):
            if self.redis.get(AUTHORITY_KEY) is not None:
                raise StateFrozen("Redis domain state was retired after SQL cutover")
            if self.redis.get(FREEZE_KEY) is not None:
                raise StateFrozen("domain access is frozen for state migration")

    def get(self, key):
        self._check((key,))
        return self.redis.get(key)

    def set(self, key, value, **kwargs):
        self._check((key,), write=True)
        return self.redis.set(key, value, **kwargs)

    def delete(self, *keys):
        self._check(keys, write=True)
        return self.redis.delete(*keys)

    def getdel(self, key):
        self._check((key,), write=True)
        return self.redis.getdel(key)

    def incr(self, key, amount=1):
        self._check((key,), write=True)
        return self.redis.incr(key, amount)

    def expire(self, key, seconds):
        self._check((key,), write=True)
        return self.redis.expire(key, seconds)

    def pexpire(self, key, milliseconds):
        self._check((key,), write=True)
        return self.redis.pexpire(key, milliseconds)

    def scan_iter(self, match="*", **kwargs):
        for key in self.redis.scan_iter(match=match, **kwargs):
            self._check((key,))
            yield key

    def keys(self, pattern="*"):
        keys = self.redis.keys(pattern)
        self._check(keys)
        return keys

    def pipeline(self, transaction=True, **kwargs):
        return LegacyPipeline(self, self.redis.pipeline(transaction=transaction, **kwargs))

    def eval(self, *args, **kwargs):
        self._check(("*",), write=True)
        return self.redis.eval(*args, **kwargs)

    def exists(self, *keys):
        self._check(keys)
        return self.redis.exists(*keys)

    def __getattr__(self, name):
        if name in ("pttl", "ttl", "ping", "close", "connection_pool", "dump", "info"):
            return getattr(self.redis, name)
        raise AttributeError(name)


class LegacyPipeline:
    def __init__(self, client, pipeline):
        self.client, self.pipeline = client, pipeline
        self.write_keys = []

    def __enter__(self):
        self.pipeline.__enter__()
        return self

    def __exit__(self, *args):
        return self.pipeline.__exit__(*args)

    def execute(self, *args, **kwargs):
        self.client._check(self.write_keys, write=True)
        return self.pipeline.execute(*args, **kwargs)

    def __getattr__(self, name):
        method = getattr(self.pipeline, name)
        if name not in ("get", "watch", "set", "incr", "delete", "getdel", "expire", "pexpire", "restore"):
            return method
        def checked(*args, **kwargs):
            keys = args if name in ("delete", "watch") else args[:1]
            write = name not in ("get", "watch")
            self.client._check(keys, write=write)
            if write:
                self.write_keys.extend(keys)
            result = method(*args, **kwargs)
            return self if result is self.pipeline else result
        return checked


def state_epoch(client):
    if isinstance(client, StateClient):
        return client.state_epoch()
    candidate = secrets.token_hex(32)
    client.set("isolate_authority_epoch", candidate, nx=True)
    raw = client.get("isolate_authority_epoch")
    if raw is None:
        raise StateUnavailable("state epoch is unavailable")
    return raw.decode() if isinstance(raw, bytes) else str(raw)
