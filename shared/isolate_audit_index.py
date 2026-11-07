"""Idempotent SQL audit index. JSONL/PTY recordings remain the evidence source.

SQLite supports a single installation. PostgreSQL provides a shared index for
several nodes. Schema creation is explicit and versioned; a sink never silently
creates a production schema while processing an SSH connection.
"""

import contextlib
import json
import os
import sqlite3
import time


class AuditIndexError(ValueError):
    pass


def _redact(value):
    if isinstance(value, dict):
        return {k: ("[redacted]" if any(part in k.lower() for part in
                ("token", "password", "secret", "private_key")) else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


class AuditIndex:
    def __init__(self, options):
        self.options = options
        self.driver = options.get("driver", "sqlite")
        if self.driver not in ("sqlite", "postgresql"):
            raise AuditIndexError("unsupported audit index driver")
        self.marker = "?" if self.driver == "sqlite" else "%s"

    @contextlib.contextmanager
    def connection(self):
        if self.driver == "sqlite":
            path = self.options.get("path")
            if not path:
                raise AuditIndexError("audit index path is required")
            conn = sqlite3.connect(path, timeout=5)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=5000")
        else:
            import psycopg
            from psycopg.rows import dict_row
            # DSNs belong in a protected file, not CLI argv or API responses.
            with open(self.options["dsn_file"], encoding="utf-8") as source:
                dsn = source.read().strip()
            conn = psycopg.connect(dsn, connect_timeout=5, row_factory=dict_row)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def initialize(self):
        if self.driver == "sqlite":
            parent = os.path.dirname(self.options.get("path", ""))
            if parent:
                os.makedirs(parent, mode=0o750, exist_ok=True)
        with self.connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS isolate_audit_schema (version INTEGER PRIMARY KEY)")
            rows = db.execute("SELECT version FROM isolate_audit_schema").fetchall()
            if rows and any(row["version"] != 1 for row in rows):
                raise AuditIndexError("unsupported audit index schema version")
            db.execute("CREATE TABLE IF NOT EXISTS isolate_audit_events ("
                "event_id TEXT PRIMARY KEY, ts DOUBLE PRECISION NOT NULL, event TEXT NOT NULL, "
                "project TEXT NOT NULL, keycloak_sub TEXT NOT NULL, username TEXT NOT NULL, "
                "host_id TEXT NOT NULL, connection_id TEXT NOT NULL, search_text TEXT NOT NULL, payload TEXT NOT NULL)")
            for name, fields in (("time", "ts, event_id"), ("subject", "keycloak_sub, ts"),
                    ("project", "project, ts"), ("session", "connection_id, ts"), ("host", "host_id, ts")):
                db.execute("CREATE INDEX IF NOT EXISTS isolate_audit_{} ON isolate_audit_events ({})".format(name, fields))
            if self.driver == "sqlite":
                db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS isolate_audit_fts USING fts5(event_id UNINDEXED, search_text)")
                db.execute("INSERT OR IGNORE INTO isolate_audit_schema(version) VALUES (1)")
            else:
                db.execute("CREATE INDEX IF NOT EXISTS isolate_audit_text ON isolate_audit_events USING GIN (to_tsvector('simple', search_text))")
                db.execute("INSERT INTO isolate_audit_schema(version) VALUES (1) ON CONFLICT DO NOTHING")
        return {"schema_version": 1, "driver": self.driver}

    def ingest(self, record):
        if not isinstance(record, dict) or not record.get("event_id"):
            raise AuditIndexError("an audit event_id is required")
        record = _redact(record)
        payload = json.dumps(record, sort_keys=True, ensure_ascii=True)
        event_id = str(record["event_id"])
        values = (event_id, float(record.get("ts") or time.time()), str(record.get("event") or ""),
            str(record.get("project") or ""), str(record.get("keycloak_sub") or ""),
            str(record.get("username") or ""), str(record.get("host_id") or ""),
            str(record.get("connection_id") or record.get("session_id") or ""), payload, payload)
        with self.connection() as db:
            cursor = db.execute("INSERT INTO isolate_audit_events VALUES ({}) ON CONFLICT(event_id) DO NOTHING".format(
                ",".join([self.marker] * len(values))), values)
            if cursor.rowcount:
                if self.driver == "sqlite":
                    db.execute("INSERT INTO isolate_audit_fts(event_id, search_text) VALUES (?, ?)", (event_id, payload))
                return True
            row = db.execute("SELECT payload FROM isolate_audit_events WHERE event_id=" + self.marker, (event_id,)).fetchone()
            if row["payload"] != payload:
                raise AuditIndexError("audit event_id collision with different content")
        return False

    def search(self, *, subject=None, projects=None, query=None, event=None, host_id=None,
               connection_id=None, since=None, until=None, before=None, limit=100):
        conditions, params = [], []
        p = self.marker
        # projects=None means unrestricted. [] explicitly grants no projects;
        # subject may still grant access to the caller's own events.
        visibility, visible_params = [], []
        if subject:
            visibility.append("keycloak_sub=" + p)
            visible_params.append(subject)
        if projects is not None:
            if projects:
                visibility.append("project IN ({})".format(",".join([p] * len(projects))))
                visible_params.extend(projects)
            conditions.append("(" + " OR ".join(visibility or ["1=0"]) + ")")
            params.extend(visible_params)
        elif subject:
            conditions.append(visibility[0])
            params.extend(visible_params)
        for name, value in (("event", event), ("host_id", host_id), ("connection_id", connection_id)):
            if value is not None:
                conditions.append(name + "=" + p)
                params.append(str(value))
        for op, value in ((">=", since), ("<=", until)):
            if value is not None:
                conditions.append("ts" + op + p)
                params.append(float(value))
        if before:
            timestamp, event_id = before
            conditions.append("(ts<" + p + " OR (ts=" + p + " AND event_id<" + p + "))")
            params.extend([float(timestamp), float(timestamp), str(event_id)])
        if query:
            if len(query) > 256:
                raise AuditIndexError("search query is too long")
            # Quote tokens, so FTS operators cannot turn an ordinary user query
            # into arbitrary SQLite syntax. PostgreSQL plainto_tsquery is data.
            if self.driver == "sqlite":
                words = query.split()
                match = " AND ".join('"' + word.replace('"', '""') + '"' for word in words)
                conditions.append("event_id IN (SELECT event_id FROM isolate_audit_fts WHERE search_text MATCH ?)")
                params.append(match or '""')
            else:
                conditions.append("to_tsvector('simple', search_text) @@ plainto_tsquery('simple', " + p + ")")
                params.append(query)
        maximum = min(500, max(1, int(limit)))
        params.append(maximum + 1)
        with self.connection() as db:
            rows = db.execute("SELECT event_id, ts, payload FROM isolate_audit_events" +
                (" WHERE " + " AND ".join(conditions) if conditions else "") +
                " ORDER BY ts DESC, event_id DESC LIMIT " + p, params).fetchall()
        more = len(rows) > maximum
        rows = rows[:maximum]
        return {"events": [json.loads(row["payload"]) for row in rows],
                "next": [rows[-1]["ts"], rows[-1]["event_id"]] if more and rows else None}

    def projects(self):
        with self.connection() as db:
            return [row["project"] for row in db.execute("SELECT DISTINCT project FROM isolate_audit_events WHERE project<>''").fetchall()]

    def import_jsonl(self, path):
        imported = 0
        with open(path, encoding="utf-8") as source:
            for line in source:
                if line.strip():
                    imported += int(self.ingest(json.loads(line)))
        return imported
