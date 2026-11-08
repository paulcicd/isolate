"""Explicit, frozen-source Redis -> SQL migration and portable SQL snapshots.

No code here switches a running deployment's configuration. Operators must stop
all old writers/ingress and revoke their Redis ACL, then initialize/import/check
and deliberately deploy the SQL configuration. The Redis retirement marker is
an extra cooperative fence, never a substitute for fencing old binaries.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import time

from isolate_state import (AUTHORITY_KEY, FREEZE_KEY, SCHEMA_VERSION, SQLState,
    StateError, StateFrozen, _bytes, is_durable_key, key_text)


class MigrationError(StateError):
    pass


SNAPSHOT_LUA = """
local result = {}
local clock = redis.call('TIME')
table.insert(result, clock[1])
table.insert(result, clock[2])
for _, key in ipairs(redis.call('KEYS', '*')) do
  local kind = redis.call('TYPE', key).ok
  local value = ''
  if kind == 'string' then value = redis.call('GET', key) end
  table.insert(result, key)
  table.insert(result, kind)
  table.insert(result, value)
  table.insert(result, redis.call('PEXPIRETIME', key))
end
return result
"""


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _checksum(records):
    return hashlib.sha256(_json(records).encode()).hexdigest()


def _source_domain(key):
    return (is_durable_key(key) and key not in (FREEZE_KEY, AUTHORITY_KEY, "isolate_authority_epoch")
            and not key.startswith("isolate_ticket_"))


def source_snapshot(redis):
    """Take one atomic Redis 7+ string snapshot during maintenance.

    PEXPIRETIME preserves the source's absolute expiry rather than extending a
    ticket or a revocation's lifetime while importing. Existing connection
    tickets are intentionally excluded: cutover invalidates all of them.
    """
    try:
        result = redis.eval(SNAPSHOT_LUA, 0)
        captured = int(result[0]) + int(result[1]) / 1000000
        if (len(result) - 2) % 4:
            raise ValueError("malformed source snapshot")
        records = []
        for position in range(2, len(result), 4):
            key = key_text(result[position])
            if not _source_domain(key):
                continue
            kind = result[position + 1]
            if isinstance(kind, bytes):
                kind = kind.decode()
            if kind != "string":
                raise MigrationError("durable source contains a non-string record")
            expiry = int(result[position + 3])
            if expiry == -2:
                continue
            records.append({"key": key, "value_b64": base64.b64encode(_bytes(result[position + 2])).decode(),
                            "expires_at": expiry / 1000 if expiry >= 0 else None})
        records.sort(key=lambda row: row["key"])
        return {"captured_at": captured, "records": records, "checksum": _checksum(records)}
    except StateError:
        raise
    except Exception as exc:
        raise MigrationError("cannot take atomic Redis 7+ migration snapshot") from exc


def _fence_ack(ack):
    if not ack:
        raise MigrationError("stop/drain all ingress and workers and externally fence every legacy Redis writer first")


def freeze_source(redis, actor, external_fence=False):
    _fence_ack(external_fence)
    if not isinstance(actor, str) or not actor.strip():
        raise MigrationError("an identified migration actor is required")
    if redis.get(AUTHORITY_KEY) is not None:
        raise MigrationError("Redis authority has already been retired")
    record = {"migration_id": secrets.token_hex(16), "actor": actor.strip(), "frozen_at": int(time.time()),
              "external_writers_fenced": True}
    if not redis.set(FREEZE_KEY, _json(record), nx=True):
        raise MigrationError("a state migration freeze already exists; inspect it before proceeding")
    return record


def _freeze(redis):
    raw = redis.get(FREEZE_KEY)
    try:
        value = json.loads(raw) if raw is not None else None
        if (not isinstance(value, dict) or not value.get("migration_id")
                or value.get("external_writers_fenced") is not True):
            raise ValueError()
        return value
    except (ValueError, TypeError) as exc:
        raise MigrationError("source is not explicitly frozen for migration") from exc


def validate_counters(records):
    values = {record["key"]: base64.b64decode(record["value_b64"], validate=True) for record in records}
    counters = {"server_": "offset_server_id", "grant_": "offset_grant_id",
        "access_request_": "offset_access_request_id", "job_": "offset_job_id",
        "announcement_": "offset_announcement_id", "access_package_": "offset_access_package_id",
        "access_package_assignment_": "offset_access_package_assignment_id"}
    for prefix, offset in counters.items():
        identifiers = [int(key[len(prefix):]) for key in values if key.startswith(prefix) and key[len(prefix):].isdigit()]
        if identifiers:
            try:
                number = int(values.get(offset, b"0"))
            except ValueError as exc:
                raise MigrationError("source ID counter is invalid: " + offset) from exc
            if number < max(identifiers) or number >= 2 ** 63:
                raise MigrationError("source ID counter is behind its records: " + offset)


def plan_migration(redis, target=None):
    snapshot = source_snapshot(redis)
    validate_counters(snapshot["records"])
    result = {"dry_run": True, "record_count": len(snapshot["records"]), "checksum": snapshot["checksum"],
              "captured_at": snapshot["captured_at"], "tickets_invalidated_at_cutover": True,
              "source_frozen": redis.get(FREEZE_KEY) is not None}
    if target is not None:
        meta = target.metadata()
        result.update(target_generation=meta["generation"], target_status=meta["status"])
    return result


def _set_meta(conn, target, name, value):
    conn.execute("INSERT INTO isolate_state_meta(name,value) VALUES (" + target.marker + "," + target.marker +
        ") ON CONFLICT(name) DO UPDATE SET value=excluded.value", (name, str(value)))


def import_source(redis, target, external_fence=False):
    _fence_ack(external_fence)
    freeze = _freeze(redis)
    snapshot = source_snapshot(redis)
    validate_counters(snapshot["records"])
    with target.connection(write=True, require_active=False) as conn:
        # Serialize the entire import/cutover manifest independently of records.
        target._lock(conn, ["__isolate_state_migration__"])
        meta = target._check_schema(conn, require_active=False)
        if meta.get("status") == "active":
            raise MigrationError("target is already active; never import into live authority")
        previous = meta.get("migration_id")
        if previous:
            rows = conn.execute("SELECT key,value,expires_at FROM isolate_state_records WHERE value IS NOT NULL ORDER BY key").fetchall()
            current = [{"key": row["key"], "value_b64": base64.b64encode(bytes(row["value"])).decode(),
                        "expires_at": row["expires_at"]} for row in rows if _source_domain(row["key"])
                       and (row["expires_at"] is None or row["expires_at"] > snapshot["captured_at"])]
            if previous != freeze["migration_id"] or _checksum(current) != snapshot["checksum"]:
                raise MigrationError("target contains a different import; do not overwrite it")
            return {"imported": False, "idempotent": True, "record_count": len(snapshot["records"]),
                    "checksum": snapshot["checksum"], "generation": meta["generation"]}
        existing = conn.execute("SELECT COUNT(*) AS count FROM isolate_state_records").fetchone()["count"]
        if existing:
            raise MigrationError("target must be empty before the initial import")
        target._lock(conn, [record["key"] for record in snapshot["records"]])
        now = target._now(conn)
        for record in snapshot["records"]:
            target._put(conn, record["key"], base64.b64decode(record["value_b64"], validate=True), None,
                        now, record["expires_at"])
        for name, value in (("migration_id", freeze["migration_id"]), ("source_checksum", snapshot["checksum"]),
                ("source_snapshot_at", snapshot["captured_at"]), ("status", "imported")):
            _set_meta(conn, target, name, value)
    return {"imported": True, "record_count": len(snapshot["records"]), "checksum": snapshot["checksum"],
            "generation": meta["generation"]}


def _target_domain(target, captured_at):
    with target.connection(require_active=False) as conn:
        rows = conn.execute("SELECT key,value,expires_at FROM isolate_state_records WHERE value IS NOT NULL ORDER BY key").fetchall()
    return [{"key": row["key"], "value_b64": base64.b64encode(bytes(row["value"])).decode(),
             "expires_at": row["expires_at"]} for row in rows
            if _source_domain(row["key"]) and (row["expires_at"] is None or row["expires_at"] > captured_at)]


def verify_migration(redis, target):
    freeze = _freeze(redis)
    meta = target.metadata()
    if meta.get("migration_id") != freeze["migration_id"]:
        raise MigrationError("source freeze and target migration do not match")
    source = source_snapshot(redis)
    records = _target_domain(target, source["captured_at"])
    actual = _checksum(records)
    if actual != source["checksum"]:
        raise MigrationError("source and SQL checksum differ; keep ingress frozen")
    return {"verified": True, "record_count": len(records), "checksum": actual, "generation": meta["generation"]}


def cutover(redis, target, actor, external_fence=False):
    _fence_ack(external_fence)
    freeze = _freeze(redis)
    if not actor:
        raise MigrationError("an identified cutover actor is required")
    meta = target.metadata()
    raw = redis.get(AUTHORITY_KEY)
    if meta.get("status") == "active":
        if raw is not None and json.loads(raw).get("generation") == meta["generation"]:
            return {"active": True, "idempotent": True, "generation": meta["generation"]}
        raise MigrationError("active SQL target lacks the matching Redis retirement fence")
    if meta.get("status") != "imported":
        raise MigrationError("target must pass import before cutover")
    result = verify_migration(redis, target)
    marker = {"backend": target.backend, "generation": meta["generation"],
              "migration_id": freeze["migration_id"], "actor": str(actor), "cutover_at": int(time.time())}
    if raw is not None and json.loads(raw).get("generation") != meta["generation"]:
        raise MigrationError("Redis is retired to a different SQL authority")
    # Retire upgraded legacy readers before publishing SQL admission. A crash
    # between these writes leaves both routes closed and is safe to retry.
    redis.set(AUTHORITY_KEY, _json(marker))
    with target.connection(write=True, require_active=False) as conn:
        target._lock(conn, ["__isolate_state_migration__", "isolate_authority_epoch"])
        current = target._check_schema(conn, require_active=False)
        if current.get("migration_id") != freeze["migration_id"]:
            raise MigrationError("target migration changed before cutover")
        now = target._now(conn)
        target._put(conn, "isolate_authority_epoch", secrets.token_hex(32).encode(),
                    target._row(conn, "isolate_authority_epoch"), now)
        _set_meta(conn, target, "status", "active")
        _set_meta(conn, target, "cutover", _json(marker))
    return dict(result, active=True, deploy_sql_configuration=True)


def abort_migration(redis, target, external_fence=False):
    _fence_ack(external_fence)
    freeze = _freeze(redis)
    if redis.get(AUTHORITY_KEY) is not None:
        raise MigrationError("a retired authority cannot be automatically rolled back to Redis")
    with target.connection(write=True, require_active=False) as conn:
        target._lock(conn, ["__isolate_state_migration__"])
        meta = target._check_schema(conn, require_active=False)
        if meta.get("status") == "active":
            raise MigrationError("active SQL cannot be rolled back by unfreezing Redis")
        _set_meta(conn, target, "status", "aborted")
    if json.loads(redis.get(FREEZE_KEY) or "{}").get("migration_id") != freeze["migration_id"]:
        raise MigrationError("source freeze changed")
    redis.delete(FREEZE_KEY)
    return {"aborted": True}


def export_snapshot(target):
    with target.connection(require_active=False) as conn:
        meta = target._check_schema(conn, require_active=False)
        rows = conn.execute("SELECT key,value,revision,expires_at,updated_at FROM isolate_state_records ORDER BY key").fetchall()
        records = [{"key": row["key"], "value_b64": None if row["value"] is None else base64.b64encode(bytes(row["value"])).decode(),
                    "revision": int(row["revision"]), "expires_at": row["expires_at"], "updated_at": row["updated_at"]} for row in rows]
        payload = {"kind": "isolate-authoritative-state", "schema_version": SCHEMA_VERSION,
                   "metadata": meta, "created_at": target._now(conn), "records": records}
        payload["checksum"] = hashlib.sha256(_json(payload).encode()).hexdigest()
        return payload


def write_snapshot(target, path):
    payload = export_snapshot(target)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(os.path.abspath(path), flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(_json(payload) + "\n")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        os.unlink(path)
        raise
    return {"exported": True, "record_count": len(payload["records"]), "checksum": payload["checksum"]}


def read_snapshot(path):
    with open(path, encoding="utf-8") as source:
        payload = json.load(source)
    checksum = payload.pop("checksum", None)
    if (payload.get("kind") != "isolate-authoritative-state" or payload.get("schema_version") != SCHEMA_VERSION
            or checksum != hashlib.sha256(_json(payload).encode()).hexdigest()):
        raise MigrationError("SQL snapshot schema/checksum is invalid")
    seen = set()
    for record in payload.get("records", []):
        key = key_text(record["key"])
        if key in seen or not is_durable_key(key) or not isinstance(record.get("revision"), int) or record["revision"] <= 0:
            raise MigrationError("SQL snapshot contains invalid records")
        seen.add(key)
        if record["value_b64"] is not None:
            base64.b64decode(record["value_b64"], validate=True)
    return dict(payload, checksum=checksum)


def restore_snapshot(target, path, external_fence=False):
    _fence_ack(external_fence)
    payload = read_snapshot(path)
    with target.connection(write=True, require_active=False) as conn:
        target._lock(conn, ["__isolate_state_migration__"])
        meta = target._check_schema(conn, require_active=False)
        if meta.get("status") != "initialized" or conn.execute("SELECT COUNT(*) AS count FROM isolate_state_records").fetchone()["count"]:
            raise MigrationError("SQL restore requires a new, empty, inactive initialized target")
        for record in payload["records"]:
            conn.execute("INSERT INTO isolate_state_records(key,value,revision,expires_at,updated_at) VALUES (" +
                ",".join([target.marker] * 5) + ")", (record["key"], None if record["value_b64"] is None else
                    base64.b64decode(record["value_b64"], validate=True), record["revision"], record["expires_at"], record["updated_at"]))
        # Restores never reopen admission. The operator must rotate the epoch
        # and explicitly activate after reconciliation while all ingress drains.
        _set_meta(conn, target, "status", "restored")
        _set_meta(conn, target, "restore_checksum", payload["checksum"])
    return {"restored": True, "record_count": len(payload["records"]), "status": "restored"}


def activate_restored(target, actor, reason, external_fence=False):
    _fence_ack(external_fence)
    if not actor or not reason or len(str(reason)) > 1024:
        raise MigrationError("restore activation requires an actor and reconciliation reason")
    with target.connection(write=True, require_active=False) as conn:
        target._lock(conn, ["__isolate_state_migration__", "isolate_authority_epoch"])
        meta = target._check_schema(conn, require_active=False)
        if meta.get("status") != "restored":
            raise MigrationError("only a restored inactive target can be activated")
        now = target._now(conn)
        quarantined = 0
        rows = conn.execute("SELECT * FROM isolate_state_records WHERE key LIKE 'job_%' AND value IS NOT NULL").fetchall()
        for row in rows:
            if re.fullmatch(r"job_[0-9]+", row["key"]) is None:
                continue
            record = json.loads(bytes(row["value"]))
            if record.get("status") not in ("queued", "claimed", "running"):
                continue
            record.update(status="recovery_required", recovery_required_at=now,
                error="Restored execution state has an unknown remote outcome; inspect the target before submitting a new job")
            target._put(conn, row["key"], _json(record).encode(), row, now)
            claim_key = "job_execution_claim_" + str(record["id"])
            previous = target._row(conn, claim_key)
            if previous is None or previous["value"] is None:
                target._put(conn, claim_key, _json({"job_id": str(record["id"]), "claimed_at": now,
                    "owner": "restored-authority-quarantine", "recovery_required": True}).encode(), previous, now)
            quarantined += 1
        target._put(conn, "isolate_authority_epoch", secrets.token_hex(32).encode(), target._row(conn, "isolate_authority_epoch"), now)
        event_key = "recovery_event_" + secrets.token_hex(16)
        target._put(conn, event_key, _json({"event": "restored_authority_activated", "ts": now,
                    "actor": str(actor), "reason": str(reason), "quarantined_jobs": quarantined}).encode(), None, now)
        _set_meta(conn, target, "status", "active")
    return {"active": True, "epoch_rotated": True, "generation": meta["generation"], "quarantined_jobs": quarantined}
