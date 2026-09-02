#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Portable, verifiable backups for Isolate runtime state."""

import base64
import datetime
import glob
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import tarfile
import time
import uuid


BACKUP_KIND = "isolate-service-backup"
BACKUP_SCHEMA_VERSION = 1
REDIS_SNAPSHOT_LUA = r"""
local seen = {}
local result = {}
for _, pattern in ipairs(ARGV) do
  for _, key in ipairs(redis.call('KEYS', pattern)) do
    if not seen[key] then
      seen[key] = true
      local payload = redis.call('DUMP', key)
      local ttl = redis.call('PTTL', key)
      if payload then
        table.insert(result, key)
        table.insert(result, tostring(ttl))
        table.insert(result, payload)
      end
    end
  end
end
return result
"""


class BackupError(Exception):
    pass


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source_f:
        while True:
            chunk = source_f.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


def _archive_parts(path):
    absolute = os.path.abspath(path)
    drive, tail = os.path.splitdrive(absolute)
    parts = []
    if drive:
        parts.append(drive.rstrip(":/\\"))
    normalized = tail.replace("\\", "/").lstrip("/")
    parts.extend(part for part in normalized.split("/") if part)
    if not parts or any(part in (".", "..") for part in parts):
        raise BackupError("unsafe backup path: {}".format(path))
    return parts


def _archive_name(path, directory=False):
    name = "files/{}".format("/".join(_archive_parts(path)))
    return name.rstrip("/") + ("/" if directory else "")


def _path_spec(spec):
    if isinstance(spec, str):
        return spec, False
    if not isinstance(spec, dict) or not spec.get("path"):
        raise BackupError("backup.paths entries must be paths or objects with path")
    return str(spec["path"]), bool(spec.get("required", False))


def _iter_backup_paths(path_specs):
    files = {}
    directories = {}
    warnings = []
    for spec in path_specs:
        source, required = _path_spec(spec)
        source = os.path.abspath(source)
        if not os.path.lexists(source):
            if required:
                raise BackupError("required backup path does not exist: {}".format(source))
            warnings.append("optional path missing: {}".format(source))
            continue
        if os.path.islink(source):
            warnings.append("symlink skipped: {}".format(source))
            continue
        if os.path.isfile(source):
            if not os.access(source, os.R_OK):
                if required:
                    raise BackupError("required backup path is not readable: {}".format(source))
                warnings.append("optional path unreadable: {}".format(source))
                continue
            files[source] = None
            continue
        if not os.path.isdir(source):
            warnings.append("unsupported path skipped: {}".format(source))
            continue
        if not os.access(source, os.R_OK | os.X_OK):
            if required:
                raise BackupError("required backup path is not readable: {}".format(source))
            warnings.append("optional path unreadable: {}".format(source))
            continue
        def walk_error(exc):
            if required:
                raise BackupError("required backup path cannot be traversed: {}".format(exc))
            warnings.append("optional path cannot be traversed: {}".format(exc))

        for current_root, dirnames, filenames in os.walk(source, followlinks=False, onerror=walk_error):
            safe_dirs = []
            for dirname in dirnames:
                candidate = os.path.join(current_root, dirname)
                if os.path.islink(candidate):
                    warnings.append("symlink skipped: {}".format(candidate))
                else:
                    safe_dirs.append(dirname)
            dirnames[:] = safe_dirs
            directories[current_root] = None
            for filename in filenames:
                candidate = os.path.join(current_root, filename)
                if os.path.islink(candidate):
                    warnings.append("symlink skipped: {}".format(candidate))
                elif os.path.isfile(candidate):
                    if os.access(candidate, os.R_OK):
                        files[candidate] = None
                    elif required:
                        raise BackupError("required backup file is not readable: {}".format(candidate))
                    else:
                        warnings.append("optional file unreadable: {}".format(candidate))
    return sorted(files), sorted(directories), warnings


def _redis_snapshot_fallback(redis, patterns, created_at_ms):
    keys = set()
    for pattern in patterns:
        keys.update(redis.keys(pattern))
    records = []
    for key in sorted(keys, key=_as_bytes):
        payload = redis.dump(key)
        if payload is None:
            continue
        ttl = int(redis.pttl(key)) if hasattr(redis, "pttl") else -1
        records.append(_redis_record(key, ttl, payload, created_at_ms))
    return records


def _redis_record(key, ttl_ms, payload, created_at_ms):
    key_bytes = _as_bytes(key)
    payload_bytes = _as_bytes(payload)
    return {
        "key": key_bytes.decode("utf-8", errors="replace"),
        "key_b64": base64.b64encode(key_bytes).decode("ascii"),
        "dump_b64": base64.b64encode(payload_bytes).decode("ascii"),
        "expire_at_ms": created_at_ms + ttl_ms if ttl_ms >= 0 else None,
    }


def snapshot_redis(redis, patterns, created_at_ms=None):
    created_at_ms = int(created_at_ms if created_at_ms is not None else time.time() * 1000)
    warnings = []
    try:
        raw = redis.eval(REDIS_SNAPSHOT_LUA, 0, *patterns)
        if len(raw) % 3:
            raise BackupError("Redis snapshot returned malformed data")
        records = [
            _redis_record(raw[index], int(_as_bytes(raw[index + 1])), raw[index + 2], created_at_ms)
            for index in range(0, len(raw), 3)
        ]
        consistent = True
    except Exception as exc:
        records = _redis_snapshot_fallback(redis, patterns, created_at_ms)
        consistent = False
        warnings.append("atomic Redis snapshot unavailable; used key-by-key fallback: {}".format(exc))
    records.sort(key=lambda item: item["key_b64"])
    return {
        "schema_version": 1,
        "created_at_ms": created_at_ms,
        "patterns": list(patterns),
        "consistent": consistent,
        "key_count": len(records),
        "records": records,
    }, warnings


def _tar_add_bytes(archive, name, data, mode=0o600):
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(time.time())
    archive.addfile(info, io.BytesIO(data))


def _file_entry(path):
    stat_result = os.stat(path, follow_symlinks=False)
    return {
        "source": path,
        "archive_path": _archive_name(path),
        "size": stat_result.st_size,
        "sha256": _sha256_file(path),
        "mode": stat_result.st_mode & 0o7777,
        "uid": getattr(stat_result, "st_uid", None),
        "gid": getattr(stat_result, "st_gid", None),
        "mtime": stat_result.st_mtime,
    }


def _directory_entry(path):
    stat_result = os.stat(path, follow_symlinks=False)
    return {
        "source": path,
        "archive_path": _archive_name(path, directory=True),
        "mode": stat_result.st_mode & 0o7777,
        "uid": getattr(stat_result, "st_uid", None),
        "gid": getattr(stat_result, "st_gid", None),
        "mtime": stat_result.st_mtime,
    }


def _git_revision(data_root):
    try:
        return subprocess.check_output(
            ["git", "-C", data_root, "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        ).strip()
    except Exception:
        return None


def _apply_archive_permissions(path, backup_config):
    if os.name == "posix":
        os.chmod(path, 0o600)
        try:
            import grp
            import pwd

            uid = pwd.getpwnam(backup_config.get("owner", "auth")).pw_uid
            gid = grp.getgrnam(backup_config.get("group", "auth")).gr_gid
            os.chown(path, uid, gid)
        except (KeyError, PermissionError):
            pass


def _prune_archives(base_path, retention_count):
    archives = sorted(
        glob.glob(os.path.join(base_path, "isolate-backup-*.tar.gz")),
        key=lambda path: os.path.getmtime(path),
        reverse=True,
    )
    removed = []
    for archive in archives[max(int(retention_count), 1):]:
        os.remove(archive)
        checksum_path = archive + ".sha256"
        if os.path.isfile(checksum_path):
            os.remove(checksum_path)
        removed.append(archive)
    return removed


def create_backup(config, redis, output_path=None, include_logs=None):
    backup_cfg = config.get("backup", {})
    base_path = os.path.abspath(backup_cfg.get("base_path") or os.path.join(config.get("data_root", "/opt/auth"), "backups", "service"))
    os.makedirs(base_path, mode=0o700, exist_ok=True)
    include_logs = backup_cfg.get("include_logs", False) if include_logs is None else bool(include_logs)
    path_specs = list(backup_cfg.get("paths") or [])
    if include_logs:
        path_specs.append({"path": config.get("logging", {}).get("base_path"), "required": False})
        spool_path = os.path.join(config.get("data_root", "/opt/auth"), "spool")
        path_specs.append({"path": spool_path, "required": False})

    created = _utc_now()
    stamp = created.strftime("%Y%m%dT%H%M%S%fZ")
    final_path = os.path.abspath(output_path or os.path.join(base_path, "isolate-backup-{}.tar.gz".format(stamp)))
    if not final_path.endswith(".tar.gz"):
        raise BackupError("backup output must end with .tar.gz")
    if os.path.exists(final_path):
        raise BackupError("backup output already exists: {}".format(final_path))
    os.makedirs(os.path.dirname(final_path), mode=0o700, exist_ok=True)
    temp_path = os.path.join(os.path.dirname(final_path), ".isolate-backup-{}.tmp".format(uuid.uuid4().hex))

    redis_snapshot, redis_warnings = snapshot_redis(redis, backup_cfg.get("redis_patterns") or [])
    files, directories, path_warnings = _iter_backup_paths(path_specs)
    redis_data = json.dumps(redis_snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
    file_entries = [_file_entry(path) for path in files]
    directory_entries = [_directory_entry(path) for path in directories]
    manifest = {
        "kind": BACKUP_KIND,
        "schema_version": BACKUP_SCHEMA_VERSION,
        "created_at": created.isoformat(),
        "created_at_epoch": created.timestamp(),
        "hostname": socket.gethostname(),
        "data_root": config.get("data_root", "/opt/auth"),
        "git_revision": _git_revision(config.get("data_root", "/opt/auth")),
        "include_logs": include_logs,
        "redis": {
            "member": "redis.json",
            "sha256": _sha256_bytes(redis_data),
            "key_count": redis_snapshot["key_count"],
            "consistent": redis_snapshot["consistent"],
            "patterns": redis_snapshot["patterns"],
        },
        "files": file_entries,
        "directories": directory_entries,
        "warnings": redis_warnings + path_warnings,
    }
    manifest_data = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

    try:
        with tarfile.open(temp_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            _tar_add_bytes(archive, "manifest.json", manifest_data)
            _tar_add_bytes(archive, "redis.json", redis_data)
            for entry in directory_entries:
                info = tarfile.TarInfo(name=entry["archive_path"])
                info.type = tarfile.DIRTYPE
                info.mode = entry["mode"]
                info.mtime = int(entry["mtime"])
                archive.addfile(info)
            for entry in file_entries:
                archive.add(entry["source"], arcname=entry["archive_path"], recursive=False)
        os.replace(temp_path, final_path)
        _apply_archive_permissions(final_path, backup_cfg)
        archive_hash = _sha256_file(final_path)
        checksum_path = final_path + ".sha256"
        with open(checksum_path, "w", encoding="ascii") as checksum_f:
            checksum_f.write("{}  {}\n".format(archive_hash, os.path.basename(final_path)))
        _apply_archive_permissions(checksum_path, backup_cfg)
        removed = _prune_archives(base_path, int(backup_cfg.get("retention_count", 14)))
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise

    return {
        "archive": final_path,
        "checksum": archive_hash,
        "file_count": len(file_entries),
        "redis_key_count": redis_snapshot["key_count"],
        "redis_consistent": redis_snapshot["consistent"],
        "include_logs": include_logs,
        "warnings": manifest["warnings"],
        "pruned": removed,
    }


def _safe_member_name(name):
    normalized = name.replace("\\", "/")
    return bool(normalized and not normalized.startswith("/") and ".." not in normalized.split("/"))


def read_backup_manifest(archive_path):
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            member = archive.getmember("manifest.json")
            if not member.isfile() or not _safe_member_name(member.name):
                raise BackupError("backup manifest member is unsafe")
            manifest_f = archive.extractfile(member)
            if manifest_f is None:
                raise BackupError("backup manifest is unreadable")
            manifest = json.load(manifest_f)
    except (OSError, KeyError, tarfile.TarError, ValueError) as exc:
        raise BackupError("cannot read backup manifest: {}".format(exc))
    try:
        schema_version = int(manifest.get("schema_version", 0))
    except (TypeError, ValueError):
        schema_version = 0
    if manifest.get("kind") != BACKUP_KIND or schema_version != BACKUP_SCHEMA_VERSION:
        raise BackupError("unsupported backup format")
    redis_meta = manifest.get("redis")
    if not isinstance(redis_meta, dict) or not redis_meta.get("member") or not redis_meta.get("sha256"):
        raise BackupError("backup manifest has invalid Redis metadata")
    if not _safe_member_name(str(redis_meta["member"])):
        raise BackupError("backup manifest has unsafe Redis member")
    for collection in ("files", "directories"):
        entries = manifest.get(collection) or []
        if not isinstance(entries, list):
            raise BackupError("backup manifest {} must be a list".format(collection))
        for entry in entries:
            if not isinstance(entry, dict) or not entry.get("source") or not entry.get("archive_path"):
                raise BackupError("backup manifest has invalid {} entry".format(collection))
            if not _safe_member_name(str(entry["archive_path"])):
                raise BackupError("backup manifest has unsafe {} entry".format(collection))
    return manifest


def verify_backup(archive_path):
    archive_path = os.path.abspath(archive_path)
    manifest = read_backup_manifest(archive_path)
    errors = []
    expected_members = {"manifest.json", manifest["redis"]["member"]}
    expected_members.update(entry["archive_path"].rstrip("/") for entry in manifest.get("files") or [])
    expected_members.update(entry["archive_path"].rstrip("/") for entry in manifest.get("directories") or [])
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            actual_members = set()
            for member in members:
                normalized = member.name.rstrip("/")
                if normalized in actual_members:
                    errors.append("duplicate archive member: {}".format(member.name))
                actual_members.add(normalized)
                if not _safe_member_name(member.name):
                    errors.append("unsafe archive member: {}".format(member.name))
                if member.issym() or member.islnk():
                    errors.append("links are not allowed in backup: {}".format(member.name))
                if normalized not in expected_members:
                    errors.append("unexpected archive member: {}".format(member.name))
            for missing in sorted(expected_members - actual_members):
                errors.append("missing archive member: {}".format(missing))
            redis_member = archive.extractfile(manifest["redis"]["member"])
            redis_data = redis_member.read() if redis_member is not None else b""
            if redis_member is None or _sha256_bytes(redis_data) != manifest["redis"]["sha256"]:
                errors.append("redis.json checksum mismatch")
            else:
                try:
                    snapshot = json.loads(redis_data.decode("utf-8"))
                    records = snapshot.get("records")
                    if int(snapshot.get("schema_version", 0)) != 1 or not isinstance(records, list):
                        raise ValueError("unsupported Redis snapshot schema")
                    if int(snapshot.get("key_count", -1)) != len(records):
                        raise ValueError("Redis snapshot key count mismatch")
                    if int(manifest["redis"].get("key_count", -1)) != len(records):
                        raise ValueError("manifest Redis key count mismatch")
                    for record in records:
                        base64.b64decode(record["key_b64"], validate=True)
                        base64.b64decode(record["dump_b64"], validate=True)
                except (KeyError, TypeError, ValueError) as exc:
                    errors.append("invalid redis.json: {}".format(exc))
            for entry in manifest.get("files") or []:
                try:
                    member_f = archive.extractfile(entry["archive_path"])
                    if member_f is None:
                        raise KeyError(entry["archive_path"])
                    digest = hashlib.sha256()
                    while True:
                        chunk = member_f.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                    if digest.hexdigest() != entry["sha256"]:
                        errors.append("file checksum mismatch: {}".format(entry["source"]))
                except KeyError:
                    errors.append("missing archive member: {}".format(entry["archive_path"]))
    except (OSError, KeyError, tarfile.TarError, ValueError) as exc:
        errors.append("archive verification failed: {}".format(exc))

    checksum_path = archive_path + ".sha256"
    sidecar_ok = None
    if os.path.isfile(checksum_path):
        try:
            with open(checksum_path, "r", encoding="ascii") as checksum_f:
                expected_hash = checksum_f.read().split()[0]
            sidecar_ok = _sha256_file(archive_path) == expected_hash
            if not sidecar_ok:
                errors.append("archive checksum sidecar mismatch")
        except (OSError, IndexError):
            sidecar_ok = False
            errors.append("archive checksum sidecar is invalid")
    return {
        "valid": not errors,
        "archive": archive_path,
        "created_at": manifest.get("created_at"),
        "file_count": len(manifest.get("files") or []),
        "redis_key_count": manifest.get("redis", {}).get("key_count", 0),
        "sidecar_verified": sidecar_ok,
        "errors": errors,
        "warnings": manifest.get("warnings") or [],
        "manifest": manifest,
    }


def _target_path(target_root, source):
    parts = _archive_parts(source)
    root_real = os.path.realpath(os.path.abspath(target_root))
    destination = os.path.abspath(os.path.join(root_real, *parts))
    if os.path.commonpath([root_real, destination]) != root_real:
        raise BackupError("restore path escapes target root: {}".format(source))
    return destination


def _ensure_safe_parent(target_root, destination):
    root_real = os.path.realpath(os.path.abspath(target_root))
    parent = os.path.dirname(destination)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    current = parent
    while os.path.commonpath([root_real, current]) == root_real and current != root_real:
        if os.path.islink(current):
            raise BackupError("restore parent is a symlink: {}".format(current))
        current = os.path.dirname(current)


def _restore_files(archive, manifest, target_root, preserve_owner=False):
    restored = []
    for entry in sorted(manifest.get("directories") or [], key=lambda item: len(_archive_parts(item["source"]))):
        destination = _target_path(target_root, entry["source"])
        _ensure_safe_parent(target_root, destination)
        if os.path.islink(destination):
            raise BackupError("restore directory is a symlink: {}".format(destination))
        os.makedirs(destination, mode=entry.get("mode", 0o700), exist_ok=True)
        os.chmod(destination, entry.get("mode", 0o700))
    for entry in manifest.get("files") or []:
        destination = _target_path(target_root, entry["source"])
        _ensure_safe_parent(target_root, destination)
        member_f = archive.extractfile(entry["archive_path"])
        if member_f is None:
            raise BackupError("missing restore member: {}".format(entry["archive_path"]))
        temp_path = destination + ".isolate-restore-{}".format(uuid.uuid4().hex)
        try:
            with open(temp_path, "wb") as output_f:
                shutil.copyfileobj(member_f, output_f, length=1024 * 1024)
                output_f.flush()
                os.fsync(output_f.fileno())
            os.chmod(temp_path, entry.get("mode", 0o600))
            if preserve_owner and os.name == "posix" and os.geteuid() == 0:
                os.chown(temp_path, int(entry.get("uid", 0)), int(entry.get("gid", 0)))
            os.replace(temp_path, destination)
            os.utime(destination, (entry.get("mtime", time.time()), entry.get("mtime", time.time())))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        restored.append(destination)
    return restored


def _redis_existing(redis, key):
    if hasattr(redis, "exists"):
        return bool(redis.exists(key))
    return redis.get(key) is not None


def _redis_restore_candidates(snapshot, now_ms):
    candidates = []
    expired = []
    for record in snapshot.get("records") or []:
        key = base64.b64decode(record["key_b64"])
        payload = base64.b64decode(record["dump_b64"])
        expire_at = record.get("expire_at_ms")
        if expire_at is not None and int(expire_at) <= now_ms:
            expired.append(record.get("key"))
            continue
        ttl = max(int(expire_at) - now_ms, 1) if expire_at is not None else 0
        candidates.append((key, ttl, payload, record.get("key")))
    return candidates, expired


def restore_redis_snapshot(redis, snapshot, conflict="abort", now_ms=None):
    if conflict not in ("abort", "replace", "skip"):
        raise BackupError("Redis conflict mode must be abort, replace, or skip")
    now_ms = int(now_ms if now_ms is not None else time.time() * 1000)
    candidates, expired = _redis_restore_candidates(snapshot, now_ms)

    conflicts = [display for key, _, _, display in candidates if _redis_existing(redis, key)]
    if conflicts and conflict == "abort":
        raise BackupError("Redis restore conflicts with existing keys: {}".format(", ".join(conflicts[:10])))
    if conflict == "skip":
        candidates = [row for row in candidates if not _redis_existing(redis, row[0])]

    target = redis.pipeline(transaction=True) if hasattr(redis, "pipeline") else redis
    for key, ttl, payload, _ in candidates:
        target.restore(key, ttl, payload, replace=(conflict == "replace"))
    if target is not redis:
        target.execute()
    return {"restored": len(candidates), "expired_skipped": expired, "conflicts": conflicts}


def restore_backup(archive_path, target_root, redis=None, restore_files=True, restore_redis=False, redis_conflict="abort", preserve_owner=False, confirmed=False, live=False):
    if not confirmed:
        raise BackupError("restore requires explicit confirmation")
    verification = verify_backup(archive_path)
    if not verification["valid"]:
        raise BackupError("backup verification failed: {}".format("; ".join(verification["errors"])))
    target_root = os.path.abspath(target_root)
    filesystem_root = os.path.abspath(os.path.sep)
    if os.path.realpath(target_root) == os.path.realpath(filesystem_root) and not live:
        raise BackupError("live filesystem restore requires explicit live mode")
    os.makedirs(target_root, mode=0o700, exist_ok=True)
    restored_files = []
    redis_result = None
    with tarfile.open(archive_path, "r:gz") as archive:
        redis_snapshot = None
        if restore_redis:
            if redis is None:
                raise BackupError("Redis client is required for Redis restore")
            redis_f = archive.extractfile(verification["manifest"]["redis"]["member"])
            if redis_f is None:
                raise BackupError("redis.json is missing")
            redis_snapshot = json.load(redis_f)
            if redis_conflict == "abort":
                candidates, _ = _redis_restore_candidates(redis_snapshot, int(time.time() * 1000))
                conflicts = [display for key, _, _, display in candidates if _redis_existing(redis, key)]
                if conflicts:
                    raise BackupError("Redis restore conflicts with existing keys: {}".format(", ".join(conflicts[:10])))
        if restore_files:
            restored_files = _restore_files(archive, verification["manifest"], target_root, preserve_owner=preserve_owner)
        if restore_redis:
            redis_result = restore_redis_snapshot(redis, redis_snapshot, conflict=redis_conflict)
    return {
        "archive": os.path.abspath(archive_path),
        "target_root": target_root,
        "files_restored": len(restored_files),
        "redis": redis_result,
    }


def list_backups(config):
    base_path = os.path.abspath(config.get("backup", {}).get("base_path"))
    rows = []
    for path in sorted(glob.glob(os.path.join(base_path, "isolate-backup-*.tar.gz")), reverse=True):
        try:
            manifest = read_backup_manifest(path)
            rows.append({
                "archive": path,
                "created_at": manifest.get("created_at"),
                "size": os.path.getsize(path),
                "file_count": len(manifest.get("files") or []),
                "redis_key_count": manifest.get("redis", {}).get("key_count", 0),
            })
        except BackupError as exc:
            rows.append({"archive": path, "error": str(exc), "size": os.path.getsize(path)})
    return rows
