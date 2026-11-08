"""Signed, chunked session evidence with a durable local S3 outbox.

S3 objects are written conditionally and addressed by content. The latest
published manifest is anchored in the authoritative state store, rather than a
mutable S3 'latest' object. Reads require that pointer and never silently use an
older cached revision. Authorization belongs to callers; describe() lets them
check identity/project metadata before downloading recording contents.
"""

import base64
import contextlib
import datetime
import hashlib
import hmac
import json
import os
import re
import stat
import time
import uuid
from urllib.parse import urlsplit


class RecordingError(ValueError):
    pass


class RecordingUnavailable(RecordingError):
    pass


class RecordingNotFound(RecordingUnavailable):
    pass


class RecordingIntegrityError(RecordingError):
    pass


ARTIFACTS = frozenset({"session.jsonl", "terminal.log", "terminal.log.meta"})
METADATA = frozenset({"username", "keycloak_sub", "project", "host_id", "protocol", "source_ip", "owner_node",
    "audit_profile", "remote_user", "sudo_mode", "started_at", "ended_at", "expires_at", "connection_id",
    "target_host", "server_name", "exit_code", "ts"})
ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
DIGEST_RE = re.compile(r"[a-f0-9]{64}\Z")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _identifier(value):
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise RecordingError("invalid recording connection ID")
    return value


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _integer(value, minimum, maximum, field):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RecordingError("invalid recording " + field)
    return value


def _directory(path):
    if not isinstance(path, str) or not os.path.isabs(path):
        raise RecordingError("recording directories must use absolute paths")
    os.makedirs(path, mode=0o700, exist_ok=True)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RecordingError("recording directory must not be a symlink")
    if os.name == "posix" and (info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o077):
        raise RecordingError("recording spool/cache directories must be owner-only")
    return path


def _sync_directory(path):
    if os.name == "posix":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def capture_root(config):
    """Use service-owned evidence before hashing/signing, not a human group dir."""
    options = config.get("recordings") or {}
    path = options.get("capture_path") or os.path.join(config.get("data_root", "/opt/auth"), "spool", "evidence")
    _directory(path)
    if os.name == "posix":
        current = os.path.abspath(path)
        while True:
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.geteuid()):
                raise RecordingError("capture ancestors must be owned by the service or root")
            # A root-owned sticky temporary directory protects private fixture
            # children from replacement. Production /opt ancestors are stricter.
            sticky_temporary = bool(info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
            if info.st_mode & 0o022 and not sticky_temporary:
                raise RecordingError("capture ancestors must not be group/world writable")
            parent = os.path.dirname(current)
            if parent == current or sticky_temporary:
                break
            current = parent
    return path


def _read(path, maximum=8 * 1024 * 1024, secret=False):
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or os.path.islink(path):
                raise RecordingError("recording files must be regular files")
            if secret and os.name == "posix" and (info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o077):
                raise RecordingError("recording signing key must be owner-only")
            data = source.read(maximum + 1)
        if len(data) > maximum:
            raise RecordingError("recording file exceeds its permitted size")
        return data
    except RecordingError:
        raise
    except OSError as exc:
        raise RecordingUnavailable("cannot read recording file") from exc


def _write(path, data):
    """Durably replace a private local descriptor; temporary names are generated."""
    parent = os.path.dirname(path)
    _directory(parent)
    temporary = os.path.join(parent, ".write-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _sync_directory(parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


@contextlib.contextmanager
def _session_lock(directory, connection_id):
    _directory(directory)
    path = os.path.join(directory, _identifier(connection_id) + ".lock")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RecordingError("invalid recording lock")
        if os.name == "posix":
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        else:
            import msvcrt
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, 0)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        yield
    finally:
        if os.name != "posix":
            import msvcrt
            os.lseek(descriptor, 0, 0)
            with contextlib.suppress(OSError):
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        os.close(descriptor)


class RecordingArchive:
    def __init__(self, config, s3_client=None, state_client=None):
        self.config = config
        self.options = config.get("recordings") or {}
        self.enabled = self.options.get("enabled", False) is True
        self._client, self._state_client = s3_client, state_client
        self._last_capture = {}
        if not self.enabled:
            return
        if self.options.get("backend", "s3") != "s3":
            raise RecordingError("unsupported recording storage backend")
        self.bucket = self.options.get("bucket")
        if not isinstance(self.bucket, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{1,62}", self.bucket):
            raise RecordingError("a recording bucket is required")
        self.prefix = str(self.options.get("prefix", "isolate-recordings")).strip("/")
        if (not self.prefix or len(self.prefix) > 256 or not re.fullmatch(r"[A-Za-z0-9_./-]+", self.prefix)
                or any(part in ("", ".", "..") for part in self.prefix.split("/"))):
            raise RecordingError("invalid recording object prefix")
        endpoint = self.options.get("endpoint_url")
        if endpoint:
            parsed = urlsplit(endpoint)
            test_http = (self.options.get("allow_loopback_http") is True and parsed.scheme == "http"
                         and parsed.hostname in ("localhost", "127.0.0.1", "::1"))
            if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or parsed.path not in ("", "/") or parsed.scheme != "https" and not test_http):
                raise RecordingError("S3 recordings require a verified HTTPS origin")
        if self.options.get("tls_verify", True) is not True:
            raise RecordingError("S3 TLS verification cannot be disabled")
        self.chunk_bytes = _integer(self.options.get("chunk_bytes", 262144), 1024, 4 * 1024 * 1024, "chunk_bytes")
        self.maximum_bytes = _integer(self.options.get("max_session_bytes", 1024 ** 3), 1024, 16 * 1024 ** 3, "max_session_bytes")
        self.capture_interval = max(0.1, min(30, float(self.options.get("upload_interval_seconds", 2))))
        self.outbox = _directory(self.options.get("outbox_path", os.path.join(config.get("data_root", "/opt/auth"), "spool", "recordings")))
        self.cache = _directory(self.options.get("cache_path", os.path.join(config.get("data_root", "/opt/auth"), "cache", "recordings")))
        self.logs = os.path.realpath(capture_root(config))
        self.key_id = str(self.options.get("signing_key_id", "recordings-v1"))
        key_file = self.options.get("signing_key_file") or (config.get("logging", {}).get("integrity") or {}).get("key_file")
        if not key_file or not os.path.isabs(key_file):
            raise RecordingError("a protected recording manifest signing key is required")
        self.signing_key = _read(key_file, maximum=16384, secret=True).strip()
        if len(self.signing_key) < 32:
            raise RecordingError("recording manifest signing key must contain at least 32 bytes")
        self.verification_keys = {self.key_id: self.signing_key}
        for name, path in (self.options.get("verification_key_files") or {}).items():
            self.verification_keys[str(name)] = _read(path, maximum=16384, secret=True).strip()
        for child in ("states", "chunks", "pending", "locks"):
            _directory(os.path.join(self.outbox, child))

    @property
    def client(self):
        if self._client is None:
            import boto3
            from botocore.config import Config
            self._client = boto3.client("s3", endpoint_url=self.options.get("endpoint_url"),
                region_name=self.options.get("region", "us-east-1"), verify=self.options.get("ca_bundle") or True,
                config=Config(signature_version="s3v4", connect_timeout=3, read_timeout=5,
                    retries={"max_attempts": 2, "mode": "standard"},
                    s3={"addressing_style": self.options.get("addressing_style", "path")}))
        return self._client

    @property
    def state(self):
        if self._state_client is None:
            from isolate_redis import create_redis_client
            self._state_client = create_redis_client(self.config)
        return self._state_client

    def _signed(self, payload):
        result = dict(payload, integrity_alg="hmac-sha256", integrity_key_id=self.key_id)
        result["integrity_signature"] = hmac.new(self.signing_key, _canonical(result), hashlib.sha256).hexdigest()
        return result

    def _verify(self, payload, expected_id=None):
        if not isinstance(payload, dict):
            raise RecordingIntegrityError("invalid recording manifest")
        unsigned = {key: value for key, value in payload.items() if key != "integrity_signature"}
        key = self.verification_keys.get(payload.get("integrity_key_id"))
        signature = payload.get("integrity_signature")
        if (payload.get("integrity_alg") != "hmac-sha256" or not key or not isinstance(signature, str)
                or not hmac.compare_digest(signature, hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest())):
            raise RecordingIntegrityError("recording manifest signature differs")
        if payload.get("schema_version") != 1 or expected_id and payload.get("connection_id") != expected_id:
            raise RecordingIntegrityError("recording manifest identity or schema differs")
        _identifier(payload.get("connection_id"))
        _integer(payload.get("revision"), 1, 2 ** 53, "manifest revision")
        if not isinstance(payload.get("complete"), bool) or not isinstance(payload.get("metadata"), dict):
            raise RecordingIntegrityError("invalid recording manifest metadata")
        files = payload.get("files")
        if not isinstance(files, dict) or not files or set(files) - ARTIFACTS:
            raise RecordingIntegrityError("invalid recording manifest artifacts")
        total = 0
        for artifact in files.values():
            if not isinstance(artifact, dict) or not isinstance(artifact.get("chunks"), list):
                raise RecordingIntegrityError("invalid recording artifact")
            size = _integer(artifact.get("size"), 0, self.maximum_bytes, "artifact size")
            offset = 0
            if len(artifact["chunks"]) > 100000:
                raise RecordingIntegrityError("recording contains too many chunks")
            for chunk in artifact["chunks"]:
                if (not isinstance(chunk, dict) or chunk.get("offset") != offset
                        or not isinstance(chunk.get("sha256"), str) or not DIGEST_RE.fullmatch(chunk["sha256"])):
                    raise RecordingIntegrityError("invalid recording chunk ordering or digest")
                offset += _integer(chunk.get("size"), 1, 4 * 1024 * 1024, "chunk size")
            if offset != size:
                raise RecordingIntegrityError("recording artifact is truncated")
            if payload["complete"] and (not isinstance(artifact.get("sha256"), str) or not DIGEST_RE.fullmatch(artifact["sha256"])):
                raise RecordingIntegrityError("completed recording lacks an artifact digest")
            total += size
        if total > self.maximum_bytes:
            raise RecordingIntegrityError("recording exceeds the session size limit")
        return payload

    def _state_path(self, connection_id):
        return os.path.join(self.outbox, "states", _identifier(connection_id) + ".json")

    def _chunk_path(self, digest):
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            raise RecordingIntegrityError("invalid recording chunk digest")
        return os.path.join(self.outbox, "chunks", digest)

    def _pending_path(self, manifest):
        digest = _digest(_canonical(manifest))
        return os.path.join(self.outbox, "pending", "{}.{:020d}.{}.json".format(manifest["connection_id"], manifest["revision"], digest))

    def _chunk_key(self, digest):
        if not DIGEST_RE.fullmatch(digest):
            raise RecordingIntegrityError("invalid recording chunk digest")
        return self.prefix + "/chunks/" + digest

    def _manifest_key(self, connection_id, revision, digest):
        _identifier(connection_id)
        _integer(revision, 1, 2 ** 53, "revision")
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            raise RecordingIntegrityError("invalid recording manifest digest")
        return self.prefix + "/sessions/{}/{:020d}-{}.json".format(connection_id, revision, digest)

    def _capture(self, path, previous):
        resolved = os.path.realpath(path)
        if os.path.commonpath([self.logs, resolved]) != self.logs:
            raise RecordingError("recording source lies outside the configured log directory")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or os.path.islink(path):
                raise RecordingError("recording source must be a regular file")
            if previous and (previous["device"] != info.st_dev or previous["inode"] != info.st_ino or previous["size"] > info.st_size):
                raise RecordingIntegrityError("recording source was replaced or truncated")
            result = dict(previous or {"path": resolved, "device": info.st_dev, "inode": info.st_ino, "size": 0, "chunks": []})
            result["chunks"] = list(result["chunks"])
            if info.st_size > self.maximum_bytes:
                raise RecordingError("recording source exceeds the size limit")
            source.seek(result["size"])
            remaining = info.st_size - result["size"]
            while remaining:
                data = source.read(min(remaining, self.chunk_bytes))
                if not data:
                    raise RecordingIntegrityError("recording source changed during snapshot")
                digest = _digest(data)
                target = self._chunk_path(digest)
                if os.path.exists(target):
                    if _read(target, self.chunk_bytes) != data:
                        raise RecordingIntegrityError("local recording chunk differs")
                else:
                    _write(target, data)
                result["chunks"].append({"offset": result["size"], "size": len(data), "sha256": digest})
                result["size"] += len(data)
                remaining -= len(data)
        return result

    def enqueue_file(self, connection_id, artifact, path, metadata=None, closed=False):
        """Snapshot appended bytes durably; no network is needed to enqueue."""
        if not self.enabled:
            return None
        connection_id = _identifier(connection_id)
        if artifact not in ARTIFACTS:
            raise RecordingError("unsupported recording artifact")
        resolved = os.path.realpath(path)
        if os.path.commonpath([self.logs, resolved]) != self.logs:
            raise RecordingError("recording source lies outside the configured capture directory")
        bindings = {key: value for key, value in (metadata or {}).items() if key in
                    ("username", "keycloak_sub", "project", "host_id", "protocol") and value is not None}
        cached = self._last_capture.get((connection_id, artifact))
        if cached and not closed and bindings == cached["bindings"]:
            info = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or resolved != cached["path"] or info.st_dev != cached["device"]
                    or info.st_ino != cached["inode"] or info.st_size < cached["size"]
                    or cached["complete"] and info.st_size != cached["size"]):
                raise RecordingIntegrityError("recording source was replaced, truncated or changed after completion")
            if time.monotonic() - cached["captured_at"] < self.capture_interval:
                return cached["manifest"]
        with _session_lock(os.path.join(self.outbox, "locks"), connection_id):
            state_path = self._state_path(connection_id)
            state = json.loads(_read(state_path)) if os.path.exists(state_path) else {"connection_id": connection_id,
                "revision": 0, "metadata": {}, "sources": {}, "complete": False}
            old_state = _canonical(state)
            updated_metadata = {key: value for key, value in (metadata or {}).items() if key in METADATA and value is not None}
            for key in ("username", "keycloak_sub", "project", "host_id"):
                if key in state["metadata"] and key in updated_metadata and state["metadata"][key] != updated_metadata[key]:
                    raise RecordingIntegrityError("recording authorization identity changed")
            state["metadata"].update(updated_metadata)
            state["metadata"]["connection_id"] = connection_id
            if state["complete"]:
                prior = state["sources"].get(artifact)
                if not prior or os.path.getsize(path) != prior["size"]:
                    raise RecordingIntegrityError("completed recording cannot accept more data")
                return state["manifest"]
            state["sources"][artifact] = self._capture(path, state["sources"].get(artifact))
            if closed:
                if "session.jsonl" not in state["sources"]:
                    raise RecordingError("completed recording requires session metadata")
                # Capture any last bytes from all previously registered files,
                # then compare the original evidence with its captured chunks.
                for name, record in list(state["sources"].items()):
                    record = self._capture(record["path"], record)
                    expected = hashlib.sha256()
                    for chunk in record["chunks"]:
                        expected.update(_read(self._chunk_path(chunk["sha256"]), 4 * 1024 * 1024))
                    actual = hashlib.sha256()
                    with open(record["path"], "rb") as source:
                        for data in iter(lambda: source.read(self.chunk_bytes), b""):
                            actual.update(data)
                    if expected.digest() != actual.digest():
                        raise RecordingIntegrityError("recording source was modified after capture")
                    record["sha256"] = expected.hexdigest()
                    state["sources"][name] = record
                state["complete"] = True
            if old_state == _canonical(state):
                return state.get("manifest")
            state["revision"] += 1
            manifest = {"schema_version": 1, "connection_id": connection_id, "revision": state["revision"],
                "previous_manifest_sha256": _digest(_canonical(state["manifest"])) if state.get("manifest") else None,
                "updated_at": time.time(), "complete": state["complete"], "metadata": state["metadata"],
                "files": {name: {key: item[key] for key in ("size", "chunks", "sha256") if key in item}
                          for name, item in state["sources"].items()}}
            manifest = self._signed(manifest)
            self._verify(manifest, connection_id)
            state["manifest"] = manifest
            # A crash after the first fsync is repaired by flush_once scanning
            # states. A queue descriptor can never refer to unwritten chunks.
            _write(state_path, _canonical(state))
            pending_path = self._pending_path(manifest)
            _write(pending_path, _canonical(manifest))
            # New manifests include every captured chunk. Superseding only
            # unuploaded descriptors bounds spool amplification during outages;
            # immutable data chunks and published manifests are never removed.
            pattern = re.compile(re.escape(connection_id) + r"\.(\d{20})\.[a-f0-9]{64}\.json\Z")
            for name in os.listdir(os.path.dirname(pending_path)):
                matched = pattern.fullmatch(name)
                if matched and int(matched[1]) < manifest["revision"]:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(os.path.join(os.path.dirname(pending_path), name))
            _sync_directory(os.path.dirname(pending_path))
            source = state["sources"][artifact]
            self._last_capture[(connection_id, artifact)] = {"captured_at": time.monotonic(), "bindings": bindings,
                "path": resolved, "device": source["device"], "inode": source["inode"], "size": source["size"],
                "complete": state["complete"], "manifest": manifest}
            return manifest

    def _get_object(self, key, maximum):
        try:
            result = self.client.get_object(Bucket=self.bucket, Key=key)
            body = result["Body"]
            try:
                data = body.read(maximum + 1)
            finally:
                body.close()
            if len(data) > maximum:
                raise RecordingIntegrityError("recording object is too large")
            return data
        except RecordingError:
            raise
        except Exception as exc:
            raise RecordingUnavailable("recording storage object is unavailable") from exc

    def _put_object(self, key, data):
        options = {"Bucket": self.bucket, "Key": key, "Body": data, "IfNoneMatch": "*",
            "ChecksumSHA256": base64.b64encode(hashlib.sha256(data).digest()).decode(),
            "Metadata": {"sha256": _digest(data)}}
        encryption = self.options.get("server_side_encryption")
        if encryption:
            if encryption not in ("AES256", "aws:kms"):
                raise RecordingError("unsupported recording encryption setting")
            options["ServerSideEncryption"] = encryption
            if encryption == "aws:kms" and self.options.get("kms_key_id"):
                options["SSEKMSKeyId"] = self.options["kms_key_id"]
        retention = self.options.get("retention_days")
        if retention:
            retention = _integer(retention, 1, 36500, "retention_days")
            mode = self.options.get("object_lock_mode")
            if mode not in ("GOVERNANCE", "COMPLIANCE"):
                raise RecordingError("retention requires an explicit S3 object lock mode")
            options.update(ObjectLockMode=mode, ObjectLockRetainUntilDate=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=retention))
        if self.options.get("legal_hold") is True:
            options["ObjectLockLegalHoldStatus"] = "ON"
        try:
            self.client.put_object(**options)
        except Exception as exc:
            response = getattr(exc, "response", {})
            code = str((response.get("Error") or {}).get("Code") or "")
            status_code = (response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
            if code not in ("PreconditionFailed", "412") and status_code != 412:
                raise RecordingUnavailable("recording object upload failed") from exc
            if self._get_object(key, len(data)) != data:
                raise RecordingIntegrityError("immutable recording object differs") from exc

    def _publish(self, manifest):
        key = "recording_head_" + manifest["connection_id"]
        digest = _digest(_canonical(manifest))
        pointer = {"schema_version": 1, "connection_id": manifest["connection_id"], "revision": manifest["revision"],
            "manifest_sha256": digest, "complete": manifest["complete"], "metadata": manifest["metadata"]}
        from redis.exceptions import WatchError
        for _ in range(16):
            try:
                with self.state.pipeline() as transaction:
                    transaction.watch(key)
                    raw = transaction.get(key)
                    previous = json.loads(raw) if raw else None
                    if previous:
                        if previous["revision"] > pointer["revision"]:
                            return
                        if previous["revision"] == pointer["revision"]:
                            if previous["manifest_sha256"] != digest:
                                raise RecordingIntegrityError("recording revision has two different producers")
                            return
                    transaction.multi()
                    transaction.set(key, json.dumps(pointer, sort_keys=True))
                    transaction.execute()
                    return
            except WatchError:
                continue
            except RecordingError:
                raise
            except Exception as exc:
                raise RecordingUnavailable("recording authority publication failed") from exc
        raise RecordingUnavailable("recording publication contention")

    def flush_once(self, limit=100):
        if not self.enabled:
            return {"published": 0, "failed": 0, "pending": 0}
        limit = _integer(limit, 1, 10000, "flush limit")
        # Repair a crash between local state and queue fsync. Published state is
        # checked through the authoritative store; failure never clears outbox.
        published, failed = 0, 0
        for filename in os.listdir(os.path.join(self.outbox, "states")):
            if not filename.endswith(".json"):
                continue
            try:
                state = json.loads(_read(os.path.join(self.outbox, "states", filename)))
                manifest = self._verify(state.get("manifest"), filename[:-5])
                raw = self.state.get("recording_head_" + manifest["connection_id"])
                head = json.loads(raw) if raw else None
                if not head or head["revision"] < manifest["revision"]:
                    path = self._pending_path(manifest)
                    if not os.path.exists(path):
                        _write(path, _canonical(manifest))
            except Exception:
                # One damaged local descriptor cannot suppress publication of
                # other sessions. It remains on disk for operator recovery.
                failed += 1
        paths = sorted(os.listdir(os.path.join(self.outbox, "pending")))
        for filename in paths[:limit]:
            if not filename.endswith(".json"):
                continue
            path = os.path.join(self.outbox, "pending", filename)
            try:
                manifest = self._verify(json.loads(_read(path)))
                data = _canonical(manifest)
                if self._pending_path(manifest) != path:
                    raise RecordingIntegrityError("recording queue descriptor differs")
                for artifact in manifest["files"].values():
                    for chunk in artifact["chunks"]:
                        payload = _read(self._chunk_path(chunk["sha256"]), 4 * 1024 * 1024)
                        if len(payload) != chunk["size"] or _digest(payload) != chunk["sha256"]:
                            raise RecordingIntegrityError("local recording chunk is corrupt")
                        self._put_object(self._chunk_key(chunk["sha256"]), payload)
                self._put_object(self._manifest_key(manifest["connection_id"], manifest["revision"], _digest(data)), data)
                self._publish(manifest)
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path)
                _sync_directory(os.path.dirname(path))
                published += 1
            except (RecordingError, ValueError, KeyError, TypeError, OSError):
                failed += 1
        return {"published": published, "failed": failed,
                "pending": len([name for name in os.listdir(os.path.join(self.outbox, "pending")) if name.endswith(".json")])}

    def _manifest(self, connection_id, min_revision=None):
        if not self.enabled:
            raise RecordingUnavailable("shared recordings are disabled")
        connection_id = _identifier(connection_id)
        try:
            raw = self.state.get("recording_head_" + connection_id)
        except Exception as exc:
            raise RecordingUnavailable("recording authority is unavailable") from exc
        if not raw:
            raise RecordingNotFound("recording is not yet published")
        try:
            pointer = json.loads(raw)
            if pointer.get("schema_version") != 1 or pointer.get("connection_id") != connection_id:
                raise RecordingIntegrityError("invalid recording publication pointer")
            revision = _integer(pointer.get("revision"), 1, 2 ** 53, "published revision")
            if min_revision is not None and revision < _integer(min_revision, 1, 2 ** 53, "minimum revision"):
                raise RecordingIntegrityError("recording publication is older than requested")
            key = self._manifest_key(connection_id, revision, pointer["manifest_sha256"])
            data = self._get_object(key, 16 * 1024 * 1024)
            if _digest(data) != pointer["manifest_sha256"]:
                raise RecordingIntegrityError("published recording manifest digest differs")
            manifest = self._verify(json.loads(data), connection_id)
            if manifest["revision"] != revision or manifest["metadata"] != pointer["metadata"] or manifest["complete"] != pointer["complete"]:
                raise RecordingIntegrityError("recording metadata differs from the authority")
            return manifest
        except RecordingError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise RecordingIntegrityError("invalid recording publication") from exc

    def describe(self, connection_id, min_revision=None):
        """Verify public authorization metadata before downloading artifacts."""
        manifest = self._manifest(connection_id, min_revision)
        return {"connection_id": manifest["connection_id"], "revision": manifest["revision"],
            "complete": manifest["complete"], "metadata": manifest["metadata"],
            "updated_at": manifest["updated_at"], "size": sum(item["size"] for item in manifest["files"].values())}

    def materialize(self, connection_id, min_revision=None, expected_revision=None, artifacts=None):
        manifest = self._manifest(connection_id, min_revision)
        if expected_revision is not None and manifest["revision"] != expected_revision:
            raise RecordingUnavailable("recording publication changed; reauthorize its metadata")
        revision_dir = _directory(os.path.join(self.cache, manifest["connection_id"], str(manifest["revision"]) + "-" + _digest(_canonical(manifest))))
        if artifacts is not None:
            if not isinstance(artifacts, (list, tuple, set)) or not artifacts or set(artifacts) - ARTIFACTS:
                raise RecordingError("unsupported recording artifact selection")
            if set(artifacts) - set(manifest["files"]):
                raise RecordingIntegrityError("requested recording artifact is missing")
        paths = {}
        for name, artifact in manifest["files"].items():
            if artifacts is not None and name not in artifacts:
                continue
            target = os.path.join(revision_dir, name)
            temporary = os.path.join(revision_dir, ".download-" + uuid.uuid4().hex)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            digest, size = hashlib.sha256(), 0
            try:
                with os.fdopen(descriptor, "wb") as output:
                    for chunk in artifact["chunks"]:
                        data = self._get_object(self._chunk_key(chunk["sha256"]), chunk["size"])
                        if len(data) != chunk["size"] or _digest(data) != chunk["sha256"]:
                            raise RecordingIntegrityError("recording chunk is missing, corrupt or truncated")
                        output.write(data)
                        digest.update(data)
                        size += len(data)
                    if size != artifact["size"] or artifact.get("sha256") and digest.hexdigest() != artifact["sha256"]:
                        raise RecordingIntegrityError("recording artifact digest differs")
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, target)
                _sync_directory(revision_dir)
                paths[name] = target
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary)
        return {"session_path": paths.get("session.jsonl"), "raw_log_path": paths.get("terminal.log"),
            "raw_meta_path": paths.get("terminal.log.meta"), "session_dir": revision_dir, "manifest": manifest,
            "metadata": manifest["metadata"], "complete": manifest["complete"]}
