"""Opt-in native database protocol mediation over an authorized gateway stream.

The one-use Isolate ticket selects the inventory endpoint and policy identity.
An independent private frontend capability authenticates the local native client;
upstream passwords never leave this process. PostgreSQL/MySQL wire messages are
forwarded rather than replayed through an SQL driver, preserving transactions,
prepared statements, COPY and native result encoding. Audit excludes parameters,
rows, passwords, authentication exchanges and COPY data.
"""
import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import math
import re
import secrets
import ssl
import struct
import time
import unicodedata
from collections import deque
from urllib import parse, request, error

from isolate_protocols import ProtocolError

_PG_SSL = struct.pack("!II", 8, 80877103)
_PG_CANCEL = 80877102
_LIVE = {}
_USER = re.compile(r"[A-Za-z_][A-Za-z0-9_.@-]{0,127}\Z")
_MAX_PACKET = 16777216
_MY_CAP = (1 | 2 | 4 | 8 | 0x200 | 0x800 | 0x2000 | 0x8000 | 0x10000 | 0x20000 | 0x40000 | 0x80000 | 0x100000 | 0x200000)


def validate_database_target(target, check_paths=False):
    options = target.get("database_proxy") or {}
    if options.get("enabled") is not True:
        raise ProtocolError("database protocol mediation is disabled")
    if target.get("protocol") not in ("postgresql", "mysql"):
        raise ProtocolError("unsupported mediated database protocol")
    for name in ("frontend_cert_file", "frontend_key_file"):
        import os
        path = options.get(name)
        if not isinstance(path, str) or not os.path.isabs(path):
            raise ProtocolError("database frontend TLS certificate and private key paths are required")
        if check_paths:
            from isolate_credentials import _read_file
            _read_file(path, secret=name.endswith("key_file"))
    databases = options.get("databases")
    if (not isinstance(databases, list) or not databases or len(databases) > 100
            or any(not isinstance(name, str) or not name or len(name) > 128 or any(ord(c) < 32 for c in name) for name in databases)):
        raise ProtocolError("database mediation requires an explicit database-name allowlist")
    credentials = options.get("credentials")
    identities = options.get("identities")
    if bool(credentials) == bool(identities):
        raise ProtocolError("configure one database credential profile or policy-user identity profiles")
    profiles = [credentials] if credentials else list(identities.values()) if isinstance(identities, dict) else []
    if not profiles or any(not isinstance(item, dict) for item in profiles):
        raise ProtocolError("invalid database credential profiles")
    if identities and any(not isinstance(user, str) or not _USER.fullmatch(user) for user in identities):
        raise ProtocolError("invalid database policy identity")
    for profile in profiles:
        if profile.get("type", "file") not in ("file", "vault-kv", "vault-database"):
            raise ProtocolError("unsupported database credential provider")
        if profile.get("type", "file") == "file":
            if not profile.get("password_file") or not profile.get("username"):
                raise ProtocolError("file database credentials require a username and protected password_file")
    if type(options.get("audit_statement_text", False)) is not bool:
        raise ProtocolError("audit_statement_text must be an explicit boolean")
    maximum = options.get("max_packet_bytes", _MAX_PACKET)
    if type(maximum) is not int or not 1024 <= maximum <= 67108864:
        raise ProtocolError("database packet limit must be between 1024 and 67108864 bytes")
    return options


def _vault_response(provider, path, payload=None):
    from isolate_credentials import _read_file, _vault_path, _NoRedirect
    address = provider.get("address") or ""
    parsed = parse.urlsplit(address)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")
            or provider.get("tls_verify", True) is not True):
        raise ProtocolError("database Vault credentials require a trusted verified HTTPS origin")
    token = _read_file(provider.get("token_file"), secret=True, maximum=16384).decode().strip()
    if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ProtocolError("invalid Vault credential")
    headers = {"X-Vault-Token": token, "Accept": "application/json", "Content-Type": "application/json"}
    if provider.get("namespace"):
        namespace = provider["namespace"]
        if not isinstance(namespace, str) or any(ord(c) < 33 or ord(c) > 126 for c in namespace):
            raise ProtocolError("invalid Vault namespace")
        headers["X-Vault-Namespace"] = namespace
    endpoint = address.rstrip("/") + "/v1/" + _vault_path(provider, path)
    context = ssl.create_default_context(cafile=provider.get("ca_file"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = request.build_opener(request.HTTPSHandler(context=context), _NoRedirect())
    req = request.Request(endpoint, headers=headers, data=None if payload is None else json.dumps(payload).encode())
    try:
        with opener.open(req, timeout=max(1, min(10, float(provider.get("timeout_seconds", 5))))) as response:
            raw = response.read(1048577)
        value = json.loads(raw) if len(raw) <= 1048576 else None
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (OSError, ValueError, error.URLError) as exc:
        raise ProtocolError("database credential service is unavailable") from exc


@contextlib.contextmanager
def database_credentials(target, context):
    from isolate_credentials import _read_file
    options = validate_database_target(target)
    decision = context.get("decision") or {}
    username = decision.get("remote_user")
    if decision.get("sudo_mode") != "none" or not isinstance(username, str) or not _USER.fullmatch(username):
        raise ProtocolError("database mediation requires an exact policy user and no sudo")
    profile = dict((options.get("identities") or {}).get(username) or options.get("credentials") or {})
    if not profile:
        raise ProtocolError("no credential profile for the policy-selected database identity")
    kind = profile.get("type", "file")
    lease_id = None
    credential = {}
    try:
        if kind == "file":
            password = _read_file(profile.get("password_file"), secret=True, maximum=16384).decode("utf-8").rstrip("\r\n")
            returned_user = profile.get("username")
            expires = None
        else:
            if kind == "vault-kv":
                path = profile.get("path") or ""
                result = _vault_response(profile, path)
                data = result.get("data") or {}
                data = data.get("data", data)
                expires = None
            else:
                path = profile.get("path") or ""
                result = _vault_response(profile, path)
                data = result.get("data") or {}
                lease_id = result.get("lease_id")
                ttl = result.get("lease_duration")
                if not isinstance(lease_id, str) or not lease_id or type(ttl) is not int or ttl <= 0:
                    raise ProtocolError("database credential lease is invalid")
                expires = time.time() + ttl
            returned_user = data.get(profile.get("username_field", "username"))
            password = data.get(profile.get("password_field", "password"))
        if returned_user != username or not isinstance(password, str) or not password or len(password) > 16384 or "\0" in password:
            raise ProtocolError("database credential identity does not match the policy-selected user")
        credential.update(username=username, password=password, expires_at=expires)
        yield credential
    finally:
        credential.clear()
        if lease_id:
            # Revoke needs an explicit allowlisted endpoint too. Never silently
            # generate a broader Vault path from a user/lease string.
            revoke_path = profile.get("revoke_path", "sys/leases/revoke")
            _vault_response(profile, revoke_path, {"lease_id": lease_id})


class _TLSStream:
    """Native database TLS carried as binary frames inside verified WSS."""
    def __init__(self, raw, websocket, options):
        self.raw, self.websocket = raw, websocket
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        from isolate_credentials import _read_file
        _read_file(options["frontend_cert_file"])
        _read_file(options["frontend_key_file"], secret=True)
        context.load_cert_chain(options["frontend_cert_file"], options["frontend_key_file"])
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)
        self.read_lock, self.write_lock = asyncio.Lock(), asyncio.Lock()

    async def flush(self):
        async with self.write_lock:
            while self.outgoing.pending:
                await self.websocket.send_bytes(self.outgoing.read(65536))

    async def ingest(self):
        async with self.read_lock:
            data = await self.raw.read(65536)
            if not data:
                self.incoming.write_eof()
                raise EOFError()
            self.incoming.write(data)

    async def handshake(self):
        while True:
            try:
                self.tls.do_handshake()
                await self.flush()
                return
            except ssl.SSLWantReadError:
                await self.flush()
                await self.ingest()

    async def read(self, maximum=65536):
        while True:
            try:
                data = self.tls.read(maximum)
                await self.flush()
                return data
            except ssl.SSLWantReadError:
                await self.flush()
                await self.ingest()
            except ssl.SSLZeroReturnError:
                return b""

    async def readexactly(self, size):
        data = bytearray()
        while len(data) < size:
            chunk = await self.read(size - len(data))
            if not chunk:
                raise EOFError()
            data.extend(chunk)
        return bytes(data)

    async def write(self, data):
        while data:
            try:
                written = self.tls.write(data[:65536])
                data = data[written:]
                await self.flush()
            except ssl.SSLWantReadError:
                await self.flush()
                await self.ingest()


async def _write(writer, data):
    writer.write(data)
    await writer.drain()


async def _pg_packet(reader, maximum):
    kind = await reader.readexactly(1)
    header = await reader.readexactly(4)
    size = struct.unpack("!I", header)[0]
    if not 4 <= size <= maximum:
        raise ProtocolError("PostgreSQL packet exceeds its configured limit")
    payload = await reader.readexactly(size - 4)
    return kind, payload, kind + header + payload


def _pg_message(kind, payload):
    return kind + struct.pack("!I", len(payload) + 4) + payload


def _cstring(payload, offset=0):
    end = payload.find(b"\0", offset)
    if end < 0:
        raise ProtocolError("database string is unterminated")
    return payload[offset:end], end + 1


def _scram_password(password):
    # PostgreSQL falls back to the original UTF-8 password when SASLprep is
    # prohibited. Use the same behavior rather than altering such credentials.
    import stringprep
    mapped = "".join(" " if stringprep.in_table_c12(c) else c for c in password if not stringprep.in_table_b1(c))
    normalized = unicodedata.normalize("NFKC", mapped)
    prohibited = (stringprep.in_table_c12, stringprep.in_table_c21, stringprep.in_table_c22,
                  stringprep.in_table_c3, stringprep.in_table_c4, stringprep.in_table_c5,
                  stringprep.in_table_c6, stringprep.in_table_c7, stringprep.in_table_c8, stringprep.in_table_c9)
    if any(test(char) for char in normalized for test in prohibited):
        return password.encode()
    randal = [stringprep.in_table_d1(char) for char in normalized]
    if any(randal) and (any(stringprep.in_table_d2(char) for char in normalized) or not randal[0] or not randal[-1]):
        return password.encode()
    return normalized.encode()


async def _pg_connect(target, username, password, startup):
    reader, writer = await asyncio.open_connection(target["address"], target["port"])
    try:
        await _write(writer, _PG_SSL)
        if await reader.readexactly(1) != b"S":
            raise ProtocolError("PostgreSQL upstream refused verified TLS")
        tls = ssl.create_default_context(cafile=target.get("ca_file"))
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        await writer.start_tls(tls, server_hostname=target["hostname"])
        await _write(writer, struct.pack("!I", len(startup) + 4) + startup)
        bare, expected_signature = None, None
        for _ in range(12):
            kind, payload, raw = await _pg_packet(reader, 1048576)
            if kind == b"E":
                raise ProtocolError("PostgreSQL upstream authentication failed")
            if kind != b"R" or len(payload) < 4:
                raise ProtocolError("unexpected PostgreSQL authentication response")
            code = struct.unpack("!I", payload[:4])[0]
            if code == 0:
                return reader, writer, raw
            if code == 3:
                await _write(writer, _pg_message(b"p", password.encode() + b"\0"))
            elif code == 5 and len(payload) == 8:
                digest = hashlib.md5((password + username).encode()).hexdigest().encode()
                response = b"md5" + hashlib.md5(digest + payload[4:]).hexdigest().encode()
                await _write(writer, _pg_message(b"p", response + b"\0"))
            elif code == 10 and b"SCRAM-SHA-256\0" in payload[4:]:
                nonce = base64.b64encode(secrets.token_bytes(24)).decode()
                bare = "n=,r=" + nonce
                first = ("n,," + bare).encode()
                await _write(writer, _pg_message(b"p", b"SCRAM-SHA-256\0" + struct.pack("!I", len(first)) + first))
            elif code == 11 and bare:
                server_first = payload[4:].decode("ascii")
                values = dict(part.split("=", 1) for part in server_first.split(","))
                iterations = int(values["i"])
                server_nonce = values["r"]
                if not server_nonce.startswith(nonce) or len(server_nonce) <= len(nonce) or not 4096 <= iterations <= 1000000:
                    raise ProtocolError("invalid PostgreSQL SCRAM challenge")
                salt = base64.b64decode(values["s"], validate=True)
                if not 1 <= len(salt) <= 1024:
                    raise ProtocolError("invalid PostgreSQL SCRAM salt")
                salted = await asyncio.to_thread(hashlib.pbkdf2_hmac, "sha256", _scram_password(password), salt, iterations)
                client_key = hmac.digest(salted, b"Client Key", "sha256")
                final = "c=biws,r=" + server_nonce
                auth = (bare + "," + server_first + "," + final).encode()
                signature = hmac.digest(hashlib.sha256(client_key).digest(), auth, "sha256")
                proof = bytes(left ^ right for left, right in zip(client_key, signature))
                expected_signature = hmac.digest(hmac.digest(salted, b"Server Key", "sha256"), auth, "sha256")
                await _write(writer, _pg_message(b"p", (final + ",p=" + base64.b64encode(proof).decode()).encode()))
            elif code == 12 and expected_signature is not None:
                values = dict(part.split("=", 1) for part in payload[4:].decode("ascii").split(","))
                if not hmac.compare_digest(base64.b64decode(values.get("v", ""), validate=True), expected_signature):
                    raise ProtocolError("PostgreSQL SCRAM server signature is invalid")
            else:
                raise ProtocolError("unsupported PostgreSQL authentication method")
        raise ProtocolError("PostgreSQL authentication exceeded the exchange limit")
    except BaseException:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        raise


def _statement(sql, options):
    metadata = {"statement_sha256": hashlib.sha256(sql).hexdigest(), "statement_bytes": len(sql)}
    decoded = sql.decode("utf-8", errors="replace")
    leading = re.sub(r"(?s)^\s*(?:(?:/\*.*?\*/|--[^\n]*(?:\n|$))\s*)*", "", decoded)
    word = re.match(r"[A-Za-z]+", leading)
    metadata["statement_kind"] = word.group().upper()[:32] if word else "UNKNOWN"
    if options.get("audit_statement_text") is True:
        metadata["statement_text"] = decoded[:4096]
        metadata["statement_text_truncated"] = len(decoded) > 4096
    return metadata


async def _audit(runtime, context, event, **metadata):
    await asyncio.to_thread(runtime.channel_event, context, event, database_user=context["decision"]["remote_user"], **metadata)


def _cancel_key(pid, key):
    return "database_cancel_" + hashlib.sha256(struct.pack("!II", pid, key)).hexdigest()


async def _register_cancel(runtime, context, backend):
    pid, key = struct.unpack("!II", backend)
    fake_pid, fake_key = secrets.randbelow(2147483646) + 1, secrets.randbits(32)
    value = {"backend_pid": pid, "backend_key": key, "subject": context["identity"]["keycloak_sub"],
        "host_id": str(context["host"]["server_id"]), "connection_id": context["connection_id"],
        "database_user": context["decision"]["remote_user"], "username": context["identity"]["username"],
        "deadline": context["deadline"], "authority_epoch": context.get("authority_epoch"),
        "authorization_revision": context.get("authorization_revision"), "target_revision": context.get("target_revision"),
        "lease_owner": getattr(context.get("_lease"), "owner", None), "session_approval_id": context.get("session_approval_id"),
        "approval_consumed": context.get("_approval_consumed", False), "source_ip": context.get("source_ip")}
    registry = _cancel_key(fake_pid, fake_key)
    await asyncio.to_thread(runtime.redis.set, registry, json.dumps(value), ex=max(1, int(context["deadline"] - time.time())))
    return registry, struct.pack("!II", fake_pid, fake_key)


async def cancel_database_query(runtime, context, target, cancellation):
    """Cancel only an owner's live, still-authorized PostgreSQL backend.

    Registry contains no caller-chosen address. The lookup key is a synthetic
    64-bit native capability, while owner, route, policy, epoch, live lease and
    consumed approval must all match. Missing/foreign keys are indistinguishable.
    """
    if target.get("protocol") != "postgresql" or not isinstance(cancellation, dict) or set(cancellation) != {"process_id", "secret_key"}:
        raise ProtocolError("invalid database cancellation")
    pid, key = cancellation["process_id"], cancellation["secret_key"]
    if type(pid) is not int or type(key) is not int or not 0 <= pid <= 0xFFFFFFFF or not 0 <= key <= 0xFFFFFFFF:
        raise ProtocolError("invalid database cancellation")
    raw = await asyncio.to_thread(runtime.redis.get, _cancel_key(pid, key))
    if raw is None:
        return False
    value = json.loads(raw)
    if (value.get("subject") != context["identity"]["keycloak_sub"] or value.get("host_id") != str(context["host"]["server_id"])
            or value.get("database_user") != context["decision"]["remote_user"] or value.get("deadline", 0) <= time.time()
            or value.get("authority_epoch") != context.get("authority_epoch")
            or value.get("authorization_revision") != context.get("authorization_revision")
            or value.get("target_revision") != context.get("target_revision")):
        return False
    connection_id = value["connection_id"]
    original = _LIVE.get(connection_id)
    cancellation_logger = None
    if original:
        await asyncio.to_thread(runtime.recheck, original)
        audit_context = original
    else:
        from isolate_sessions import get_session, termination_requested
        active = await asyncio.to_thread(get_session, runtime.redis, connection_id)
        lease = await asyncio.to_thread(runtime.redis.get, "isolate_session_owner_" + connection_id)
        if isinstance(lease, bytes):
            lease = lease.decode()
        if (not active or active.get("status") != "active" or lease != value.get("lease_owner") or not lease
                or await asyncio.to_thread(termination_requested, runtime.redis, connection_id)):
            return False
        from isolate_session_approvals import session_approval_required, validate_session_approval
        if value.get("approval_consumed"):
            await asyncio.to_thread(validate_session_approval, runtime.redis, runtime.config, value["session_approval_id"],
                context["identity"], context["host"], context["decision"], connection_id, source_ip=value.get("source_ip"))
        elif session_approval_required(runtime.config, context["host"], context["decision"]):
            return False
        from isolate_logging import SessionLogger
        # A different node must never append to the original owner's recording
        # or publish a competing archive head. Give this authorized request its
        # own audit stream and link the parent explicitly instead.
        cancellation_logger = SessionLogger(runtime.config["logging"]["base_path"], context["identity"],
            session_id=context["connection_id"], logging_config=runtime.config.get("logging", {}),
            archive_config=runtime.config, state_client=runtime.redis)
        audit_context = dict(context, _logger=cancellation_logger)
    writer = None
    try:
        await _audit(runtime, audit_context, "database_cancel", result="requested", parent_connection_id=connection_id)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target["address"], target["port"]), timeout=5)
        await _write(writer, _PG_SSL)
        if await reader.readexactly(1) != b"S":
            raise ProtocolError("PostgreSQL cancellation requires verified upstream TLS")
        tls = ssl.create_default_context(cafile=target.get("ca_file"))
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        await writer.start_tls(tls, server_hostname=target["hostname"])
        await _write(writer, struct.pack("!IIII", 16, _PG_CANCEL, value["backend_pid"], value["backend_key"]))
        await asyncio.wait_for(reader.read(1), timeout=5)
        return True
    finally:
        if writer:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        if cancellation_logger:
            await asyncio.to_thread(cancellation_logger.close_archive)


async def _postgresql(runtime, context, target, raw, websocket, frontend_password):
    options = validate_database_target(target)
    first = await raw.readexactly(8)
    if first != _PG_SSL:
        raise ProtocolError("PostgreSQL client must negotiate native TLS")
    await websocket.send_bytes(b"S")
    client = _TLSStream(raw, websocket, options)
    await client.handshake()
    size = struct.unpack("!I", await client.readexactly(4))[0]
    if not 8 <= size <= 65536:
        raise ProtocolError("invalid PostgreSQL startup packet")
    startup = await client.readexactly(size - 4)
    if startup[:4] != struct.pack("!I", 196608) or startup[-1:] != b"\0":
        raise ProtocolError("PostgreSQL protocol 3.0 is required")
    pieces = startup[4:].split(b"\0")
    if pieces[-2:] != [b"", b""] or len(pieces) % 2:
        raise ProtocolError("invalid PostgreSQL startup parameters")
    parameters = {}
    for index in range(0, len(pieces) - 2, 2):
        name, value = pieces[index].decode("ascii"), pieces[index + 1].decode("utf-8")
        if name in parameters:
            raise ProtocolError("duplicate PostgreSQL startup parameter")
        parameters[name] = value
    if parameters.get("database") not in options["databases"] or parameters.get("replication"):
        raise ProtocolError("database or replication startup is not permitted")
    # Authentication of the local client happens before fetching any upstream
    # credential. PostgreSQL cleartext password messages are inside native TLS.
    await client.write(_pg_message(b"R", struct.pack("!I", 3)))
    kind, supplied, _ = await _pg_packet(client, 65536)
    if kind != b"p" or not hmac.compare_digest(supplied, frontend_password.encode() + b"\0"):
        raise ProtocolError("native database client capability is invalid")
    credential_context = database_credentials(target, context)
    credentials = await asyncio.to_thread(credential_context.__enter__)
    writer, registry = None, None
    try:
        if credentials["expires_at"]:
            context["deadline"] = min(context["deadline"], int(credentials["expires_at"]))
        parameters["user"] = credentials["username"]
        # Runtime GUC options/replication extensions can materially change the
        # selected identity; only harmless explicit startup settings pass.
        allowed = {"user", "database", "client_encoding", "application_name", "DateStyle", "TimeZone"}
        if set(parameters) - allowed:
            raise ProtocolError("unsupported PostgreSQL startup option")
        upstream_start = struct.pack("!I", 196608) + b"".join(name.encode() + b"\0" + value.encode() + b"\0" for name, value in parameters.items()) + b"\0"
        reader, writer, authenticated = await _pg_connect(target, credentials["username"], credentials["password"], upstream_start)
        await client.write(authenticated)
        maximum = options.get("max_packet_bytes", _MAX_PACKET)
        for _ in range(100):
            kind, payload, packet = await _pg_packet(reader, maximum)
            if kind == b"K":
                if len(payload) != 8:
                    raise ProtocolError("invalid PostgreSQL backend cancellation key")
                registry, synthetic = await _register_cancel(runtime, context, payload)
                packet = _pg_message(b"K", synthetic)
            await client.write(packet)
            if kind == b"Z":
                break
            if kind == b"E":
                return
        else:
            raise ProtocolError("PostgreSQL startup exceeded its message limit")
        _LIVE[context["connection_id"]] = context
        statements, portals, pending = {}, {}, deque()

        async def frontend():
            while True:
                kind, payload, packet = await _pg_packet(client, maximum)
                if kind == b"Q":
                    if payload[-1:] != b"\0":
                        raise ProtocolError("invalid PostgreSQL query packet")
                    query = dict(_statement(payload[:-1], options), operation_id=secrets.token_hex(16), prepared=False)
                    await _audit(runtime, context, "database_query", **query)
                    pending.append(query)
                elif kind == b"P":
                    name, offset = _cstring(payload)
                    sql, _ = _cstring(payload, offset)
                    if len(statements) >= 10000 and name not in statements:
                        raise ProtocolError("prepared statement count exceeds its limit")
                    statements[name] = _statement(sql, options)
                    await _audit(runtime, context, "database_prepare", statement_id=hashlib.sha256(name).hexdigest(), **statements[name])
                elif kind == b"B":
                    portal, offset = _cstring(payload)
                    statement, _ = _cstring(payload, offset)
                    if len(portals) >= 10000 and portal not in portals:
                        raise ProtocolError("prepared portal count exceeds its limit")
                    portals[portal] = statement
                    # Bind payload contains secrets/parameters and is never read
                    # into any audit object.
                elif kind == b"E":
                    portal, _ = _cstring(payload)
                    statement = statements.get(portals.get(portal, b""), {})
                    query = dict(statement, operation_id=secrets.token_hex(16), prepared=True)
                    await _audit(runtime, context, "database_query", **query)
                    pending.append(query)
                elif kind == b"C" and payload:
                    name, _ = _cstring(payload, 1)
                    (statements if payload[:1] == b"S" else portals).pop(name, None)
                elif kind == b"S":
                    # Keep ReadyForQuery boundaries even when a pipelined next
                    # query is already queued before the current result arrives.
                    pending.append({"sync": True})
                elif kind in (b"F",):
                    raise ProtocolError("legacy PostgreSQL fast-path calls are not supported")
                elif kind not in (b"H", b"S", b"X", b"d", b"c", b"f", b"D", b"Q", b"P", b"B", b"E", b"C"):
                    raise ProtocolError("unknown PostgreSQL frontend message")
                if len(pending) > 10000:
                    raise ProtocolError("database pipeline exceeds its limit")
                await _write(writer, packet)
                if kind == b"X":
                    return

        async def backend():
            while True:
                kind, payload, packet = await _pg_packet(reader, maximum)
                if kind in (b"C", b"E", b"s") and pending and not pending[0].get("sync"):
                    query = pending[0]
                    result = {"operation_id": query["operation_id"], "prepared": query.get("prepared", False),
                              "result": "failed" if kind == b"E" else "suspended" if kind == b"s" else "completed"}
                    if kind == b"E":
                        fields = payload.split(b"\0")
                        code = next((item[1:].decode("ascii", "ignore") for item in fields if item[:1] == b"C"), "")
                        if re.fullmatch(r"[A-Z0-9]{5}", code):
                            result["sqlstate"] = code
                    else:
                        tag = payload.rstrip(b"\0").decode("ascii", "ignore")
                        if re.fullmatch(r"[A-Z0-9_ ]{1,128}", tag):
                            result["command_tag"] = tag
                    if query.get("prepared"):
                        pending.popleft()
                        await _audit(runtime, context, "database_result", **result)
                    else:
                        # A simple-query message can contain several statements.
                        # Wait for its ReadyForQuery, so a later error cannot be
                        # hidden behind the first statement's CommandComplete.
                        previous = query.get("_result", {})
                        result["command_count"] = previous.get("command_count", 0) + (kind == b"C")
                        query["_result"] = result
                if kind == b"Z":
                    while pending:
                        query = pending.popleft()
                        if query.get("sync"):
                            break
                        if not query.get("prepared"):
                            result = query.get("_result", {"operation_id": query["operation_id"],
                                "prepared": False, "result": "completed", "command_count": 0})
                            await _audit(runtime, context, "database_result", **result)
                            break
                        # PostgreSQL skips pipelined Execute messages after an
                        # error until Sync. Do not claim those queries completed.
                        await _audit(runtime, context, "database_result", operation_id=query["operation_id"],
                            prepared=True, result="not-executed")
                    portals.pop(b"", None)
                if kind == b"K":
                    raise ProtocolError("unexpected PostgreSQL cancellation-key change")
                await client.write(packet)
        await _duplex(frontend(), backend())
    finally:
        _LIVE.pop(context["connection_id"], None)
        if registry:
            await asyncio.to_thread(runtime.redis.delete, registry)
        if writer:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.to_thread(credential_context.__exit__, None, None, None)


async def _duplex(left, right):
    tasks = (asyncio.create_task(left), asyncio.create_task(right))
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    except (EOFError, asyncio.IncompleteReadError):
        return
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _mysql_packet(reader, maximum=_MAX_PACKET):
    header = await reader.readexactly(4)
    size = int.from_bytes(header[:3], "little")
    if size > maximum:
        raise ProtocolError("MySQL packet exceeds its configured limit")
    payload = await reader.readexactly(size)
    return header[3], payload, header + payload


def _mysql_message(payload, sequence):
    if len(payload) > 0xFFFFFF:
        raise ProtocolError("MySQL packet exceeds its wire limit")
    return len(payload).to_bytes(3, "little") + bytes([sequence & 255]) + payload


def _mysql_greeting(payload):
    if not payload or payload[0] != 10:
        raise ProtocolError("MySQL protocol 10 is required")
    _, offset = _cstring(payload, 1)
    if len(payload) < offset + 31:
        raise ProtocolError("invalid MySQL greeting")
    process_id = int.from_bytes(payload[offset:offset + 4], "little")
    salt = payload[offset + 4:offset + 12]
    low = int.from_bytes(payload[offset + 13:offset + 15], "little")
    charset, status = payload[offset + 15], int.from_bytes(payload[offset + 16:offset + 18], "little")
    high = int.from_bytes(payload[offset + 18:offset + 20], "little")
    capabilities = low | high << 16
    auth_length = payload[offset + 20]
    position = offset + 31
    remaining = max(13, auth_length - 8)
    salt += payload[position:position + remaining]
    plugin = payload[position + remaining:].split(b"\0", 1)[0].decode("ascii") if capabilities & 0x80000 else "mysql_native_password"
    return {"process_id": process_id, "salt": salt[:20], "plugin": plugin, "capabilities": capabilities,
            "charset": charset, "status": status}


def _mysql_scramble(plugin, password, salt):
    password = password.encode("utf-8")
    if not password:
        return b""
    if plugin == "mysql_native_password":
        first = hashlib.sha1(password).digest()
        third = hashlib.sha1(salt + hashlib.sha1(first).digest()).digest()
    elif plugin == "caching_sha2_password":
        first = hashlib.sha256(password).digest()
        third = hashlib.sha256(hashlib.sha256(first).digest() + salt).digest()
    elif plugin == "sha256_password":
        return password + b"\0"  # Only used after mandatory verified TLS.
    else:
        raise ProtocolError("unsupported MySQL authentication plugin")
    return bytes(left ^ right for left, right in zip(first, third))


def _lenenc(data, offset=0):
    if offset >= len(data):
        raise ProtocolError("invalid MySQL length-encoded integer")
    first = data[offset]
    if first < 251:
        return first, offset + 1
    size = {252: 2, 253: 3, 254: 8}.get(first)
    if size is None or offset + 1 + size > len(data):
        raise ProtocolError("invalid MySQL length-encoded integer")
    return int.from_bytes(data[offset + 1:offset + 1 + size], "little"), offset + 1 + size


def _mysql_response(payload):
    if len(payload) < 32:
        raise ProtocolError("invalid MySQL handshake response")
    capabilities = int.from_bytes(payload[:4], "little")
    username, offset = _cstring(payload, 32)
    if capabilities & 0x200000:
        size, offset = _lenenc(payload, offset)
        if offset + size > len(payload):
            raise ProtocolError("invalid MySQL authentication response")
        auth, offset = payload[offset:offset + size], offset + size
    elif capabilities & 0x8000:
        if offset >= len(payload):
            raise ProtocolError("invalid MySQL authentication response")
        size = payload[offset]
        auth, offset = payload[offset + 1:offset + 1 + size], offset + 1 + size
    else:
        auth, offset = _cstring(payload, offset)
    database = None
    if capabilities & 8:
        database, offset = _cstring(payload, offset)
        database = database.decode("utf-8")
    plugin = "mysql_native_password"
    if capabilities & 0x80000:
        value, offset = _cstring(payload, offset)
        plugin = value.decode("ascii")
    return capabilities, payload[8], username, auth, database, plugin


async def _mysql_authenticate(reader, writer, greeting, capabilities, charset, username, password, database):
    capabilities = capabilities & greeting["capabilities"] | 0x800 | 0x200 | 0x8000
    # Native connection attributes are untrusted local metadata; never forward
    # them into database authorization or server audit attribution.
    capabilities &= ~0x100000
    prefix = struct.pack("<IIB", capabilities, _MAX_PACKET, charset) + b"\0" * 23
    await _write(writer, _mysql_message(prefix, 1))
    tls = ssl.create_default_context(cafile=greeting["target"].get("ca_file"))
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    await writer.start_tls(tls, server_hostname=greeting["target"]["hostname"])
    plugin, salt = greeting["plugin"], greeting["salt"]
    auth = _mysql_scramble(plugin, password, salt)
    response = prefix + username.encode() + b"\0" + bytes([len(auth)]) + auth
    if capabilities & 8:
        response += database.encode() + b"\0"
    if capabilities & 0x80000:
        response += plugin.encode() + b"\0"
    await _write(writer, _mysql_message(response, 2))
    for _ in range(12):
        sequence, payload, _ = await _mysql_packet(reader, 1048576)
        if payload[:1] == b"\x00":
            return payload
        if payload[:1] == b"\xff":
            raise ProtocolError("MySQL upstream authentication failed")
        if payload[:1] == b"\xfe":
            name, offset = _cstring(payload, 1)
            plugin = name.decode("ascii")
            salt = payload[offset:-1] if payload[-1:] == b"\0" else payload[offset:]
            response = _mysql_scramble(plugin, password, salt)
        elif payload == b"\x01\x03" and plugin == "caching_sha2_password":
            continue
        elif payload == b"\x01\x04" and plugin == "caching_sha2_password":
            response = password.encode() + b"\0"
        else:
            raise ProtocolError("unsupported MySQL authentication exchange")
        await _write(writer, _mysql_message(response, sequence + 1))
    raise ProtocolError("MySQL authentication exceeded its exchange limit")


class MySQLAuditState:
    """Observe framing/status without reading or retaining result row values."""
    def __init__(self, options):
        self.options, self.statements, self.active = options, {}, None

    def command(self, payload):
        if not payload:
            raise ProtocolError("empty MySQL command")
        command = payload[0]
        if command == 0x11:
            raise ProtocolError("MySQL user switching is forbidden")
        if self.active is not None:
            raise ProtocolError("MySQL command pipelining is not supported")
        metadata = {"operation_id": secrets.token_hex(16), "command": command, "prepared": False}
        if command in (0x03, 0x16):
            metadata.update(_statement(payload[1:], self.options))
        elif command in (0x17, 0x18, 0x19, 0x1A, 0x1C):
            if len(payload) < 5:
                raise ProtocolError("invalid MySQL prepared statement command")
            statement_id = int.from_bytes(payload[1:5], "little")
            if statement_id not in self.statements:
                raise ProtocolError("unknown MySQL prepared statement")
            metadata.update(self.statements[statement_id], prepared=True)
            if command == 0x19:
                self.statements.pop(statement_id, None)
        elif command == 0x02:
            database = payload[1:].decode("utf-8")
            if database not in self.options["databases"]:
                raise ProtocolError("MySQL database is outside the configured allowlist")
            metadata["database"] = database
        elif command not in (1, 4, 9, 0x0C, 0x0E, 0x1B, 0x1F):
            raise ProtocolError("unsupported MySQL command")
        if command == 0x1F:
            self.statements.clear()
        event = "database_prepare" if command == 0x16 else "database_query" if command in (3, 0x17, 0x1C) else "database_command"
        if command not in (1, 0x18, 0x19):
            self.active = dict(metadata, first=True, columns=None, field_eof=False, rows=False, row_count=0,
                               response_bytes=0, prepare_remaining=None)
        return event, metadata

    def response(self, payload):
        state = self.active
        if state is None:
            raise ProtocolError("unexpected MySQL response outside a command")
        state["response_bytes"] += len(payload)
        command = state["command"]
        done, result, status, sqlstate = False, "completed", 0, None
        if payload[:1] == b"\xff":
            done, result = True, "failed"
            candidate = payload[4:9].decode("ascii", "ignore") if payload[3:4] == b"#" else ""
            sqlstate = candidate if re.fullmatch(r"[A-Z0-9]{5}", candidate) else None
        elif command == 0x16:
            if state["first"]:
                if len(payload) < 12 or payload[0] != 0:
                    raise ProtocolError("invalid MySQL prepared-statement response")
                statement_id = int.from_bytes(payload[1:5], "little")
                columns, parameters = int.from_bytes(payload[5:7], "little"), int.from_bytes(payload[7:9], "little")
                if len(self.statements) >= 10000:
                    raise ProtocolError("MySQL prepared statement count exceeds its limit")
                self.statements[statement_id] = {key: value for key, value in state.items() if key.startswith("statement_")}
                state["prepare_remaining"] = columns + parameters + bool(columns) + bool(parameters)
                state["first"] = False
            else:
                state["prepare_remaining"] -= 1
            done = state["prepare_remaining"] == 0
        elif command == 9:
            done = True
        elif command in (4, 0x1C):
            if payload[:1] == b"\xfe" and len(payload) < 9:
                done = True
                status = int.from_bytes(payload[3:5], "little")
            elif command == 0x1C:
                state["row_count"] += 1
        elif state["first"]:
            state["first"] = False
            if payload[:1] == b"\x00":
                _, offset = _lenenc(payload, 1)
                _, offset = _lenenc(payload, offset)
                status = int.from_bytes(payload[offset:offset + 2], "little")
                done = True
            elif payload[:1] == b"\xfe" and len(payload) < 9:
                done = True
                status = int.from_bytes(payload[3:5], "little")
            elif payload[:1] == b"\xfb":
                raise ProtocolError("MySQL LOCAL INFILE requests are forbidden")
            else:
                state["columns"], _ = _lenenc(payload)
                if not 1 <= state["columns"] <= 65536:
                    raise ProtocolError("invalid MySQL result column count")
        elif state["columns"] is not None and state["columns"] > 0:
            state["columns"] -= 1
            if state["columns"] == 0:
                state["field_eof"] = True
        elif state["field_eof"]:
            if payload[:1] != b"\xfe" or len(payload) >= 9:
                raise ProtocolError("MySQL field EOF marker is missing")
            state["field_eof"], state["rows"] = False, True
            status = int.from_bytes(payload[3:5], "little")
            if status & 0x40:
                done, result = True, "cursor"
        elif state["rows"]:
            if payload[:1] == b"\xfe" and len(payload) < 9:
                done = True
                status = int.from_bytes(payload[3:5], "little")
            else:
                state["row_count"] += 1
        else:
            raise ProtocolError("unexpected MySQL result packet")
        if done and status & 8:
            state.update(first=True, columns=None, field_eof=False, rows=False)
            return None
        if done:
            self.active = None
            result = {"operation_id": state["operation_id"], "command": command, "prepared": state["prepared"],
                "result": result, "row_count": state["row_count"], "response_bytes": state["response_bytes"]}
            if sqlstate:
                result["sqlstate"] = sqlstate
            return result
        return None


async def _mysql(runtime, context, target, raw, websocket, frontend_password):
    options = validate_database_target(target)
    reader, writer = await asyncio.open_connection(target["address"], target["port"])
    credential_context, credentials = None, None
    try:
        sequence, payload, _ = await _mysql_packet(reader, 65536)
        if sequence != 0:
            raise ProtocolError("invalid MySQL greeting sequence")
        greeting = _mysql_greeting(payload)
        greeting["target"] = target
        capabilities = greeting["capabilities"] & _MY_CAP
        if capabilities & (0x800 | 0x200 | 0x8000) != (0x800 | 0x200 | 0x8000):
            raise ProtocolError("MySQL upstream requires native TLS and protocol 4.1")
        # Several native clients treat the advertised plugin data as a C string.
        # Exclude NUL as MySQL servers do, avoiding intermittent auth failures.
        salt = bytes(secrets.randbelow(255) + 1 for _ in range(20))
        # The database connection ID is not a login credential; retaining it
        # keeps native mysql query-cancellation semantics (KILL QUERY) intact.
        frontend = (b"\x0a8.0.0-Isolate\0" + struct.pack("<I", greeting["process_id"]) + salt[:8] + b"\0"
            + struct.pack("<H", capabilities & 65535) + bytes([greeting["charset"]]) + struct.pack("<H", greeting["status"])
            + struct.pack("<H", capabilities >> 16) + bytes([21]) + b"\0" * 10 + salt[8:] + b"\0mysql_native_password\0")
        await websocket.send_bytes(_mysql_message(frontend, 0))
        sequence, tls_request, _ = await _mysql_packet(raw, 65536)
        if sequence != 1 or len(tls_request) != 32 or not int.from_bytes(tls_request[:4], "little") & 0x800:
            raise ProtocolError("MySQL client must negotiate native TLS")
        client = _TLSStream(raw, websocket, options)
        await client.handshake()
        sequence, handshake, _ = await _mysql_packet(client, 65536)
        selected, charset, _, supplied, database, plugin = _mysql_response(handshake)
        # Clients may advertise extra support (MariaDB does this for LOCAL_FILES
        # and SESSION_TRACK). Only the intersection is negotiated and forwarded;
        # unsupported compression, infile and session extensions stay disabled.
        selected &= capabilities
        if (sequence != 2 or plugin != "mysql_native_password"
                or selected & (0x200 | 0x8000 | 0x800) != (0x200 | 0x8000 | 0x800)
                or not hmac.compare_digest(supplied, _mysql_scramble(plugin, frontend_password, salt))):
            raise ProtocolError("native MySQL client capability is invalid")
        database = database or options.get("default_database")
        if database not in options["databases"]:
            raise ProtocolError("MySQL database is outside the configured allowlist")
        credential_context = database_credentials(target, context)
        credentials = await asyncio.to_thread(credential_context.__enter__)
        if credentials["expires_at"]:
            context["deadline"] = min(context["deadline"], int(credentials["expires_at"]))
        # If no DB was sent by the client, choose the trusted default and turn
        # on CONNECT_WITH_DB for this upstream authentication only.
        selected |= 8
        authenticated = await _mysql_authenticate(reader, writer, greeting, selected, charset,
            credentials["username"], credentials["password"], database)
        await client.write(_mysql_message(authenticated, 3))
        state = MySQLAuditState(options)
        maximum = options.get("max_packet_bytes", _MAX_PACKET)

        async def frontend_messages():
            while True:
                sequence, payload, packet = await _mysql_packet(client, maximum)
                if sequence != 0:
                    raise ProtocolError("MySQL command must start with sequence zero")
                # A physical packet exactly 0xffffff long requires continuation;
                # bound the logical command before observing or forwarding it.
                logical, packets = bytearray(payload), [packet]
                while len(payload) == 0xFFFFFF:
                    previous = sequence
                    sequence, payload, packet = await _mysql_packet(client, maximum)
                    if sequence != (previous + 1) & 255 or len(logical) + len(payload) > maximum:
                        raise ProtocolError("MySQL command continuation is invalid or oversized")
                    logical.extend(payload)
                    packets.append(packet)
                event, metadata = state.command(bytes(logical))
                if logical[0] == 0x18:
                    metadata["parameter_bytes"] = max(0, len(logical) - 7)
                await _audit(runtime, context, event, **metadata)
                for packet in packets:
                    await _write(writer, packet)
                if logical[0] == 1:
                    return

        async def backend_messages():
            while True:
                sequence, payload, packet = await _mysql_packet(reader, maximum)
                # Result rows may span physical packets. Reassemble only within
                # the bounded logical limit, never retain them in audit state.
                logical, packets = bytearray(payload), [packet]
                while len(payload) == 0xFFFFFF:
                    previous = sequence
                    sequence, payload, packet = await _mysql_packet(reader, maximum)
                    if sequence != (previous + 1) & 255 or len(logical) + len(payload) > maximum:
                        raise ProtocolError("MySQL response continuation is invalid or oversized")
                    logical.extend(payload)
                    packets.append(packet)
                result = state.response(bytes(logical))
                if result:
                    await _audit(runtime, context, "database_result", **result)
                for packet in packets:
                    await client.write(packet)
        await asyncio.wait_for(_duplex(frontend_messages(), backend_messages()), timeout=max(0, context["deadline"] - time.time()))
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        if credentials is not None:
            await asyncio.to_thread(credential_context.__exit__, None, None, None)


async def proxy_database_session(runtime, context, target, client_reader, websocket, *, frontend_password):
    """Serve a brokered session after Runtime prepare/start and before finish.

    The gateway continues to run its normal recheck guard around this coroutine.
    No bearer token or ticket is accepted here: those have already selected and
    authorized context. A client capability is independent from DB credentials.
    """
    options = validate_database_target(target)
    if (not isinstance(frontend_password, str) or not 32 <= len(frontend_password) <= 1024
            or any(ord(c) < 33 or ord(c) > 126 for c in frontend_password)):
        raise ProtocolError("a private native-client capability of at least 32 characters is required")
    context["audit_profile"] = "sql-query"
    stats = context.setdefault("protocol_stats", {"received_bytes": 0, "sent_bytes": 0})

    class MeasuredTransport:
        # Count the native client's wire bytes, including native TLS, without
        # retaining authentication or SQL payloads in connection metadata.
        async def read(self, maximum=65536):
            data = await client_reader.read(maximum)
            stats["received_bytes"] += len(data)
            return data

        async def readexactly(self, size):
            data = await client_reader.readexactly(size)
            stats["received_bytes"] += len(data)
            return data

        async def send_bytes(self, data):
            await websocket.send_bytes(data)
            stats["sent_bytes"] += len(data)

    transport = MeasuredTransport()
    timeout = max(0, context["deadline"] - time.time())
    operation = _postgresql if target["protocol"] == "postgresql" else _mysql
    await asyncio.wait_for(operation(runtime, context, target, transport, transport, frontend_password), timeout=timeout)
