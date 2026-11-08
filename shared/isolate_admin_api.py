"""Explicitly scoped, revision-checked inventory/policy desired-state API.

No transport credentials or transient grants are writable through this surface.
An idempotency result and its new object commit in the same Redis transaction;
updates recheck scope, ownership and revision against the watched raw record.
"""

import hashlib
import json
import re
import time
import uuid
from functools import wraps

from isolate_audit import AuditSinkError, prepare_and_dispatch
from isolate_identity import IdentityError
from isolate_inventory import HostValidationError, host_revision, normalize_host, validate_host_updates
from isolate_permissions import is_platform_admin
from isolate_policy_bundle import grant_identity, validate_bundle


ID = re.compile(r"^[0-9]{1,20}$")
PROJECT = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
REVISION = re.compile(r"^[a-f0-9]{64}$")
HOST_FIELDS = frozenset({"project_name", "server_name", "server_ip", "server_user", "server_port",
    "server_nosudo", "server_note", "server_services", "proxy_id", "resource_owner", "environment", "tags"})
GRANT_FIELDS = frozenset({"subject", "name", "project", "project_glob", "project_set", "host",
    "remote_user", "sudo_mode", "allowed_actions", "keycloak_sub"})
GRANT_STATUS_FIELDS = frozenset({"managed_by", "temporary", "expires_at", "starts_at"})


class AdminError(Exception):
    def __init__(self, status, error):
        self.status, self.error = status, error


def _json(raw):
    try:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, TypeError, UnicodeError):
        raise AdminError(503, "control_record_invalid") from None


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _revision(kind, record):
    if kind == "host":
        return host_revision(normalize_host(record))
    return hashlib.sha256(_encode({k: v for k, v in record.items() if k not in ("id", "_revision")}).encode()).hexdigest()


def _public(kind, record, resource_id):
    if kind == "host":
        normalized = normalize_host(record)
        value = {key: normalized[key] for key in HOST_FIELDS if key in normalized}
        value["server_id"] = str(resource_id)
    else:
        value = {key: record[key] for key in GRANT_FIELDS | GRANT_STATUS_FIELDS if key in record}
        value["id"] = str(resource_id)
    value["_revision"] = _revision(kind, record)
    return value


def _projects(config, identity, action, browser=False):
    claims = identity.get("raw_claims") or {}
    scope = claims.get("scope") or claims.get("scp") or ""
    if isinstance(scope, str):
        scopes = scope.split()
    elif isinstance(scope, list) and all(isinstance(item, str) for item in scope):
        scopes = scope
    else:
        raise AdminError(403, "explicit_admin_scope_required")
    if not browser or identity.get("principal_type") == "service":
        if "isolate." + action not in scopes:
            raise AdminError(403, "explicit_admin_scope_required")
    if identity.get("principal_type") != "service":
        if not is_platform_admin(identity, config):
            raise AdminError(403, "platform_administrator_required")
        return frozenset({"*"})
    workloads = config.get("identity_security", {}).get("workloads", {})
    client = workloads.get("clients", {}).get(identity.get("service_client_id"))
    if (not workloads.get("enabled") or not isinstance(client, dict)
            or action not in (client.get("allowed_actions") or [])):
        raise AdminError(403, "workload_administration_not_allowed")
    projects = client.get("admin_projects")
    if (not isinstance(projects, list) or not projects
            or any(not isinstance(p, str) or (p != "*" and PROJECT.fullmatch(p) is None) for p in projects)):
        raise AdminError(403, "explicit_admin_projects_required")
    return frozenset(projects)


def _in_scope(kind, record, projects):
    if "*" in projects:
        return True
    if kind == "host":
        return record.get("project_name") in projects
    # Project sets, lists, globs and wildcards can exceed a workload's exact scope.
    return (isinstance(record.get("project"), str) and record["project"] in projects
            and not record.get("project_glob") and not record.get("project_set"))


def _require_scope(kind, record, projects):
    if not _in_scope(kind, record, projects):
        raise AdminError(403, "outside_administrative_projects")


def _protected_grant(record):
    return (bool(record.get("managed_by")) or bool(record.get("temporary"))
            or any(record.get(key) is not None for key in ("expires_at", "starts_at", "request_id", "access_request_id", "package_id")))


def _host_updates(reader, values, projects, resource_id=None):
    if set(values) - HOST_FIELDS:
        raise AdminError(400, "unsupported_host_fields")
    for key, value in values.items():
        if key == "server_port":
            if type(value) is not int:
                raise AdminError(400, "invalid_host_field_type")
        elif key == "server_nosudo":
            if type(value) is not bool:
                raise AdminError(400, "invalid_host_field_type")
        elif key == "tags":
            if not isinstance(value, dict):
                raise AdminError(400, "invalid_host_field_type")
        elif key == "proxy_id":
            if value not in (None, "") and (not isinstance(value, str) or not ID.fullmatch(value)):
                raise AdminError(400, "invalid_proxy_id")
        elif not isinstance(value, str):
            raise AdminError(400, "invalid_host_field_type")
        if isinstance(value, str) and (value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise AdminError(400, "noncanonical_host_field")
    if "project_name" in values and not PROJECT.fullmatch(values["project_name"]):
        raise AdminError(400, "invalid_project_name")
    if "server_name" in values and values["server_name"] != values["server_name"].lower():
        raise AdminError(400, "noncanonical_server_name")
    if "server_user" in values and not values["server_user"]:
        raise AdminError(400, "invalid_server_user")
    # Watch the pinned jump record as part of this commit, and check its scope.
    proxy = values.get("proxy_id")
    if proxy:
        if str(resource_id) == proxy:
            raise AdminError(400, "self_proxy_is_not_allowed")
        key = "server_" + proxy
        reader.watch(key)
        raw = reader.get(key)
        if raw is None:
            raise AdminError(400, "proxy_not_found")
        _require_scope("host", _json(raw), projects)
    result = validate_host_updates(reader, values)
    if "proxy_id" in values and values["proxy_id"] is None:
        result["proxy_id"] = None
    return result


def _grant_updates(reader, values, before=None):
    if set(values) - GRANT_FIELDS:
        raise AdminError(400, "unsupported_grant_fields")
    result = dict(before or {})
    # A new selector replaces the old selector instead of accidentally widening it.
    selectors = [key for key in ("project", "project_glob", "project_set") if key in values]
    if len(selectors) > 1:
        raise AdminError(400, "exactly_one_project_selector_required")
    if selectors:
        for key in ("project", "project_glob", "project_set"):
            result.pop(key, None)
    for key, value in values.items():
        if key == "allowed_actions":
            if (not isinstance(value, list) or not 1 <= len(value) <= 64
                    or any(not isinstance(item, str) or re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", item) is None for item in value)
                    or len(value) != len(set(value))):
                raise AdminError(400, "invalid_allowed_actions")
            value = sorted(value)
        elif (not isinstance(value, str) or len(value) > 512 or value != value.strip()
                or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise AdminError(400, "invalid_grant_field")
        result[key] = value
    if values.get("keycloak_sub") == "":
        result.pop("keycloak_sub", None)
    if result.get("keycloak_sub") and result.get("subject") != "user":
        raise AdminError(400, "subject_binding_requires_user")
    if not result.get("name") or len(result["name"]) > 256:
        raise AdminError(400, "invalid_subject_name")
    for selector in ("project", "project_glob", "project_set"):
        if selector in result and not result[selector]:
            raise AdminError(400, "empty_project_selector")
    if "project" in result and result["project"] != "*" and not PROJECT.fullmatch(result["project"]):
        raise AdminError(400, "invalid_project_name")
    sets = []
    if result.get("project_set"):
        set_key = "project_set_" + result["project_set"]
        reader.watch(set_key)
        raw = reader.get(set_key)
        if raw is not None:
            sets.append(_json(raw))
    validation = validate_bundle({"schema_version": 2, "grants": [result], "project_sets": sets})
    if not validation["valid"]:
        raise AdminError(400, "invalid_grant")
    return result


def _record_keys(reader, kind):
    prefix = "server_" if kind == "host" else "grant_"
    keys = reader.keys(prefix + "*")
    return sorted(k.decode() if isinstance(k, bytes) else k for k in keys
                  if re.fullmatch(prefix + r"[0-9]{1,20}", k.decode() if isinstance(k, bytes) else k))


def _unique_grant(reader, proposed, own_key=None, store=None):
    # Counter covers concurrent creates; watched objects cover selector updates.
    reader.watch("offset_grant_id")
    keys = _record_keys(store if store is not None else reader, "grant")
    if keys:
        reader.watch(*keys)
    identity = grant_identity(proposed)
    for key in keys:
        raw = reader.get(key)
        if key != own_key and raw is not None:
            existing = _json(raw)
            if not existing.get("temporary") and grant_identity(existing) == identity:
                raise AdminError(409, "grant_selector_already_exists")


def _audit(config, identity, kind, action, resource_id, record, mutation_id):
    prepare_and_dispatch({"event": "admin_" + kind + "_" + action, "source": "isolate-control-api",
        "event_id": mutation_id, "ts": time.time(), "username": identity.get("username"),
        "keycloak_sub": identity["keycloak_sub"], "principal_type": identity.get("principal_type", "human"),
        "project": record.get("project_name" if kind == "host" else "project"),
        "host_id" if kind == "host" else "grant_id": str(resource_id),
        "result": "requested"}, dict(config.get("logging", {}), fail_closed=True))


def register_admin_api(app, config, runtime_factory, bearer, bounded_json, failure, errors):
    from flask import jsonify, request
    from redis.exceptions import WatchError
    from isolate_admission import check_admission

    def guarded(function):
        @wraps(function)
        def invoke(*args, **kwargs):
            try:
                response = function(*args, **kwargs)
            except AdminError as exc:
                response = (jsonify(error=exc.error), exc.status)
            except AuditSinkError:
                response = (jsonify(error="audit_evidence_unavailable"), 503)
            except HostValidationError:
                response = (jsonify(error="invalid_host"), 400)
            except errors as exc:
                response = failure(exc)
            response = app.make_response(response)
            response.headers["Cache-Control"] = "no-store"
            return response
        return invoke

    def context(kind, mutation=False):
        token = bearer(allow_browser=True, mutation=mutation)
        runtime = runtime_factory()
        identity = runtime.authenticate(token)
        action = "inventory.write" if kind == "host" else "policy.write"
        projects = _projects(config, identity, action, browser=not bool(request.headers.get("Authorization")))
        if mutation:
            check_admission(runtime.redis, {"admission": dict(config.get("admission", {}), enabled=True)},
                identity["keycloak_sub"], request.remote_addr, kind="admin")
            if kind == "grant" and config.get("policy_as_code", {}).get("enforce_git"):
                raise AdminError(403, "policy_is_managed_by_git")
        return runtime.redis, identity, projects

    def confirmed(kind=None):
        payload = bounded_json(65536)
        allowed = {"confirm", kind} if kind else {"confirm"}
        if set(payload) != allowed or payload.get("confirm") is not True:
            raise AdminError(400, "explicit_confirmation_and_record_required")
        if kind and (not isinstance(payload[kind], dict) or not payload[kind]):
            raise AdminError(400, "nonempty_record_required")
        return payload.get(kind) if kind else None

    def expected_revision():
        value = request.headers.get("If-Match")
        if value is None:
            raise AdminError(428, "revision_required")
        if len(value) == 66 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if not REVISION.fullmatch(value):
            raise AdminError(400, "invalid_revision")
        return value

    def collection(kind):
        redis, identity, projects = context(kind, request.method == "POST")
        prefix = "server_" if kind == "host" else "grant_"
        plural = kind + "s"
        if request.method == "GET":
            values = []
            for key in _record_keys(redis, kind):
                raw = redis.get(key)
                if raw is not None:
                    record = _json(raw)
                    if _in_scope(kind, record, projects):
                        values.append(_public(kind, record, key[len(prefix):]))
            return jsonify({plural: values})
        values = confirmed(kind)
        key = request.headers.get("Idempotency-Key", "")
        if not 16 <= len(key) <= 128 or any(ord(c) < 33 or ord(c) > 126 for c in key):
            raise AdminError(400, "valid_idempotency_key_required")
        digest = hashlib.sha256(_encode(values).encode()).hexdigest()
        intent_key = "admin_create_" + hashlib.sha256((identity["keycloak_sub"] + ":" + kind + ":" + key).encode()).hexdigest()
        counter = "offset_server_id" if kind == "host" else "offset_grant_id"
        mutation_id = str(uuid.uuid4())
        for _ in range(12):
            with redis.pipeline(transaction=True) as pipe:
                try:
                    pipe.watch(intent_key, counter)
                    existing = pipe.get(intent_key)
                    if existing is not None:
                        existing = _json(existing)
                        if existing.get("digest") != digest:
                            raise AdminError(409, "idempotency_conflict")
                        # Reauthorization also applies to cached creates after scope changes.
                        result_id = existing["result"][kind]["server_id" if kind == "host" else "id"]
                        current = pipe.get(prefix + result_id)
                        if current is None or _json(current).get("_admin_create_id") != existing.get("creation_id"):
                            raise AdminError(409, "created_object_requires_reconciliation")
                        current = _json(current)
                        _require_scope(kind, current, projects)
                        return jsonify({kind: _public(kind, current, result_id)}), 200
                    offset = int(pipe.get(counter) or (10000 if kind == "host" else 0))
                    for _candidate in range(10000):
                        offset += 1
                        if offset > 99999999999999999999:
                            raise AdminError(503, "resource_id_exhausted")
                        object_key = prefix + str(offset)
                        pipe.watch(object_key)
                        if pipe.get(object_key) is None:
                            break
                    else:
                        raise AdminError(409, "resource_id_allocation_requires_review")
                    if kind == "host":
                        required = ("project_name", "server_name", "server_ip", "server_user")
                        if any(not values.get(field) for field in required):
                            raise AdminError(400, "required_host_fields_missing")
                        record = dict(server_id=offset, server_port=22, server_nosudo=False,
                            server_services="", server_note="", tags={}, proxy_id=None,
                            resource_owner="", environment="")
                        record.update(_host_updates(pipe, values, projects, str(offset)))
                    else:
                        record = _grant_updates(pipe, dict({"sudo_mode": "none", "allowed_actions": ["ssh"], "host": ""}, **values))
                        record["schema_version"] = 2
                        _unique_grant(pipe, record, store=redis)
                    _require_scope(kind, record, projects)
                    record.update(updated_by=identity["keycloak_sub"], updated_at=int(time.time()), _admin_create_id=mutation_id)
                    result = {kind: _public(kind, record, offset)}
                    _audit(config, identity, kind, "create", offset, record, mutation_id)
                    pipe.multi()
                    pipe.set(counter, offset)
                    pipe.set(object_key, _encode(record))
                    pipe.set(intent_key, _encode({"digest": digest, "result": result, "creation_id": mutation_id}))
                    pipe.execute()
                    return jsonify(result), 201
                except WatchError:
                    continue
        raise AdminError(409, "concurrent_change_retry_required")

    def item(kind, resource_id):
        if not ID.fullmatch(resource_id):
            raise AdminError(404, "resource_not_found")
        mutation = request.method != "GET"
        redis, identity, projects = context(kind, mutation)
        key = ("server_" if kind == "host" else "grant_") + resource_id
        if not mutation:
            raw = redis.get(key)
            if raw is None:
                raise AdminError(404, "resource_not_found")
            record = _json(raw)
            if not _in_scope(kind, record, projects):
                raise AdminError(404, "resource_not_found")
            return jsonify({kind: _public(kind, record, resource_id)})
        values = confirmed(kind if request.method == "PUT" else None)
        expected = expected_revision()
        mutation_id = str(uuid.uuid4())
        for _ in range(12):
            with redis.pipeline(transaction=True) as pipe:
                try:
                    pipe.watch(key)
                    raw = pipe.get(key)
                    if raw is None:
                        raise AdminError(404, "resource_not_found")
                    before = _json(raw)
                    _require_scope(kind, before, projects)
                    if kind == "grant" and _protected_grant(before):
                        raise AdminError(403, "grant_has_external_owner")
                    if _revision(kind, before) != expected:
                        raise AdminError(409, "revision_conflict")
                    if request.method == "PUT":
                        if kind == "host":
                            record = dict(before, **_host_updates(pipe, values, projects, resource_id))
                        else:
                            record = _grant_updates(pipe, values, before)
                            _unique_grant(pipe, record, key, store=redis)
                        _require_scope(kind, record, projects)
                        record.update(updated_by=identity["keycloak_sub"], updated_at=int(time.time()))
                    else:
                        record = before
                        if kind == "host":
                            # Do not leave another managed host pointing to a deleted jump.
                            pipe.watch("offset_server_id")
                            host_keys = _record_keys(redis, "host")
                            if host_keys:
                                pipe.watch(*host_keys)
                            for host_key in host_keys:
                                other = pipe.get(host_key)
                                if other and str(_json(other).get("proxy_id") or "") == resource_id:
                                    raise AdminError(409, "host_is_referenced_as_proxy")
                    action = "update" if request.method == "PUT" else "delete"
                    _audit(config, identity, kind, action, resource_id, record, mutation_id)
                    pipe.multi()
                    if request.method == "PUT":
                        pipe.set(key, _encode(record))
                    else:
                        pipe.delete(key)
                    pipe.execute()
                    if request.method == "DELETE":
                        return "", 204
                    return jsonify({kind: _public(kind, record, resource_id)})
                except WatchError:
                    continue
        raise AdminError(409, "concurrent_change_retry_required")

    @app.route("/api/v1/admin/hosts", methods=["GET", "POST"])
    @guarded
    def api_admin_hosts():
        return collection("host")

    @app.route("/api/v1/admin/hosts/<host_id>", methods=["GET", "PUT", "DELETE"])
    @guarded
    def api_admin_host(host_id):
        return item("host", host_id)

    @app.route("/api/v1/admin/grants", methods=["GET", "POST"])
    @guarded
    def api_admin_grants():
        return collection("grant")

    @app.route("/api/v1/admin/grants/<grant_id>", methods=["GET", "PUT", "DELETE"])
    @guarded
    def api_admin_grant(grant_id):
        return item("grant", grant_id)
