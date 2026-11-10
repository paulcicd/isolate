"""Scoped investigation timeline using explicit, bounded evidence references.

The audit index is a searchable projection, not a replacement for signed JSONL
or archived recordings. No correlation is inferred from usernames or proximity
in time, and missing capture is never presented as a completed lifecycle.
"""
import hashlib
import json
import math
import re
import time

from isolate_audit_index import AuditIndex
from isolate_permissions import has_permission, is_platform_admin


KINDS = {
    "connection": ("connection_id", "session_id", "parent_connection_id"),
    "request": ("access_request_id",), "approval": ("session_approval_id",),
    "job": ("job_id", "retry_of"), "campaign": ("campaign_id",),
    "grant": ("grant_id",), "identity-session": ("identity_session_sha256",),
}
STAGES = ("authentication", "access", "approval", "session", "command", "result")
SAFE_FIELDS = frozenset({"event_id", "event", "ts", "username", "keycloak_sub", "project", "host_id",
    "connection_id", "session_id", "parent_connection_id", "access_request_id", "session_approval_id", "job_id",
    "campaign_id", "grant_id", "identity_session_sha256", "outcome", "status", "exit_code", "result", "protocol",
    "remote_user", "command_sha256", "statement_sha256", "statement_kind", "operation", "action", "source",
    "audit_profile", "reason_code", "command_count", "output_bytes", "bytes", "sqlstate"})
SAFE_FIELDS = SAFE_FIELDS | {'decision', 'target_subject', 'requester_sub', 'review_id', 'assignment_id', 'offboarding_id'}


class InvestigationError(ValueError):
    pass


def identity_session_reference(identity):
    claims = (identity or {}).get("raw_claims") or {}
    sid = claims.get("sid") or claims.get("session_state")
    issuer = claims.get("iss")
    if not isinstance(sid, str) or not sid or not isinstance(issuer, str) or not issuer:
        return None
    return hashlib.sha256(json.dumps([issuer, sid], separators=(",", ":")).encode()).hexdigest()


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}", value):
        raise InvestigationError("invalid investigation identifier")
    return value


def _timestamp(value):
    try:
        number = float(value)
    except (ValueError, TypeError):
        raise InvestigationError("invalid timeline timestamp") from None
    if not math.isfinite(number) or not 0 <= number <= 253402300799:
        raise InvestigationError("invalid timeline timestamp")
    return number


def stage(record):
    event = str(record.get("event") or "").lower()
    action = str(record.get("action") or "").lower()
    if event.startswith("identity_") or action in ("login", "logout"):
        return "authentication"
    if "approval" in event or "session_approve" in action:
        return "approval"
    if event.startswith(("access_", "governance_")) or "access_request" in action or "grant_" in action:
        return "access"
    if event.endswith(("_end", "_result", "_failed", "_stopped")) or event in ("job_recovery_required", "campaign_complete"):
        return "result"
    if "command" in event or event in ("database_query", "database_prepare", "job_start") or event.startswith("kubernetes_operation"):
        return "command"
    return "session"


def _references(record):
    # Grant IDs are deliberately not followed automatically: a group grant can
    # cover thousands of unrelated users. Investigate that grant explicitly.
    result = {}
    for name in ("connection_id", "session_id", "parent_connection_id", "access_request_id", "session_approval_id",
                 "job_id", "retry_of", "campaign_id", "identity_session_sha256"):
        value = record.get(name)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            try:
                result[name] = _identifier(str(value))
            except InvestigationError:
                continue
    return result


def _project(record):
    projected = {}
    for name in SAFE_FIELDS:
        value = record.get(name)
        if isinstance(value, (str, int, float, bool)) or value is None:
            if name in record:
                projected[name] = value[:512] if isinstance(value, str) else value
    projected["stage"] = stage(record)
    timestamp = record.get('ts')
    original_time = isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool) and math.isfinite(timestamp)
    projected['ts'] = timestamp if original_time else record['_index_timestamp']
    projected['timestamp_source'] = 'event' if original_time else 'index-ingestion'
    links = {}
    for key, prefix in (("connection_id", "/session/"), ("job_id", "/job/")):
        value = projected.get(key)
        if isinstance(value, (str, int)) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", str(value)):
            links[key] = prefix + str(value)
    projected["links"] = links
    return projected


def timeline(config, identity, filters=None):
    options = config.get("audit_index") or {}
    if not options.get("enabled"):
        raise InvestigationError("the shared audit index is not enabled")
    if not isinstance(identity, dict) or not identity.get("keycloak_sub"):
        raise InvestigationError("a verified identity is required")
    filters = dict(filters or {})
    if set(filters) - {"kind", "id", "subject", "project", "host_id", "since", "until", "before", "limit", "related", "q"}:
        raise InvestigationError("unknown investigation filter")
    index = AuditIndex(options)
    admin = is_platform_admin(identity, config)
    scope = None if admin else [project for project in index.projects() if has_permission(identity, config, "audit.read", project)]
    limit = filters.get("limit", 100)
    try:
        maximum = int(limit)
    except (ValueError, TypeError):
        raise InvestigationError("invalid timeline limit") from None
    if isinstance(limit, bool) or str(maximum) != str(limit) or not 1 <= maximum <= 200:
        raise InvestigationError("timeline limit must be between 1 and 200")
    arguments = {"subject": None if admin else identity["keycloak_sub"], "projects": scope,
                 "limit": maximum, "query": filters.get("q"), "include_index_time": True}
    for name, target in (("subject", "person_sub"), ("project", "project"), ("host_id", "host_id")):
        if filters.get(name):
            value = str(filters[name])
            if len(value) > 256 or any(ord(c) < 32 for c in value):
                raise InvestigationError("invalid timeline filter")
            arguments[target] = value
    for name in ("since", "until"):
        if filters.get(name) not in (None, ""):
            arguments[name] = _timestamp(filters[name])
    if arguments.get("since", 0) > arguments.get("until", float("inf")):
        raise InvestigationError("timeline time range is reversed")
    if filters.get("before"):
        cursor = filters["before"]
        if not isinstance(cursor, list) or len(cursor) != 2:
            raise InvestigationError("invalid timeline cursor")
        arguments["before"] = [_timestamp(cursor[0]), _identifier(cursor[1])]
    references = None
    kind, identifier = filters.get("kind"), filters.get("id")
    if bool(kind) != bool(identifier) or kind and kind not in KINDS:
        raise InvestigationError("choose one supported entity kind and identifier")
    if kind:
        identifier = _identifier(identifier)
        references = {field: [identifier] for field in KINDS[kind]}
    related = filters.get("related", True)
    if not isinstance(related, bool):
        raise InvestigationError("related must be boolean")
    bounded = False
    if references and related:
        for _ in range(3):
            # Expansion always uses the very same current subject/project
            # visibility predicates, before LIMIT or reference discovery.
            page = index.search(**dict(arguments, references=references, limit=200, before=None))
            changed = False
            for record in page["events"]:
                for field, value in _references(record).items():
                    aliases = next((fields for fields in KINDS.values() if field in fields), (field,))
                    for alias in aliases:
                        values = references.setdefault(alias, [])
                        if value not in values:
                            if len(values) == 64:
                                bounded = True
                                continue
                            values.append(value)
                            changed = True
            bounded = bounded or bool(page["next"])
            if not changed:
                break
        else:
            bounded = True
    page = index.search(**dict(arguments, references=references))
    rows = [_project(record) for record in reversed(page["events"])]
    observed = {record["stage"] for record in rows}
    return {"events": rows, "next": page["next"], "order": "chronological-within-page", "page_direction": "earlier",
        "correlation": "explicit-identifiers" if references else "visible-context", "expansion_bounded": bounded,
        "coverage": {"observed": [item for item in STAGES if item in observed], "not_observed": [item for item in STAGES if item not in observed]},
        "evidence": "search-index-projection", "generated_at": time.time()}
