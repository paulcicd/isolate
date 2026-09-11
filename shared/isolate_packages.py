#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Versioned access package templates backed by existing Isolate grants."""

import copy
import json
import re
import time

from isolate_access import parse_duration


class AccessPackageError(Exception):
    pass


_REMOTE_USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
_SUBJECTS = {"user", "group", "role"}
_ACTIONS = {"ssh", "command", "runbook", "operate"}
_STATUSES = {"enabled", "disabled"}


def _decode(value):
    return value.decode("utf-8") if isinstance(value, bytes) else value


def _json(value):
    return json.loads(_decode(value))


def _key_name(value):
    return str(_decode(value))


def _now(now=None):
    return int(time.time() if now is None else now)


def _unique_strings(values):
    result = []
    for value in values or []:
        text = str(value).strip()
        if text and text not in result:
            result.append(text)
    return result


def _package_reference_matches(record, reference):
    value = str(reference or "").strip()
    return str(record.get("id")) == value or str(record.get("name") or "").casefold() == value.casefold()


def normalize_package(payload, current=None, actor=None, now=None, max_rules=100):
    if not isinstance(payload, dict):
        raise AccessPackageError("access package must be an object")
    current = current or {}
    name = str(payload.get("name") if "name" in payload else current.get("name") or "").strip()
    if not name or len(name) > 120:
        raise AccessPackageError("package name is required and must not exceed 120 characters")
    description = str(payload.get("description") if "description" in payload else current.get("description") or "").strip()
    if len(description) > 1000:
        raise AccessPackageError("package description must not exceed 1000 characters")
    status = str(payload.get("status") if "status" in payload else current.get("status") or "enabled").lower()
    if status not in _STATUSES:
        raise AccessPackageError("package status must be enabled or disabled")

    raw_access = payload.get("access") if "access" in payload else current.get("access")
    if not isinstance(raw_access, list) or not raw_access:
        raise AccessPackageError("package access must contain at least one rule")
    if len(raw_access) > int(max_rules or 100):
        raise AccessPackageError("package access exceeds the configured rule limit")
    access = []
    seen_rule_ids = set()
    seen_selectors = set()
    for index, raw_rule in enumerate(raw_access, 1):
        if not isinstance(raw_rule, dict):
            raise AccessPackageError("package access rule {} must be an object".format(index))
        rule_id = str(raw_rule.get("id") or "rule-{}".format(index)).strip()
        if not rule_id or len(rule_id) > 64 or rule_id in seen_rule_ids:
            raise AccessPackageError("package access rule ids must be unique and at most 64 characters")
        seen_rule_ids.add(rule_id)
        selectors = [key for key in ("project", "project_glob", "project_set") if raw_rule.get(key)]
        if len(selectors) != 1:
            raise AccessPackageError("access rule {} requires exactly one project selector".format(rule_id))
        remote_user = str(raw_rule.get("remote_user") or "").strip()
        if not _REMOTE_USER_RE.match(remote_user):
            raise AccessPackageError("access rule {} has an invalid remote_user".format(rule_id))
        sudo_mode = str(raw_rule.get("sudo_mode") or "none").strip()
        if sudo_mode not in ("none", "sudo-i"):
            raise AccessPackageError("access rule {} sudo_mode must be none or sudo-i".format(rule_id))
        actions = _unique_strings(raw_rule.get("allowed_actions") or ["ssh"])
        unknown_actions = [action for action in actions if action not in _ACTIONS]
        if unknown_actions:
            raise AccessPackageError("access rule {} has unsupported actions: {}".format(rule_id, ", ".join(unknown_actions)))
        rule = {
            "id": rule_id,
            "project": str(raw_rule.get("project")).strip() if raw_rule.get("project") else None,
            "project_glob": str(raw_rule.get("project_glob")).strip() if raw_rule.get("project_glob") else None,
            "project_set": str(raw_rule.get("project_set")).strip() if raw_rule.get("project_set") else None,
            "host": str(raw_rule.get("host")).strip() if raw_rule.get("host") else None,
            "remote_user": remote_user,
            "sudo_mode": sudo_mode,
            "allowed_actions": actions,
        }
        selector_type = selectors[0]
        selector_identity = (selector_type, rule[selector_type], rule.get("host") or "")
        if selector_identity in seen_selectors:
            raise AccessPackageError("package contains duplicate access selector: {}".format(rule_id))
        seen_selectors.add(selector_identity)
        access.append(rule)

    raw_lifecycle = dict(current.get("lifecycle") or {})
    if "lifecycle" in payload:
        if not isinstance(payload.get("lifecycle"), dict):
            raise AccessPackageError("package lifecycle must be an object")
        raw_lifecycle.update(payload.get("lifecycle") or {})
    if not isinstance(raw_lifecycle, dict):
        raise AccessPackageError("package lifecycle must be an object")
    default_ttl = raw_lifecycle.get("default_ttl")
    max_ttl = raw_lifecycle.get("max_ttl")
    permanent_allowed = bool(raw_lifecycle.get("permanent_allowed", True))
    if default_ttl not in (None, ""):
        try:
            parse_duration(default_ttl)
        except (TypeError, ValueError) as exc:
            raise AccessPackageError("invalid default_ttl: {}".format(exc)) from exc
        default_ttl = str(default_ttl)
    else:
        default_ttl = None
    if max_ttl not in (None, ""):
        try:
            max_seconds = parse_duration(max_ttl)
        except (TypeError, ValueError) as exc:
            raise AccessPackageError("invalid max_ttl: {}".format(exc)) from exc
        max_ttl = str(max_ttl)
        if default_ttl and parse_duration(default_ttl) > max_seconds:
            raise AccessPackageError("default_ttl cannot exceed max_ttl")
    else:
        max_ttl = None
    if not permanent_allowed and not default_ttl:
        raise AccessPackageError("default_ttl is required when permanent assignments are disabled")

    raw_approval = dict(current.get("approval") or {})
    if "approval" in payload:
        if not isinstance(payload.get("approval"), dict):
            raise AccessPackageError("package approval must be an object")
        raw_approval.update(payload.get("approval") or {})
    if not isinstance(raw_approval, dict):
        raise AccessPackageError("package approval must be an object")
    try:
        minimum_approvals = int(raw_approval.get("minimum_approvals") or 1)
    except (TypeError, ValueError) as exc:
        raise AccessPackageError("minimum_approvals must be an integer") from exc
    if not 1 <= minimum_approvals <= 10:
        raise AccessPackageError("minimum_approvals must be between 1 and 10")
    approval = {
        "required": bool(raw_approval.get("required", False)),
        "admin_groups": _unique_strings(raw_approval.get("admin_groups")),
        "ticket_required": bool(raw_approval.get("ticket_required", False)),
        "minimum_approvals": minimum_approvals,
    }

    timestamp = _now(now)
    record = {
        "schema_version": 2,
        "id": str(current.get("id")) if current.get("id") is not None else None,
        "name": name,
        "description": description,
        "status": status,
        "access": access,
        "lifecycle": {
            "default_ttl": default_ttl,
            "max_ttl": max_ttl,
            "permanent_allowed": permanent_allowed,
        },
        "approval": approval,
        "revision": int(current.get("revision") or 0),
        "created_at": int(current.get("created_at") or timestamp),
        "created_by": current.get("created_by") or actor,
        "updated_at": timestamp,
        "updated_by": actor,
    }
    return record


def list_packages(redis, status=None):
    rows = []
    for key in redis.keys("access_package_*"):
        key_name = _key_name(key)
        suffix = key_name.replace("access_package_", "", 1)
        if not suffix.isdigit():
            continue
        record = _json(redis.get(key))
        if status and record.get("status") != status:
            continue
        rows.append(record)
    return sorted(rows, key=lambda row: (str(row.get("name") or "").casefold(), int(row.get("id") or 0)))


def get_package(redis, reference):
    direct = redis.get("access_package_{}".format(reference))
    if direct is not None:
        return _json(direct)
    matches = [record for record in list_packages(redis) if _package_reference_matches(record, reference)]
    if not matches:
        return None
    if len(matches) > 1:
        raise AccessPackageError("package name is ambiguous; use its numeric id")
    return matches[0]


def _assert_unique_name(redis, record, package_id=None):
    for existing in list_packages(redis):
        if package_id is not None and str(existing.get("id")) == str(package_id):
            continue
        if str(existing.get("name") or "").casefold() == str(record.get("name") or "").casefold():
            raise AccessPackageError("an access package with this name already exists")


def _store_revision(redis, record):
    redis.set(
        "access_package_revision_{}_{}".format(record["id"], record["revision"]),
        json.dumps(record, sort_keys=True),
    )


def create_package(redis, payload, actor=None, now=None, max_rules=100):
    record = normalize_package(payload, actor=actor, now=now, max_rules=max_rules)
    _assert_unique_name(redis, record)
    record["id"] = str(redis.incr("offset_access_package_id"))
    record["revision"] = 1
    redis.set("access_package_{}".format(record["id"]), json.dumps(record, sort_keys=True))
    _store_revision(redis, record)
    return record


def list_assignments(redis, package=None, subject=None, name=None, include_expired=True, now=None):
    package_record = get_package(redis, package) if package is not None else None
    if package is not None and package_record is None:
        raise AccessPackageError("access package was not found")
    rows = []
    timestamp = _now(now)
    for key in redis.keys("access_package_assignment_*"):
        key_name = _key_name(key)
        suffix = key_name.replace("access_package_assignment_", "", 1)
        if not suffix.isdigit():
            continue
        record = _json(redis.get(key))
        if package_record and str(record.get("package_id")) != str(package_record.get("id")):
            continue
        if subject and record.get("subject") != subject:
            continue
        if name and record.get("name") != name:
            continue
        expired = bool(record.get("expires_at") and int(record["expires_at"]) <= timestamp)
        record["expired"] = expired
        if expired and not include_expired:
            continue
        rows.append(record)
    return sorted(rows, key=lambda row: int(row.get("id") or 0))


def get_assignment(redis, assignment_id):
    raw = redis.get("access_package_assignment_{}".format(assignment_id))
    return _json(raw) if raw is not None else None


def _managed_grants(redis, assignment_id):
    rows = []
    for key in redis.keys("grant_*"):
        grant = _json(redis.get(key))
        if grant.get("managed_by") == "access_package" and str(grant.get("assignment_id")) == str(assignment_id):
            rows.append((_key_name(key).replace("grant_", "", 1), grant))
    return rows


def _grant_from_rule(package, assignment, rule):
    return {
        "schema_version": 2,
        "subject": assignment["subject"],
        "name": assignment["name"],
        "project": rule.get("project"),
        "project_glob": rule.get("project_glob"),
        "project_set": rule.get("project_set"),
        "host": rule.get("host"),
        "remote_user": rule.get("remote_user"),
        "sudo_mode": rule.get("sudo_mode") or "none",
        "allowed_actions": list(rule.get("allowed_actions") or ["ssh"]),
        "temporary": bool(assignment.get("expires_at")),
        "expires_at": assignment.get("expires_at"),
        "managed_by": "access_package",
        "package_id": package["id"],
        "package_name": package["name"],
        "package_revision": package["revision"],
        "package_rule_id": rule["id"],
        "assignment_id": assignment["id"],
    }


def _grant_identity(grant):
    selector = next((key for key in ("project", "project_glob", "project_set") if grant.get(key) is not None), None)
    return (
        str(grant.get("subject") or ""), str(grant.get("name") or ""), selector,
        str(grant.get(selector) or "") if selector else "", str(grant.get("host") or ""),
    )


def _assert_no_grant_conflicts(redis, package, assignment, now=None):
    if package.get("status") != "enabled" or assignment.get("status") != "active":
        return
    desired = [_grant_from_rule(package, assignment, rule) for rule in package.get("access") or []]
    existing = []
    timestamp = _now(now)
    for key in redis.keys("grant_*"):
        grant = _json(redis.get(key))
        if str(grant.get("assignment_id") or "") == str(assignment.get("id") or ""):
            continue
        if grant.get("expires_at") and int(grant["expires_at"]) <= timestamp:
            continue
        existing.append((_key_name(key), grant))
    existing_by_identity = {_grant_identity(grant): key for key, grant in existing}
    for grant in desired:
        conflict = existing_by_identity.get(_grant_identity(grant))
        if conflict:
            raise AccessPackageError(
                "package assignment conflicts with {}; remove or change the existing grant first".format(conflict)
            )


def sync_assignment(redis, package, assignment, dry_run=False):
    existing = {grant.get("package_rule_id"): (grant_id, grant) for grant_id, grant in _managed_grants(redis, assignment["id"])}
    desired = {}
    if package.get("status") == "enabled" and assignment.get("status") == "active":
        for rule in package.get("access") or []:
            desired[rule["id"]] = _grant_from_rule(package, assignment, rule)
    changes = {"create": [], "update": [], "delete": []}
    grant_ids = []
    for rule_id, grant in desired.items():
        previous = existing.get(rule_id)
        if previous is None:
            changes["create"].append({"package_rule_id": rule_id, "grant": grant})
            if not dry_run:
                grant_id = str(redis.incr("offset_grant_id"))
                redis.set("grant_{}".format(grant_id), json.dumps(grant, sort_keys=True))
                grant_ids.append(grant_id)
        else:
            grant_id, old = previous
            grant_ids.append(grant_id)
            if old != grant:
                changes["update"].append({"grant_id": grant_id, "before": old, "after": grant})
                if not dry_run:
                    redis.set("grant_{}".format(grant_id), json.dumps(grant, sort_keys=True))
    for rule_id, (grant_id, old) in existing.items():
        if rule_id not in desired:
            changes["delete"].append({"grant_id": grant_id, "grant": old})
            if not dry_run:
                redis.delete("grant_{}".format(grant_id))
    if not dry_run:
        assignment["grant_ids"] = sorted(grant_ids, key=lambda value: int(value) if str(value).isdigit() else str(value))
        assignment["package_revision"] = package["revision"]
        assignment["package_name"] = package["name"]
        redis.set("access_package_assignment_{}".format(assignment["id"]), json.dumps(assignment, sort_keys=True))
    changes["count"] = sum(len(changes[key]) for key in ("create", "update", "delete"))
    return changes


def preview_package_update(redis, reference, payload, actor=None, now=None, max_rules=100):
    current = get_package(redis, reference)
    if current is None:
        raise AccessPackageError("access package was not found")
    proposed = normalize_package(payload, current=current, actor=actor, now=now, max_rules=max_rules)
    proposed["id"] = current["id"]
    proposed["revision"] = int(current.get("revision") or 0) + 1
    _assert_unique_name(redis, proposed, package_id=current["id"])
    assignment_changes = []
    for assignment in list_assignments(redis, package=current["id"], include_expired=False, now=now):
        _assert_no_grant_conflicts(redis, proposed, assignment, now=now)
        assignment_changes.append({
            "assignment_id": assignment["id"],
            "subject": assignment["subject"],
            "name": assignment["name"],
            "grant_changes": sync_assignment(redis, proposed, assignment, dry_run=True),
        })
    return {
        "package_id": current["id"],
        "from_revision": current["revision"],
        "to_revision": proposed["revision"],
        "before": current,
        "after": proposed,
        "assignments": assignment_changes,
        "affected_subjects": len(assignment_changes),
        "grant_change_count": sum(row["grant_changes"]["count"] for row in assignment_changes),
    }


def update_package(redis, reference, payload, actor=None, expected_revision=None, now=None, max_rules=100):
    preview = preview_package_update(redis, reference, payload, actor=actor, now=now, max_rules=max_rules)
    current = preview["before"]
    if expected_revision is not None and int(expected_revision) != int(current.get("revision") or 0):
        raise AccessPackageError("package revision changed; refresh and preview again")
    proposed = preview["after"]
    redis.set("access_package_{}".format(proposed["id"]), json.dumps(proposed, sort_keys=True))
    _store_revision(redis, proposed)
    sync_results = []
    for assignment in list_assignments(redis, package=proposed["id"], include_expired=False, now=now):
        sync_results.append({"assignment_id": assignment["id"], "changes": sync_assignment(redis, proposed, assignment)})
    return proposed, sync_results


def _assignment_expiry(package, ttl=None, permanent=False, now=None):
    lifecycle = package.get("lifecycle") or {}
    if permanent:
        if not lifecycle.get("permanent_allowed", True):
            raise AccessPackageError("this package does not allow permanent assignments")
        return None
    effective_ttl = ttl or lifecycle.get("default_ttl")
    if not effective_ttl:
        if lifecycle.get("permanent_allowed", True):
            return None
        raise AccessPackageError("an assignment TTL is required")
    try:
        seconds = parse_duration(effective_ttl)
    except (TypeError, ValueError) as exc:
        raise AccessPackageError("invalid assignment TTL: {}".format(exc)) from exc
    max_ttl = lifecycle.get("max_ttl")
    if max_ttl and seconds > parse_duration(max_ttl):
        raise AccessPackageError("assignment TTL exceeds package max_ttl")
    return _now(now) + seconds


def assign_package(redis, reference, subject, name, actor=None, ttl=None, permanent=False, ticket=None, now=None):
    package = get_package(redis, reference)
    if package is None:
        raise AccessPackageError("access package was not found")
    if package.get("status") != "enabled":
        raise AccessPackageError("disabled access packages cannot be assigned")
    approval = package.get("approval") or {}
    if int(approval.get("minimum_approvals") or 1) > 1:
        raise AccessPackageError("this package requires multiple approvals; direct assignment is not allowed")
    ticket = str(ticket or "").strip() or None
    if approval.get("ticket_required") and not ticket:
        raise AccessPackageError("this package requires a ticket")
    if subject not in _SUBJECTS:
        raise AccessPackageError("assignment subject must be user, group, or role")
    name = str(name or "").strip()
    if not name or len(name) > 255:
        raise AccessPackageError("assignment subject name is required")
    expires_at = _assignment_expiry(package, ttl=ttl, permanent=permanent, now=now)
    existing = next((row for row in list_assignments(redis, package=package["id"], subject=subject, name=name) if row.get("status") == "active"), None)
    timestamp = _now(now)
    if existing:
        assignment = existing
        assignment.update({"expires_at": expires_at, "ticket": ticket, "updated_at": timestamp, "updated_by": actor})
    else:
        assignment = {
            "schema_version": 2,
            "id": str(redis.incr("offset_access_package_assignment_id")),
            "package_id": package["id"],
            "package_name": package["name"],
            "package_revision": package["revision"],
            "subject": subject,
            "name": name,
            "status": "active",
            "expires_at": expires_at,
            "ticket": ticket,
            "grant_ids": [],
            "created_at": timestamp,
            "created_by": actor,
            "updated_at": timestamp,
            "updated_by": actor,
        }
    _assert_no_grant_conflicts(redis, package, assignment, now=now)
    redis.set("access_package_assignment_{}".format(assignment["id"]), json.dumps(assignment, sort_keys=True))
    changes = sync_assignment(redis, package, assignment)
    return assignment, changes


def unassign_package(redis, assignment_id, actor=None, now=None):
    assignment = get_assignment(redis, assignment_id)
    if assignment is None:
        raise AccessPackageError("access package assignment was not found")
    deleted_grants = 0
    for grant_id, _ in _managed_grants(redis, assignment["id"]):
        deleted_grants += redis.delete("grant_{}".format(grant_id))
    assignment.update({
        "status": "revoked",
        "grant_ids": [],
        "revoked_at": _now(now),
        "revoked_by": actor,
        "updated_at": _now(now),
        "updated_by": actor,
    })
    redis.set("access_package_assignment_{}".format(assignment["id"]), json.dumps(assignment, sort_keys=True))
    return assignment, deleted_grants


def list_package_revisions(redis, reference):
    package = get_package(redis, reference)
    if package is None:
        raise AccessPackageError("access package was not found")
    rows = []
    for key in redis.keys("access_package_revision_{}_*".format(package["id"])):
        rows.append(_json(redis.get(key)))
    return sorted(rows, key=lambda row: int(row.get("revision") or 0), reverse=True)


def rollback_package(redis, reference, revision, actor=None, expected_revision=None, now=None):
    current = get_package(redis, reference)
    if current is None:
        raise AccessPackageError("access package was not found")
    if expected_revision is not None and int(expected_revision) != int(current.get("revision") or 0):
        raise AccessPackageError("package revision changed; refresh before rollback")
    raw = redis.get("access_package_revision_{}_{}".format(current["id"], revision))
    if raw is None:
        raise AccessPackageError("access package revision was not found")
    target = copy.deepcopy(_json(raw))
    target.update({
        "id": current["id"],
        "revision": int(current.get("revision") or 0) + 1,
        "created_at": current.get("created_at"),
        "created_by": current.get("created_by"),
        "updated_at": _now(now),
        "updated_by": actor,
        "rolled_back_from": int(revision),
    })
    _assert_unique_name(redis, target, package_id=current["id"])
    assignments = list_assignments(redis, package=target["id"], include_expired=False, now=now)
    for assignment in assignments:
        _assert_no_grant_conflicts(redis, target, assignment, now=now)
    redis.set("access_package_{}".format(target["id"]), json.dumps(target, sort_keys=True))
    _store_revision(redis, target)
    sync_results = []
    for assignment in assignments:
        sync_results.append({"assignment_id": assignment["id"], "changes": sync_assignment(redis, target, assignment)})
    return target, sync_results
