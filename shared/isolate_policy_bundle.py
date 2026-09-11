#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Git-friendly policy bundle validation, diff, and apply helpers."""

import json
import re

from isolate_policy import PolicyDenied, resolve_grant

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


class PolicyBundleError(Exception):
    pass


def _decode(value):
    return value.decode("utf-8") if isinstance(value, bytes) else value


def _key_name(value):
    return str(_decode(value))


def _grant_body(grant):
    return {key: value for key, value in grant.items() if key != "id"}


def _selector(grant):
    for key in ("project", "project_glob", "project_set"):
        if grant.get(key) is not None:
            return key, str(grant[key])
    return None, None


def grant_identity(grant):
    selector_type, selector_value = _selector(grant)
    return (
        str(grant.get("subject") or ""),
        str(grant.get("name") or ""),
        selector_type or "",
        selector_value or "",
        str(grant.get("host") or grant.get("host_id") or grant.get("server_id") or ""),
    )


def load_bundle(path):
    with open(path, "r", encoding="utf-8") as policy_f:
        text = policy_f.read()
    return load_bundle_text(text, input_format="json" if path.lower().endswith(".json") else "yaml")


def load_bundle_text(text, input_format="yaml"):
    if input_format == "json":
        data = json.loads(text)
    else:
        if yaml is None:
            raise PolicyBundleError("PyYAML is required to read policy YAML")
        try:
            data = yaml.safe_load(text)
        except Exception as exc:
            raise PolicyBundleError("cannot parse policy YAML: {}".format(exc))
    if not isinstance(data, dict):
        raise PolicyBundleError("policy bundle must be an object")
    return data


def dump_bundle(bundle, output_format="yaml"):
    if output_format == "json":
        return json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    if yaml is None:
        raise PolicyBundleError("PyYAML is required to write policy YAML")
    return yaml.safe_dump(bundle, default_flow_style=False, sort_keys=False, allow_unicode=False)


def export_bundle(redis):
    grants = []
    for key in redis.keys("grant_*"):
        key_name = _key_name(key)
        grant = json.loads(_decode(redis.get(key)))
        grant["id"] = key_name.replace("grant_", "", 1)
        grants.append(grant)
    grants.sort(key=lambda row: (0, int(row["id"])) if str(row["id"]).isdigit() else (1, str(row["id"])))

    project_sets = []
    for key in redis.keys("project_set_*"):
        project_sets.append(json.loads(_decode(redis.get(key))))
    project_sets.sort(key=lambda row: str(row.get("name") or ""))
    return {"schema_version": 2, "project_sets": project_sets, "grants": grants}


def validate_bundle(bundle):
    errors = []
    warnings = []
    try:
        schema_version = int(bundle.get("schema_version", 0) or 0)
    except (TypeError, ValueError):
        schema_version = 0
    if schema_version != 2:
        errors.append("schema_version must be 2")
    grants = bundle.get("grants") or []
    project_sets = bundle.get("project_sets") or []
    if not isinstance(grants, list):
        errors.append("grants must be a list")
        grants = []
    if not isinstance(project_sets, list):
        errors.append("project_sets must be a list")
        project_sets = []

    set_names = set()
    for index, project_set in enumerate(project_sets):
        if not isinstance(project_set, dict):
            errors.append("project_sets[{}] must be an object".format(index))
            continue
        name = str((project_set or {}).get("name") or "")
        if not name:
            errors.append("project_sets[{}].name is required".format(index))
        elif name in set_names:
            errors.append("duplicate project set: {}".format(name))
        set_names.add(name)
        if not isinstance((project_set or {}).get("projects", []), list):
            errors.append("project set {} projects must be a list".format(name or index))
        if not isinstance((project_set or {}).get("project_globs", []), list):
            errors.append("project set {} project_globs must be a list".format(name or index))

    seen = {}
    seen_ids = set()
    for index, grant in enumerate(grants):
        if not isinstance(grant, dict):
            errors.append("grants[{}] must be an object".format(index))
            continue
        grant = grant or {}
        label = "grants[{}]".format(index)
        if grant.get("subject") not in ("user", "group", "role"):
            errors.append("{}.subject must be user, group, or role".format(label))
        if not grant.get("name"):
            errors.append("{}.name is required".format(label))
        selectors = [key for key in ("project", "project_glob", "project_set") if grant.get(key) is not None]
        if len(selectors) != 1:
            errors.append("{} must define exactly one project selector".format(label))
        if grant.get("project_set") and grant.get("project_set") not in set_names:
            errors.append("{} references unknown project set: {}".format(label, grant.get("project_set")))
        if not grant.get("remote_user"):
            errors.append("{}.remote_user is required".format(label))
        elif re.fullmatch(r"[A-Za-z0-9_,.-]{1,64}", str(grant.get("remote_user"))) is None:
            errors.append("{}.remote_user is invalid".format(label))
        if grant.get("sudo_mode", "none") not in ("none", "sudo-i"):
            errors.append("{}.sudo_mode must be none or sudo-i".format(label))
        actions = grant.get("allowed_actions", ["ssh"])
        if not isinstance(actions, list) or not actions:
            errors.append("{}.allowed_actions must be a non-empty list".format(label))
        elif any(re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", str(action)) is None for action in actions):
            errors.append("{}.allowed_actions contains an invalid action".format(label))
        grant_id = grant.get("id")
        if grant_id is not None:
            if not str(grant_id).isdigit():
                errors.append("{}.id must be numeric".format(label))
            if str(grant_id) in seen_ids:
                errors.append("duplicate grant id: {}".format(grant_id))
            seen_ids.add(str(grant_id))

        identity = grant_identity(grant)
        previous = seen.get(identity)
        if previous is not None:
            if _grant_body(previous) == _grant_body(grant):
                warnings.append("duplicate grant selector for {}:{}".format(grant.get("subject"), grant.get("name")))
            else:
                errors.append("conflicting grant selector for {}:{}".format(grant.get("subject"), grant.get("name")))
        else:
            seen[identity] = grant

    return {"valid": not errors, "errors": errors, "warnings": warnings}


def _current_maps(redis):
    bundle = export_bundle(redis)
    grants_by_id = {str(row["id"]): row for row in bundle["grants"]}
    grants_by_identity = {
        grant_identity(row): row for row in bundle["grants"]
        if not row.get("temporary") and row.get("managed_by") != "access_package"
    }
    sets_by_name = {row["name"]: row for row in bundle["project_sets"]}
    return grants_by_id, grants_by_identity, sets_by_name


def plan_bundle(redis, bundle, prune=False):
    validation = validate_bundle(bundle)
    if not validation["valid"]:
        raise PolicyBundleError("; ".join(validation["errors"]))
    current_by_id, current_by_identity, current_sets = _current_maps(redis)
    changes = {"grant_add": [], "grant_update": [], "grant_remove": [], "project_set_add": [], "project_set_update": [], "project_set_remove": []}
    desired_grant_ids = set()

    for desired in bundle.get("grants") or []:
        desired = dict(desired)
        desired_id = desired.get("id")
        current = current_by_id.get(str(desired_id)) if desired_id is not None else None
        if current is not None and current.get("temporary") and not desired.get("temporary"):
            current = None
        if current is not None and current.get("managed_by") == "access_package" and desired.get("managed_by") != "access_package":
            current = None
        if current is None:
            current = current_by_identity.get(grant_identity(desired))
        if current is None:
            changes["grant_add"].append(desired)
            continue
        desired_grant_ids.add(str(current["id"]))
        desired["id"] = str(current["id"])
        if _grant_body(current) != _grant_body(desired):
            changes["grant_update"].append({"before": current, "after": desired})

    desired_set_names = set()
    for desired in bundle.get("project_sets") or []:
        desired = dict(desired)
        name = desired["name"]
        desired_set_names.add(name)
        current = current_sets.get(name)
        if current is None:
            changes["project_set_add"].append(desired)
        elif current != desired:
            changes["project_set_update"].append({"before": current, "after": desired})

    if prune:
        protected_package_sets = {
            str(row.get("project_set")) for row in current_by_id.values()
            if row.get("managed_by") == "access_package" and row.get("project_set")
        }
        changes["grant_remove"] = [
            row for grant_id, row in current_by_id.items()
            if grant_id not in desired_grant_ids
            and not row.get("temporary")
            and row.get("managed_by") != "access_package"
        ]
        changes["project_set_remove"] = [
            row for name, row in current_sets.items()
            if name not in desired_set_names and name not in protected_package_sets
        ]
    return changes


def apply_bundle(redis, bundle, prune=False, dry_run=False):
    changes = plan_bundle(redis, bundle, prune=prune)
    if dry_run:
        return changes
    sets = []
    deletes = []
    for project_set in changes["project_set_add"]:
        sets.append(("project_set_{}".format(project_set["name"]), json.dumps(project_set, sort_keys=True)))
    for change in changes["project_set_update"]:
        project_set = change["after"]
        sets.append(("project_set_{}".format(project_set["name"]), json.dumps(project_set, sort_keys=True)))
    for grant in changes["grant_add"]:
        record = _grant_body(grant)
        grant_id = grant.get("id")
        if grant_id is not None and redis.get("grant_{}".format(grant_id)) is None:
            try:
                current_offset = int(_decode(redis.get("offset_grant_id")) or 0)
                if int(grant_id) > current_offset:
                    redis.set("offset_grant_id", str(grant_id))
            except (TypeError, ValueError):
                pass
        else:
            grant_id = redis.incr("offset_grant_id")
        sets.append(("grant_{}".format(grant_id), json.dumps(record, sort_keys=True)))
    for change in changes["grant_update"]:
        grant = change["after"]
        sets.append(("grant_{}".format(grant["id"]), json.dumps(_grant_body(grant), sort_keys=True)))
    for grant in changes["grant_remove"]:
        deletes.append("grant_{}".format(grant["id"]))
    for project_set in changes["project_set_remove"]:
        deletes.append("project_set_{}".format(project_set["name"]))

    if hasattr(redis, "pipeline"):
        pipeline = redis.pipeline(transaction=True)
        for key, value in sets:
            pipeline.set(key, value)
        for key in deletes:
            pipeline.delete(key)
        pipeline.execute()
    else:  # Small in-memory test clients and legacy adapters.
        for key, value in sets:
            redis.set(key, value)
        for key in deletes:
            redis.delete(key)
    return changes


def change_count(changes):
    return sum(len(rows) for rows in changes.values())


def _state_after_plan(redis, bundle, prune=False):
    current = export_bundle(redis)
    changes = plan_bundle(redis, bundle, prune=prune)
    grants = {str(row["id"]): dict(row) for row in current["grants"]}
    project_sets = {row["name"]: dict(row) for row in current["project_sets"]}
    for row in changes["grant_remove"]:
        grants.pop(str(row["id"]), None)
    for change in changes["grant_update"]:
        grants[str(change["after"]["id"])] = dict(change["after"])
    synthetic = 0
    for row in changes["grant_add"]:
        synthetic += 1
        item = dict(row)
        item["id"] = str(item.get("id") or "new-{}".format(synthetic))
        grants[item["id"]] = item
    for row in changes["project_set_remove"]:
        project_sets.pop(row["name"], None)
    for change in changes["project_set_update"]:
        project_sets[change["after"]["name"]] = dict(change["after"])
    for row in changes["project_set_add"]:
        project_sets[row["name"]] = dict(row)
    return list(grants.values()), project_sets


def _principal_identity(subject, name):
    identity = {"username": "policy-preview", "groups": [], "roles": []}
    if subject == "user":
        identity["username"] = name
    elif subject == "group":
        identity["groups"] = [name]
    elif subject == "role":
        identity["roles"] = [name]
    return identity


def _decision(identity, host, grants, project_sets, action):
    try:
        result = resolve_grant(
            identity,
            project=host.get("project_name"),
            host=host,
            grants=grants,
            project_sets=project_sets,
            defaults={"fallback_remote_user": None, "default_remote_user": None},
            action=action,
        )
        return {
            "allowed": True,
            "remote_user": result.get("remote_user"),
            "sudo_mode": result.get("sudo_mode"),
            "grant_id": (result.get("matched_rule") or {}).get("id"),
        }
    except PolicyDenied:
        return {"allowed": False}


def blast_radius(redis, bundle, hosts, prune=False, max_entries=2000):
    validation = validate_bundle(bundle)
    if not validation["valid"]:
        raise PolicyBundleError("; ".join(validation["errors"]))
    current = export_bundle(redis)
    desired_grants, desired_sets = _state_after_plan(redis, bundle, prune=prune)
    current_grants = current["grants"]
    current_sets = {row["name"]: row for row in current["project_sets"]}
    principals = sorted({
        (str(row.get("subject") or ""), str(row.get("name") or ""))
        for row in current_grants + desired_grants
        if row.get("subject") and row.get("name")
    })
    actions = sorted({
        str(action)
        for row in current_grants + desired_grants
        for action in (row.get("allowed_actions") or ["ssh"])
    })
    impacts = []
    counts = {"gained": 0, "lost": 0, "changed": 0}
    truncated = False
    for subject, name in principals:
        identity = _principal_identity(subject, name)
        for host in hosts:
            for action in actions:
                before = _decision(identity, host, current_grants, current_sets, action)
                after = _decision(identity, host, desired_grants, desired_sets, action)
                if before == after:
                    continue
                if not before.get("allowed") and after.get("allowed"):
                    change = "gained"
                elif before.get("allowed") and not after.get("allowed"):
                    change = "lost"
                else:
                    change = "changed"
                counts[change] += 1
                if len(impacts) >= int(max_entries):
                    truncated = True
                    continue
                impacts.append({
                    "change": change,
                    "subject": subject,
                    "name": name,
                    "action": action,
                    "project": host.get("project_name"),
                    "host_id": str(host.get("server_id")),
                    "server_name": host.get("server_name"),
                    "before": before,
                    "after": after,
                })
    return {"counts": counts, "impacts": impacts, "truncated": truncated, "principals": len(principals), "hosts": len(hosts)}
