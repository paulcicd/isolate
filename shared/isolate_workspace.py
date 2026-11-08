"""Subject-owned preferences and a policy-filtered, multi-protocol catalogue."""

import hashlib
import json
import re
import time

from redis.exceptions import WatchError

RESOURCE_ID = re.compile(r"[0-9]{1,20}:(?:ssh|http|kubernetes|postgresql|mysql)\Z")
TERMINAL_DEFAULTS = {"font_size": 14, "font_family": "monospace", "theme": "dark", "scrollback": 5000, "paste_threshold": 500}


def subject_key(identity):
    subject = identity.get("keycloak_sub")
    if not isinstance(subject, str) or not subject:
        raise ValueError("a verified subject is required")
    return hashlib.sha256(subject.encode()).hexdigest()


def preferences(store, identity):
    raw = store.get("user_preferences_" + subject_key(identity))
    value = json.loads(raw) if raw else {}
    return {"favorites": value.get("favorites", []), "recent": value.get("recent", []),
        "terminal": dict(TERMINAL_DEFAULTS, **value.get("terminal", {}))}


def update_preferences(store, identity, updates=None, recent=None):
    updates = updates or {}
    if not isinstance(updates, dict) or set(updates) - {"favorites", "terminal"}:
        raise ValueError("only favorites and terminal preferences may be changed")
    if "favorites" in updates:
        favorites = updates["favorites"]
        if (not isinstance(favorites, list) or len(favorites) > 200
                or any(not isinstance(item, str) or not RESOURCE_ID.fullmatch(item) for item in favorites)):
            raise ValueError("favorites must contain at most 200 resource IDs")
        updates = dict(updates, favorites=list(dict.fromkeys(favorites)))
    if "terminal" in updates:
        terminal = updates["terminal"]
        if not isinstance(terminal, dict) or set(terminal) - set(TERMINAL_DEFAULTS):
            raise ValueError("unsupported terminal preference")
        for key, minimum, maximum in (("font_size", 10, 24), ("scrollback", 1000, 20000), ("paste_threshold", 100, 10000)):
            if key in terminal and (type(terminal[key]) is not int or not minimum <= terminal[key] <= maximum):
                raise ValueError("terminal preference outside supported range: " + key)
        if "font_family" in terminal and terminal["font_family"] not in ("monospace", "ui-monospace", "Menlo", "Consolas"):
            raise ValueError("unsupported terminal font")
        if "theme" in terminal and terminal["theme"] not in ("dark", "light"):
            raise ValueError("unsupported terminal theme")
    if recent is not None and (not isinstance(recent, str) or not RESOURCE_ID.fullmatch(recent)):
        raise ValueError("invalid recent resource ID")
    key = "user_preferences_" + subject_key(identity)
    for _ in range(12):
        with store.pipeline() as pipe:
            try:
                pipe.watch(key)
                raw = pipe.get(key)
                value = json.loads(raw) if raw else {}
                if "favorites" in updates:
                    value["favorites"] = updates["favorites"]
                if "terminal" in updates:
                    value["terminal"] = dict(value.get("terminal", {}), **updates["terminal"])
                if recent is not None:
                    value["recent"] = [recent] + [item for item in value.get("recent", []) if item != recent][:29]
                pipe.multi()
                pipe.set(key, json.dumps(value, sort_keys=True))
                pipe.execute()
                return {"favorites": value.get("favorites", []), "recent": value.get("recent", []),
                    "terminal": dict(TERMINAL_DEFAULTS, **value.get("terminal", {}))}
            except WatchError:
                continue
    raise ValueError("preferences changed concurrently; retry")


def workspace_resources(runtime, identity, token, query=None, project=None, protocol=None):
    """Expose only public fields after a grant or scoped inventory permission.

    Browsing does not mint tickets, consume approvals, or contact any target.
    Inventory visibility alone never grants a connection.
    """
    from isolate import load_grants, load_project_sets
    from isolate_inventory import list_hosts, is_host_in_maintenance
    from isolate_permissions import has_permission
    from isolate_policy import resolve_grant, PolicyDenied
    from isolate_identity_security import check_step_up, assert_workload_action, StepUpRequired
    from isolate_identity import IdentityError
    from isolate_session_approvals import session_approval_required
    from isolate_protocols import resolve_target, ProtocolError
    config, store = runtime.config, runtime.redis
    grants, sets = load_grants(store), load_project_sets(store)
    rows = []
    for host in list_hosts(store, query=query, project=project):
        protocols = ["ssh"]
        target = config.get("protocols", {}).get("targets", {}).get(str(host["server_id"]))
        if config.get("protocols", {}).get("enabled") and isinstance(target, dict):
            kind = target.get("protocol")
            if kind in ("http", "kubernetes", "postgresql", "mysql"):
                protocols.append(kind)
        for kind in protocols:
            if protocol and kind != protocol:
                continue
            decision = None
            try:
                assert_workload_action(config, identity, kind)
                decision = resolve_grant(identity, project=host["project_name"], host=host, grants=grants,
                    project_sets=sets, defaults={**config.get("policy", {}), **config.get("ssh", {})}, action=kind)
            except (PolicyDenied, IdentityError):
                if not has_permission(identity, config, "inventory.read", host["project_name"]):
                    continue
            state, reason = "denied", "A separate connection grant is required."
            action = {"label": "Request access", "url": "/me/access?host=" + str(host["server_id"])}
            enabled = config.get("gateway", {}).get("enabled") and config.get("api", {}).get("enabled")
            if decision:
                state, reason, action = "available", "Access is available.", {"label": "Connect", "url": ""}
                if is_host_in_maintenance(host) and not set(identity.get("groups") or []).intersection(config.get("maintenance", {}).get("bypass_groups") or []):
                    state, reason = "maintenance", "This resource is in maintenance."
                else:
                    if kind != "ssh":
                        try:
                            resolve_target(config, host, kind)
                        except ProtocolError:
                            enabled = False
                    try:
                        # authenticate() already refreshed lifecycle once for
                        # this request. Browsing must not introspect once per
                        # resource; connection issuance rechecks everything.
                        check_step_up(config, identity, host=host, decision=decision)
                    except StepUpRequired:
                        state, reason = "step_up_required", "Fresh authentication is required."
                        action = {"label": "Verify identity", "url": "/login?step_up=true"}
                    if state == "available" and session_approval_required(config, host, decision):
                        state, reason = "approval_required", "An administrator must approve this session."
                if not enabled:
                    state, reason = "unavailable", "The connection service is not enabled for this resource."
                    action = {"label": "View resource", "url": "/me/resources/" + str(host["server_id"])}
            host_id = str(host["server_id"])
            connect_url = "/me/terminal/" + host_id if kind == "ssh" else "/workspace/resource/" + host_id + "/" + kind
            if state in ("available", "approval_required"):
                action = {"label": "Connect" if state == "available" else "Request session", "url": connect_url}
            rows.append({"resource_id": host_id + ":" + kind, "host_id": host_id, "name": host["server_name"],
                "project": host["project_name"], "protocol": kind, "owner": host.get("resource_owner") or "",
                "environment": host.get("environment") or "", "tags": host.get("tags") or {},
                "access": {"state": state, "reason": reason, "next_action": action, "url": action["url"]},
                "connect_url": connect_url if state in ("available", "approval_required") else None,
                "details_url": "/me/resources/" + host_id if kind == "ssh" else "/workspace/resource/" + host_id + "/" + kind})
    return sorted(rows, key=lambda row: (row["name"].lower(), row["resource_id"]))


def record_recent(runtime, context):
    protocol = "ssh" if context["protocol"] == "webssh" else context["protocol"]
    update_preferences(runtime.redis, context["identity"], recent=str(context["host"]["server_id"]) + ":" + protocol)
