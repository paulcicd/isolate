"""Project-scoped management permissions derived from verified OIDC groups.

These roles govern management and audit surfaces. They never authorize an SSH
connection: target access continues to use the grant resolver. A permission check
without a project is a page-entry check only; check the current object's project
again before returning it, exporting it, or applying a mutation.
"""

import fnmatch
from collections.abc import Mapping


ROLE_PERMISSIONS = {
    "project-owner": frozenset({
        "inventory.read", "inventory.write", "access.read", "access.approve",
        "sessions.read", "sessions.approve", "audit.read",
    }),
    "approver": frozenset({
        "inventory.read", "access.read", "access.approve", "sessions.approve",
    }),
    "auditor": frozenset({
        "inventory.read", "access.read", "sessions.read", "audit.read",
    }),
    "inventory-operator": frozenset({"inventory.read", "inventory.write"}),
}

PERMISSIONS = frozenset().union(*ROLE_PERMISSIONS.values())


class PermissionDenied(ValueError):
    pass


def _section(config, name):
    section = config.get(name) if isinstance(config, Mapping) else None
    return section if isinstance(section, Mapping) else {}


def _strings(value):
    """Reject malformed lists instead of widening a partially valid scope."""
    if not isinstance(value, (list, tuple)):
        return None
    if any(not isinstance(item, str) or not item.strip() for item in value):
        return None
    return value


def _identity_groups(identity):
    groups = identity.get("groups") if isinstance(identity, Mapping) else None
    valid = _strings(groups)
    return frozenset(valid or [])


def is_platform_admin(identity, config):
    """Preserve the existing Dashboard admin-group/history-group fallback."""
    groups = (_section(config, "dashboard").get("admin_groups")
              or _section(config, "history").get("admin_groups") or [])
    valid = _strings(groups)
    return bool(_identity_groups(identity) & frozenset(valid or []))


def _bindings(identity, config):
    groups = _identity_groups(identity)
    bindings = _section(config, "dashboard").get("role_bindings") or []
    if not isinstance(bindings, (list, tuple)):
        return
    for binding in bindings:
        if not isinstance(binding, Mapping):
            continue
        group, role = binding.get("group"), binding.get("role")
        if not isinstance(group, str) or group not in groups or not isinstance(role, str) or role not in ROLE_PERMISSIONS:
            continue
        projects = _strings(binding.get("projects", []))
        patterns = _strings(binding.get("project_globs", []))
        if projects is None or patterns is None or not (projects or patterns):
            continue
        yield role, projects, patterns


def _project_matches(project, projects, patterns):
    if not isinstance(project, str) or not project.strip():
        return False
    normalized = project.lower()
    return ("*" in projects or normalized in (value.lower() for value in projects)
            or any(fnmatch.fnmatchcase(normalized, pattern.lower()) for pattern in patterns))


def has_permission(identity, config, permission, project=None):
    """Check page entry or a concrete project's management permission.

    ``project=None`` allows entry when at least one scoped binding grants the
    permission. It must not be used as the authorization check for an object with
    missing project metadata. ``filter_projects`` handles that case explicitly.
    """
    if not isinstance(permission, str) or permission not in PERMISSIONS:
        return False
    if is_platform_admin(identity, config):
        return True
    return any(permission in ROLE_PERMISSIONS[role]
               and (project is None or _project_matches(project, projects, patterns))
               for role, projects, patterns in _bindings(identity, config))


def filter_projects(rows, identity, config, permission, project_field="project"):
    """Return permitted current objects, suitable for tables and exports alike."""
    if not isinstance(permission, str) or permission not in PERMISSIONS:
        return []
    if is_platform_admin(identity, config):
        return list(rows)
    filtered = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        project = row.get(project_field)
        if isinstance(project, str) and project.strip() and has_permission(identity, config, permission, project):
            filtered.append(row)
    return filtered


def role_names(identity, config):
    """Return valid assigned management roles for display and navigation."""
    if is_platform_admin(identity, config):
        return ["admin"]
    return sorted({role for role, _, _ in _bindings(identity, config)})


def authorize_inventory_change(identity, config, current, proposed):
    """Recheck watched old/new scopes and reserve routing/security to admins."""
    if is_platform_admin(identity, config):
        return
    for host in (current, proposed):
        project = host.get("project_name") if isinstance(host, Mapping) else None
        if not project or not has_permission(identity, config, "inventory.write", project):
            raise PermissionDenied("inventory.write is not allowed for the host project")
    protected = ("server_ip", "server_port", "server_user", "server_nosudo", "server_vip", "proxy_id",
                 "privileged_access_provider", "privileged_access_url", "privileged_access_hint")
    if any(current.get(field) != proposed.get(field) for field in protected):
        raise PermissionDenied("routing, credentials, VIP, and privileged settings require a platform administrator")
