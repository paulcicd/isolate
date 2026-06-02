#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Access policy and grant resolution for Isolate v2."""

import fnmatch


class PolicyDenied(Exception):
    pass


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _project_name(project):
    return str(project or "").lower()


def _subject_matches(grant, identity):
    subject = grant.get("subject")
    name = grant.get("name")
    if subject == "user":
        return name == identity.get("username")
    if subject == "group":
        return name in (identity.get("groups") or [])
    if subject == "role":
        return name in (identity.get("roles") or [])
    return False


def _host_matches(grant, host):
    rule_host = grant.get("host") or grant.get("host_id") or grant.get("server_id")
    if not rule_host:
        return True
    if host is None:
        return False
    host_values = {
        str(host.get("server_id") or ""),
        str(host.get("server_name") or ""),
        str(host.get("server_ip") or ""),
    }
    return str(rule_host) in host_values


def _project_set_matches(project_set, project):
    project_l = _project_name(project)
    exact = [_project_name(p) for p in project_set.get("projects") or []]
    if "*" in exact or project_l in exact:
        return True
    return any(fnmatch.fnmatchcase(project_l, _project_name(pattern)) for pattern in project_set.get("project_globs") or [])


def _project_matches(grant, project, project_sets=None):
    project_sets = project_sets or {}
    project_l = _project_name(project)

    exact_projects = [_project_name(p) for p in _as_list(grant.get("project"))]
    if exact_projects:
        if "*" in exact_projects or project_l in exact_projects:
            return True
        return False

    globs = _as_list(grant.get("project_glob"))
    if globs:
        return any(fnmatch.fnmatchcase(project_l, _project_name(pattern)) for pattern in globs)

    set_name = grant.get("project_set")
    if set_name:
        project_set = project_sets.get(set_name) or {}
        return _project_set_matches(project_set, project)

    return project is None


def _selector_rank(grant):
    if grant.get("project"):
        return 30
    if grant.get("project_set"):
        return 20
    if grant.get("project_glob"):
        return 10
    return 0


def _grant_rank(grant):
    subject_rank = 50 if grant.get("subject") == "user" else 0
    host_rank = 100 if (grant.get("host") or grant.get("host_id") or grant.get("server_id")) else 0
    return host_rank + subject_rank + _selector_rank(grant)


def _matches(grant, identity, project=None, host=None, project_sets=None):
    return (
        _subject_matches(grant, identity)
        and _host_matches(grant, host)
        and _project_matches(grant, project, project_sets=project_sets)
    )


def resolve_grant(identity, project=None, host=None, grants=None, project_sets=None, defaults=None, action="ssh"):
    grants = grants or []
    defaults = defaults or {}
    matches = [grant for grant in grants if _matches(grant, identity, project=project, host=host, project_sets=project_sets)]
    matches = sorted(matches, key=_grant_rank, reverse=True)

    selected = matches[0] if matches else None
    if selected is None:
        raise PolicyDenied("no matching grant for project '{}'".format(project))

    allowed = selected.get("allowed_actions") or ["ssh"]
    if action not in allowed:
        raise PolicyDenied("action '{}' is not allowed".format(action))

    remote_user = selected.get("remote_user")
    if remote_user is None:
        remote_user = defaults.get("fallback_remote_user") or defaults.get("default_remote_user")
    if remote_user is None:
        raise PolicyDenied("remote user is not resolved")

    return {
        "remote_user": remote_user,
        "sudo_mode": selected.get("sudo_mode") or defaults.get("default_sudo_mode", "sudo-i"),
        "allowed_actions": allowed,
        "matched_rule": selected,
    }


def resolve_policy(identity, project=None, host=None, rules=None, defaults=None, action="ssh", project_sets=None):
    """Backward-compatible policy entrypoint for legacy policy_* and new grant_* rules."""
    return resolve_grant(
        identity,
        project=project,
        host=host,
        grants=rules,
        project_sets=project_sets,
        defaults=defaults,
        action=action,
    )


def filter_allowed_hosts(identity, hosts, grants=None, project_sets=None, defaults=None, action="ssh"):
    allowed = []
    for host in hosts:
        try:
            resolve_grant(
                identity,
                project=host.get("project_name"),
                host=host,
                grants=grants,
                project_sets=project_sets,
                defaults=defaults,
                action=action,
            )
            allowed.append(host)
        except PolicyDenied:
            continue
    return allowed
