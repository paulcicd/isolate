#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Access policy resolution for Isolate v2."""


class PolicyDenied(Exception):
    pass


def _matches(rule, identity, project=None, host=None):
    subject = rule.get("subject")
    name = rule.get("name")
    if subject == "user" and name != identity.get("username"):
        return False
    if subject == "group" and name not in identity.get("groups", []):
        return False
    if rule.get("project") not in (None, project):
        return False
    host_id = host.get("server_id") if host else None
    host_name = host.get("server_name") if host else None
    rule_host = rule.get("host") or rule.get("host_id") or rule.get("server_id")
    if rule_host not in (None, host_id, host_name):
        return False
    return True


def _rank(rule):
    subject_rank = 2 if rule.get("subject") == "user" else 0
    host_rank = 1 if (rule.get("host") or rule.get("host_id") or rule.get("server_id")) else 0
    return subject_rank + host_rank


def resolve_policy(identity, project=None, host=None, rules=None, defaults=None, action="ssh"):
    """Resolve remote identity by precedence.

    Precedence is user-host > user-project > group-host > group-project > defaults.
    """
    rules = rules or []
    defaults = defaults or {}
    matches = [rule for rule in rules if _matches(rule, identity, project=project, host=host)]
    matches = sorted(matches, key=_rank, reverse=True)

    selected = matches[0] if matches else None
    allowed = selected.get("allowed_actions") if selected else None
    if allowed is None:
        allowed = defaults.get("allowed_actions") or defaults.get("default_allowed_actions") or ["ssh"]
    if action not in allowed:
        raise PolicyDenied("action '{}' is not allowed".format(action))

    remote_user = None
    sudo_mode = None
    if selected:
        remote_user = selected.get("remote_user")
        sudo_mode = selected.get("sudo_mode")

    if remote_user is None and host:
        remote_user = host.get("server_user")
    if remote_user is None:
        remote_user = defaults.get("fallback_remote_user") or defaults.get("default_remote_user")
    if remote_user is None:
        raise PolicyDenied("remote user is not resolved")

    return {
        "remote_user": remote_user,
        "sudo_mode": sudo_mode or defaults.get("default_sudo_mode", "sudo-i"),
        "allowed_actions": allowed,
        "matched_rule": selected,
    }
