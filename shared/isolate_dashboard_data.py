#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read models and safe mutations used by the Isolate operations dashboard."""

import hashlib
import json
import re
import time

from isolate_access import list_access_requests
from isolate_jobs import list_jobs
from isolate_policy import PolicyDenied, grant_specificity, matching_grants, resolve_grant
from isolate_session_alerts import initial_session_alerts
from isolate_sessions import list_session_records


class DashboardDataError(Exception):
    pass


FINAL_JOB_STATUSES = ("completed", "failed", "cancelled", "timed_out")
FAILED_JOB_STATUSES = ("failed", "timed_out")


def _decode(value):
    return value.decode("utf-8") if isinstance(value, bytes) else value


def _identity(subject, name):
    identity = {"username": "policy-matrix", "groups": [], "roles": []}
    if subject == "user":
        identity["username"] = name
    elif subject == "group":
        identity["groups"] = [name]
    elif subject == "role":
        identity["roles"] = [name]
    return identity


def _decision(identity, host, grants, project_sets, defaults, action="ssh"):
    try:
        decision = resolve_grant(
            identity,
            project=host.get("project_name"),
            host=host,
            grants=grants,
            project_sets=project_sets,
            defaults=defaults,
            action=action,
        )
        rule = decision.get("matched_rule") or {}
        return {
            "allowed": True,
            "remote_user": decision.get("remote_user"),
            "sudo_mode": decision.get("sudo_mode"),
            "allowed_actions": sorted(decision.get("allowed_actions") or []),
            "grant_id": str(rule.get("id") or ""),
        }
    except PolicyDenied as exc:
        return {"allowed": False, "reason": str(exc)}


def fleet_progress(jobs):
    """Summarize jobs carrying a compatible optional fleet_id field."""
    latest_attempts = {}
    ungrouped = []
    for job in jobs:
        fleet_id = str(job.get("fleet_id") or "")
        slot = str(job.get("fleet_slot") or job.get("host_id") or "")
        if not fleet_id or not slot:
            ungrouped.append(job)
            continue
        key = (fleet_id, slot)
        previous = latest_attempts.get(key)
        if previous is None or int(job.get("attempt") or 1) > int(previous.get("attempt") or 1):
            latest_attempts[key] = job
    fleets = {}
    for job in list(latest_attempts.values()) + ungrouped:
        fleet_id = str(job.get("fleet_id") or "")
        if not fleet_id:
            continue
        fleet = fleets.setdefault(
            fleet_id,
            {
                "fleet_id": fleet_id,
                "runbook_id": job.get("runbook_id") or job.get("type"),
                "username": job.get("username"),
                "created_at": job.get("created_at"),
                "total": 0,
                "queued": 0,
                "running": 0,
                "completed": 0,
                "failed": 0,
                "cancelled": 0,
                "timed_out": 0,
                "job_ids": [],
                "failed_job_ids": [],
            },
        )
        fleet["total"] += 1
        status = job.get("status") or "queued"
        if status in fleet:
            fleet[status] += 1
        fleet["job_ids"].append(str(job.get("id")))
        if status in FAILED_JOB_STATUSES:
            fleet["failed_job_ids"].append(str(job.get("id")))
        fleet["created_at"] = min(
            int(fleet.get("created_at") or job.get("created_at") or 0),
            int(job.get("created_at") or 0),
        )
    rows = []
    for fleet in fleets.values():
        done = sum(fleet[name] for name in FINAL_JOB_STATUSES)
        fleet["finished"] = done
        fleet["progress_percent"] = int((done * 100) / fleet["total"]) if fleet["total"] else 0
        if fleet["running"]:
            fleet["status"] = "running"
        elif fleet["queued"]:
            fleet["status"] = "queued"
        elif fleet["failed"] or fleet["timed_out"]:
            fleet["status"] = "failed"
        elif fleet["cancelled"] and not fleet["completed"]:
            fleet["status"] = "cancelled"
        else:
            fleet["status"] = "completed"
        rows.append(fleet)
    return sorted(rows, key=lambda row: int(row.get("created_at") or 0), reverse=True)


def filter_jobs(jobs, status=None, user=None, project=None, host=None, job_type=None):
    rows = []
    for job in jobs:
        if status and job.get("status") != status:
            continue
        if user and job.get("username") != user:
            continue
        if project and job.get("project") != project:
            continue
        if host and str(job.get("host_id")) != str(host):
            continue
        if job_type and job.get("type") != job_type:
            continue
        rows.append(job)
    return rows


def _alert_id(kind, source_type, source_id):
    raw = "{}:{}:{}".format(kind, source_type, source_id).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:20]


def _alert_state_key(alert_id):
    if re.fullmatch(r"[0-9a-f]{20}", str(alert_id or "")) is None:
        raise DashboardDataError("invalid alert id")
    return "dashboard_alert_state_{}".format(alert_id)


def _load_alert_state(redis, alert_id):
    raw = redis.get(_alert_state_key(alert_id))
    if raw is None:
        return {"status": "open", "comments": []}
    state = json.loads(_decode(raw))
    state.setdefault("status", "open")
    state.setdefault("comments", [])
    return state


def update_alert_state(redis, alert_id, actor, action, comment=None, now=None):
    state = _load_alert_state(redis, alert_id)
    now = int(now or time.time())
    username = (actor or {}).get("username") or (actor or {}).get("keycloak_sub") or "unknown"
    if action == "acknowledge":
        state.update({"status": "acknowledged", "acknowledged_at": now, "acknowledged_by": username})
    elif action == "resolve":
        state.update({"status": "resolved", "resolved_at": now, "resolved_by": username})
    elif action == "reopen":
        state.update({"status": "open", "reopened_at": now, "reopened_by": username})
    elif action != "comment":
        raise DashboardDataError("unsupported alert action")
    if comment:
        state["comments"] = list(state.get("comments") or []) + [{
            "ts": now,
            "username": username,
            "action": action,
            "text": str(comment)[:2048],
        }]
    redis.set(_alert_state_key(alert_id), json.dumps(state, sort_keys=True))
    return state


def _apply_alert_state(redis, alert):
    state = _load_alert_state(redis, alert["id"])
    alert.update(state)
    return alert


def _session_alert(redis, record, kind, now):
    labels = {
        "vip_session": ("high", "VIP session"),
        "privileged_session": ("critical", "Privileged session"),
        "unusual_source_ip": ("high", "Unusual source IP"),
        "long_session": ("medium", "Long-running session"),
    }
    severity, title = labels.get(kind, ("medium", kind.replace("_", " ").title()))
    delivery = next(
        (item for item in reversed(record.get("alert_deliveries") or []) if item.get("alert") == kind),
        None,
    )
    return _apply_alert_state(redis, {
        "id": _alert_id(kind, "session", record.get("connection_id")),
        "kind": kind,
        "source_type": "session",
        "source_id": record.get("connection_id"),
        "severity": severity,
        "title": title,
        "username": record.get("username"),
        "project": record.get("project"),
        "host_id": str(record.get("host_id") or ""),
        "created_at": int(record.get("started_at") or now),
        "details": "{} -> {} as {}".format(
            record.get("source_ip") or "unknown source",
            record.get("target_host") or record.get("host_id") or "unknown target",
            record.get("remote_user") or "unknown",
        ),
        "delivery_ok": None if delivery is None else bool(delivery.get("ok")),
        "delivery_errors": [] if delivery is None else list(delivery.get("errors") or []),
    })


def collect_alerts(redis, config, status=None, kind=None, user=None, project=None, now=None):
    """Aggregate operational alerts while keeping acknowledgement state separate."""
    now = int(now or time.time())
    alerts = []
    alert_cfg = ((config.get("session_control", {}) or {}).get("alerts", {}) or {})
    for record in list_session_records(redis):
        kinds = set(record.get("alerts_sent") or [])
        kinds.update(initial_session_alerts(config, record))
        threshold = int(alert_cfg.get("long_session_seconds") or 0)
        if alert_cfg.get("enabled", False) and threshold > 0:
            started = int(record.get("started_at") or now)
            if record.get("status") == "active" and now - started >= threshold:
                kinds.add("long_session")
        for alert_kind in sorted(kinds):
            alerts.append(_session_alert(redis, record, alert_kind, now))
        for delivery in record.get("alert_deliveries") or []:
            if delivery.get("ok", True):
                continue
            source_id = "{}:{}:{}".format(record.get("connection_id"), delivery.get("alert"), delivery.get("ts"))
            alerts.append(_apply_alert_state(redis, {
                "id": _alert_id("notification_delivery_failed", "session", source_id),
                "kind": "notification_delivery_failed",
                "source_type": "session",
                "source_id": record.get("connection_id"),
                "severity": "medium",
                "title": "Session alert notification failed",
                "username": record.get("username"),
                "project": record.get("project"),
                "host_id": str(record.get("host_id") or ""),
                "created_at": int(delivery.get("ts") or now),
                "details": "; ".join(delivery.get("errors") or ["notification sink failed"]),
                "delivery_ok": False,
                "delivery_errors": list(delivery.get("errors") or []),
            }))

    for job in list_jobs(redis, limit=10000):
        if job.get("status") not in FAILED_JOB_STATUSES:
            continue
        alerts.append(_apply_alert_state(redis, {
            "id": _alert_id("failed_job", "job", job.get("id")),
            "kind": "failed_job",
            "source_type": "job",
            "source_id": str(job.get("id")),
            "severity": "high" if job.get("status") == "failed" else "medium",
            "title": "{} job {}".format(job.get("status", "failed").title(), job.get("id")),
            "username": job.get("username"),
            "project": job.get("project"),
            "host_id": str(job.get("host_id") or ""),
            "created_at": int(job.get("finished_at") or job.get("created_at") or now),
            "details": job.get("error") or "exit code {}".format(job.get("exit_code")),
            "delivery_ok": None,
            "delivery_errors": [],
        }))

    for request_record in list_access_requests(redis):
        delivery = request_record.get("notification_status") or {}
        if delivery.get("ok", True) and not delivery.get("errors"):
            continue
        alerts.append(_apply_alert_state(redis, {
            "id": _alert_id("notification_delivery_failed", "access_request", request_record.get("id")),
            "kind": "notification_delivery_failed",
            "source_type": "access_request",
            "source_id": str(request_record.get("id")),
            "severity": "medium",
            "title": "Access request notification failed",
            "username": request_record.get("requester"),
            "project": request_record.get("project"),
            "host_id": str(request_record.get("host") or ""),
            "created_at": int(request_record.get("created_at") or now),
            "details": "; ".join(delivery.get("errors") or ["notification sink failed"]),
            "delivery_ok": False,
            "delivery_errors": list(delivery.get("errors") or []),
        }))

    filtered = []
    for alert in alerts:
        if status and alert.get("status") != status:
            continue
        if kind and alert.get("kind") != kind:
            continue
        if user and alert.get("username") != user:
            continue
        if project and alert.get("project") != project:
            continue
        filtered.append(alert)
    order = {"open": 0, "acknowledged": 1, "resolved": 2}
    return sorted(filtered, key=lambda row: (order.get(row.get("status"), 9), -int(row.get("created_at") or 0)))


def build_access_matrix(grants, project_sets, hosts, defaults=None, action="ssh"):
    defaults = defaults or {}
    subjects = sorted({
        (str(grant.get("subject")), str(grant.get("name")))
        for grant in grants
        if grant.get("subject") in ("user", "group", "role") and grant.get("name")
    })
    projects = sorted({str(host.get("project_name")) for host in hosts if host.get("project_name")})
    hosts_by_project = {project: [host for host in hosts if str(host.get("project_name")) == project] for project in projects}
    rows = []
    selected_ids = set()
    matching_ids = set()
    findings = []
    seen_findings = set()

    for subject, name in subjects:
        identity = _identity(subject, name)
        cells = {}
        for project in projects:
            outcomes = []
            for host in hosts_by_project[project]:
                matches = matching_grants(identity, project=project, host=host, grants=grants, project_sets=project_sets)
                matching_ids.update(str(item.get("id")) for item in matches if item.get("id") is not None)
                if matches:
                    highest = grant_specificity(matches[0])
                    tied = [item for item in matches if grant_specificity(item) == highest]
                    if len(tied) > 1:
                        signatures = {
                            (item.get("remote_user"), item.get("sudo_mode"), tuple(sorted(item.get("allowed_actions") or ["ssh"])))
                            for item in tied
                        }
                        finding_type = "conflict" if len(signatures) > 1 else "redundant"
                        finding_key = (finding_type, subject, name, project, str(host.get("server_id")), tuple(sorted(str(item.get("id")) for item in tied)))
                        if finding_key not in seen_findings:
                            findings.append({
                                "type": finding_type,
                                "subject": "{}:{}".format(subject, name),
                                "project": project,
                                "host_id": str(host.get("server_id")),
                                "grant_ids": ",".join(sorted(str(item.get("id")) for item in tied)),
                                "details": "equal-precedence grants have {} outcomes".format("different" if finding_type == "conflict" else "identical"),
                            })
                            seen_findings.add(finding_key)
                decision = _decision(identity, host, grants, project_sets, defaults, action=action)
                outcomes.append(decision)
                if decision.get("grant_id"):
                    selected_ids.add(decision["grant_id"])
            allowed = [outcome for outcome in outcomes if outcome.get("allowed")]
            signatures = {
                (outcome.get("remote_user"), outcome.get("sudo_mode"), tuple(outcome.get("allowed_actions") or []))
                for outcome in allowed
            }
            if not allowed:
                state = "denied"
            elif len(allowed) != len(outcomes):
                state = "partial"
            elif len(signatures) > 1:
                state = "mixed"
            else:
                state = "allowed"
            cells[project] = {
                "state": state,
                "allowed_hosts": len(allowed),
                "total_hosts": len(outcomes),
                "remote_users": sorted({item.get("remote_user") for item in allowed if item.get("remote_user")}),
                "sudo_modes": sorted({item.get("sudo_mode") for item in allowed if item.get("sudo_mode")}),
                "actions": sorted({value for item in allowed for value in item.get("allowed_actions") or []}),
            }
        rows.append({"subject": subject, "name": name, "cells": cells})

    for grant_id in sorted(matching_ids - selected_ids):
        findings.append({
            "type": "shadowed",
            "subject": "",
            "project": "",
            "host_id": "",
            "grant_ids": grant_id,
            "details": "grant matches current inventory but never wins resolver precedence",
        })
    return {"projects": projects, "rows": rows, "findings": findings}


def preview_grant_change(grants, project_sets, hosts, candidate, defaults=None, action="ssh"):
    if candidate.get("subject") not in ("user", "group", "role") or not candidate.get("name"):
        raise DashboardDataError("subject and name are required")
    identity = _identity(candidate["subject"], candidate["name"])
    candidate = dict(candidate)
    replace_grant_id = str(candidate.pop("replace_grant_id", "") or "")
    desired_grants = [grant for grant in grants if str(grant.get("id") or "") != replace_grant_id]
    candidate.setdefault("id", replace_grant_id or "preview")
    desired_grants.append(candidate)
    impacts = []
    counts = {"gained": 0, "lost": 0, "changed": 0}
    for host in hosts:
        before = _decision(identity, host, grants, project_sets, defaults or {}, action=action)
        after = _decision(identity, host, desired_grants, project_sets, defaults or {}, action=action)
        if before == after:
            continue
        if not before.get("allowed") and after.get("allowed"):
            change = "gained"
        elif before.get("allowed") and not after.get("allowed"):
            change = "lost"
        else:
            change = "changed"
        counts[change] += 1
        impacts.append({
            "change": change,
            "project": host.get("project_name"),
            "host_id": str(host.get("server_id")),
            "server_name": host.get("server_name"),
            "before": before,
            "after": after,
        })
    return {"counts": counts, "impacts": impacts}
