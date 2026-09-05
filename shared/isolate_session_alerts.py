#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Session-risk classification and best-effort notification dispatch."""

import ipaddress
import threading

from isolate_notifications import notify_session_alert
from isolate_sessions import mark_alert_delivery


def source_is_unusual(source_ip, trusted_cidrs):
    if not source_ip or not trusted_cidrs:
        return False
    try:
        address = ipaddress.ip_address(str(source_ip))
    except ValueError:
        return True
    for cidr in trusted_cidrs:
        try:
            if address in ipaddress.ip_network(str(cidr), strict=False):
                return False
        except ValueError:
            continue
    return True


def initial_session_alerts(config, record):
    alerts = (config.get("session_control", {}) or {}).get("alerts", {}) or {}
    if not alerts.get("enabled", False):
        return []
    result = []
    if alerts.get("vip", True) and record.get("server_vip"):
        result.append("vip_session")
    if alerts.get("privileged", True) and (
        record.get("remote_user") == "root" or record.get("sudo_mode") == "sudo-i"
    ):
        result.append("privileged_session")
    if alerts.get("unusual_source", True) and source_is_unusual(
        record.get("source_ip"), alerts.get("trusted_source_cidrs") or []
    ):
        result.append("unusual_source_ip")
    return result


def long_session_alert(config, record, now):
    alerts = (config.get("session_control", {}) or {}).get("alerts", {}) or {}
    threshold = int(alerts.get("long_session_seconds") or 0)
    if not alerts.get("enabled", False) or threshold <= 0:
        return None
    if "long_session" in (record.get("alerts_sent") or []):
        return None
    started_at = int(record.get("started_at") or now)
    return "long_session" if int(now) - started_at >= threshold else None


def dispatch_alert_async(config, alert_name, record, redis=None):
    def _send():
        try:
            result = notify_session_alert(config, alert_name, record)
        except Exception as exc:
            result = {"sent": [], "errors": [str(exc)]}
        if redis is not None and record.get("connection_id"):
            try:
                mark_alert_delivery(redis, record["connection_id"], alert_name, result)
            except Exception:
                pass

    thread = threading.Thread(target=_send, name="isolate-session-alert", daemon=True)
    thread.start()
    return thread
