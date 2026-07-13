#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Notification sinks for Isolate access requests."""

import json
import smtplib
import urllib.parse
import urllib.request
from email.message import EmailMessage


class NotificationError(Exception):
    pass


def _dashboard_url(config, request_id=None):
    public_url = (config.get("dashboard", {}).get("public_url") or "").rstrip("/")
    if not public_url:
        return None
    if request_id:
        return "{}/access?id={}".format(public_url, urllib.parse.quote(str(request_id)))
    return "{}/access".format(public_url)


def _actor_name(actor):
    if not actor:
        return None
    return actor.get("username") or actor.get("email") or actor.get("keycloak_sub")


def build_access_notification(config, event_name, request_record, actor=None, extra=None):
    extra = extra or {}
    request_id = request_record.get("id")
    payload = {
        "event": event_name,
        "request": request_record,
        "actor": actor or {},
        "dashboard_url": _dashboard_url(config, request_id),
    }
    payload.update(extra)

    title_by_event = {
        "access_request_created": "Access request created",
        "access_request_approved": "Access request approved",
        "access_request_denied": "Access request denied",
    }
    title = "{} #{}".format(title_by_event.get(event_name, event_name), request_id or "")
    lines = [
        title,
        "status: {}".format(request_record.get("status") or ""),
        "requester: {}".format(request_record.get("requester") or ""),
        "project: {}".format(request_record.get("project") or ""),
        "host: {}".format(request_record.get("host") or ""),
        "remote_user: {}".format(request_record.get("remote_user") or ""),
        "sudo_mode: {}".format(request_record.get("sudo_mode") or ""),
        "reason: {}".format(request_record.get("reason") or ""),
    ]
    if _actor_name(actor):
        lines.append("actor: {}".format(_actor_name(actor)))
    if request_record.get("decision_reason"):
        lines.append("decision_reason: {}".format(request_record.get("decision_reason")))
    if request_record.get("expires_at"):
        lines.append("expires_at: {}".format(request_record.get("expires_at")))
    if payload.get("dashboard_url"):
        lines.append("dashboard: {}".format(payload["dashboard_url"]))

    return {
        "subject": "[Isolate] {}".format(title),
        "text": "\n".join(lines),
        "payload": payload,
    }


def _enabled_sinks(config):
    notifications = config.get("notifications", {})
    if not notifications.get("enabled", False):
        return []
    return notifications.get("sinks") or []


def _timeout(config):
    return int(config.get("notifications", {}).get("timeout_seconds", 5))


def _send_webhook(config, sink, notification):
    url = sink.get("url")
    if not url:
        raise NotificationError("webhook sink requires url")
    data = json.dumps(notification["payload"], sort_keys=True).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    headers.update(sink.get("headers") or {})
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=_timeout(config)) as resp:
        return {"type": "webhook", "status": getattr(resp, "status", None) or resp.getcode()}


def _send_telegram(config, sink, notification):
    token = sink.get("bot_token")
    chat_id = sink.get("chat_id")
    if not token or not chat_id:
        raise NotificationError("telegram sink requires bot_token and chat_id")
    url = "https://api.telegram.org/bot{}/sendMessage".format(token)
    payload = {
        "chat_id": chat_id,
        "text": notification["text"],
    }
    if sink.get("parse_mode"):
        payload["parse_mode"] = sink["parse_mode"]
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=_timeout(config)) as resp:
        return {"type": "telegram", "status": getattr(resp, "status", None) or resp.getcode()}


def _send_email(config, sink, notification):
    host = sink.get("smtp_host")
    if not host:
        raise NotificationError("email sink requires smtp_host")
    sender = sink.get("from") or sink.get("username")
    recipients = sink.get("to") or []
    if isinstance(recipients, str):
        recipients = [recipients]
    if not sender or not recipients:
        raise NotificationError("email sink requires from and to")

    msg = EmailMessage()
    msg["Subject"] = notification["subject"]
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(notification["text"])

    port = int(sink.get("smtp_port", 587))
    with smtplib.SMTP(host, port, timeout=_timeout(config)) as smtp:
        if sink.get("starttls", True):
            smtp.starttls()
        if sink.get("username"):
            smtp.login(sink.get("username"), sink.get("password") or "")
        smtp.send_message(msg)
    return {"type": "email", "status": "sent"}


def _send_sink(config, sink, notification):
    sink_type = sink.get("type")
    if sink_type == "webhook":
        return _send_webhook(config, sink, notification)
    if sink_type == "telegram":
        return _send_telegram(config, sink, notification)
    if sink_type == "email":
        return _send_email(config, sink, notification)
    raise NotificationError("unsupported notification sink type: {}".format(sink_type))


def notify_access_event(config, event_name, request_record, actor=None, extra=None):
    notification = build_access_notification(config, event_name, request_record, actor=actor, extra=extra)
    results = []
    errors = []
    for sink in _enabled_sinks(config):
        try:
            results.append(_send_sink(config, sink, notification))
        except Exception as exc:  # pragma: no cover - exact network failures vary
            message = "{} sink failed: {}".format(sink.get("type") or "unknown", exc)
            errors.append(message)
            if config.get("notifications", {}).get("fail_closed", False):
                raise NotificationError(message)
    return {"sent": results, "errors": errors}
