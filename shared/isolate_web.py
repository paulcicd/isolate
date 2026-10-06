#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lightweight Isolate admin dashboard."""

import html
import json
import os
import re
import secrets
import time
import urllib.parse

from isolate import get_grant_record, list_grant_records, load_grants, load_project_sets, redis_client, update_grant_record
from isolate_audit import prepare_and_dispatch
from isolate_access import approve_access_request, deny_access_request, is_access_admin, list_access_requests, parse_duration, repeat_access_request, set_notification_status
from isolate_announcements import AnnouncementError, create_announcement, delete_announcement, list_announcements
from isolate_build import get_build_info
from isolate_config import load_config
from isolate_history import list_user_profiles, read_history, user_activity_summary
from isolate_health import run_health_checks
from isolate_identity import normalize_claims
from isolate_inventory import HostValidationError, bulk_update_hosts, create_host, get_host, list_hosts, update_host
from isolate_connectivity import ConnectivityError, check_host, get_last_check, save_check
from isolate_exports import ExportError, flatten_access_matrix, render_export
from isolate_dashboard_data import (
    DashboardDataError,
    build_access_matrix,
    collect_alerts,
    filter_jobs,
    fleet_progress,
    preview_grant_change,
    update_alert_state,
)
from isolate_jobs import JobError, create_runbook_fleet, get_job, list_jobs, read_job_output, request_job_cancel, retry_job
from isolate_notifications import NotificationError, notify_access_event
from isolate_packages import (
    AccessPackageError,
    assign_package,
    create_package,
    get_assignment,
    get_package,
    list_assignments,
    list_package_revisions,
    list_packages,
    preview_package_update,
    rollback_package,
    unassign_package,
    update_package,
)
from isolate_replay import find_session, parse_raw_replay
from isolate_policy import PolicyDenied, resolve_grant
from isolate_policy_bundle import PolicyBundleError, apply_bundle, blast_radius, export_bundle, plan_bundle, validate_bundle
from isolate_gitops import GitOpsError, git_policy_status, list_policy_snapshots, rollback_policy, save_policy_snapshot, sync_git_policy
from isolate_runbooks import list_runbooks
from isolate_sessions import SessionControlError, get_session, list_active_sessions, list_session_records, request_session_termination


_DASHBOARD_STARTED_AT = time.time()


def is_dashboard_admin(identity, config):
    groups = config.get("dashboard", {}).get("admin_groups") or config.get("history", {}).get("admin_groups") or []
    return is_access_admin(identity, groups)


def _secret_key(config):
    path = config.get("dashboard", {}).get("secret_key_file")
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as secret_f:
            return secret_f.read().strip()
    return os.environ.get("ISOLATE_DASHBOARD_SECRET", "dev-only-change-me")


def _build_info(config):
    try:
        from flask import current_app, has_app_context
        if has_app_context():
            cached = current_app.extensions.get("isolate_build_info")
            if cached:
                result = dict(cached)
                result["uptime_seconds"] = max(0, int(time.time() - _DASHBOARD_STARTED_AT))
                return result
    except (ImportError, RuntimeError):
        pass
    return get_build_info(config, _DASHBOARD_STARTED_AT)


_DASHBOARD_CSS = """
:root {
  color-scheme: light;
  --bg: #f4f6fa;
  --surface: #ffffff;
  --surface-muted: #eef1f7;
  --sidebar: #111622;
  --sidebar-hover: #1c2433;
  --sidebar-active: #252f44;
  --sidebar-line: #293246;
  --sidebar-text: #d8deeb;
  --sidebar-muted: #8f9bb3;
  --text: #192131;
  --muted: #68748a;
  --line: #dbe1ec;
  --accent: #4967d5;
  --accent-strong: #334fb7;
  --accent-soft: #edf0ff;
  --info: #3274c8;
  --info-soft: #eaf2fc;
  --positive: #286ea8;
  --positive-soft: #e8f3fb;
  --amber: #94600c;
  --amber-soft: #fff3d6;
  --red: #ae3f51;
  --red-soft: #fcebef;
  --topbar: rgba(255, 255, 255, 0.96);
  --table-head: #f7f8fb;
  --table-hover: #f7f9fd;
  --input: #ffffff;
  --terminal: #111722;
  --terminal-text: #dce4f3;
  --shadow: 0 1px 2px rgba(23, 31, 48, 0.05), 0 8px 24px rgba(23, 31, 48, 0.05);
}

html[data-theme="dark"] {
  color-scheme: dark;
  --bg: #0c1018;
  --surface: #151b27;
  --surface-muted: #1d2534;
  --sidebar: #080c13;
  --sidebar-hover: #171e2b;
  --sidebar-active: #222c40;
  --sidebar-line: #252d3d;
  --sidebar-text: #d7ddea;
  --sidebar-muted: #8894aa;
  --text: #e8ecf5;
  --muted: #98a4b9;
  --line: #2a3447;
  --accent: #8ea2ff;
  --accent-strong: #adbbff;
  --accent-soft: #252d4a;
  --info: #7eb2f3;
  --info-soft: #1b2b42;
  --positive: #72a9df;
  --positive-soft: #1a2b3d;
  --amber: #e1b45e;
  --amber-soft: #382d1a;
  --red: #ee91a0;
  --red-soft: #3a2028;
  --topbar: rgba(21, 27, 39, 0.96);
  --table-head: #19212e;
  --table-hover: #1a2230;
  --input: #111722;
  --terminal: #080c12;
  --terminal-text: #dce4f3;
  --shadow: 0 1px 2px rgba(0, 0, 0, 0.24), 0 10px 28px rgba(0, 0, 0, 0.18);
}

* { box-sizing: border-box; }
html { min-width: 320px; background: var(--bg); }
body {
  margin: 0;
  color: var(--text);
  background: var(--bg);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 14px;
  line-height: 1.5;
  letter-spacing: 0;
}

a { color: var(--accent); text-decoration: none; }
a:hover { color: var(--accent-strong); text-decoration: underline; }

.app-shell { min-height: 100vh; }
.sidebar {
  position: fixed;
  inset: 0 auto 0 0;
  z-index: 20;
  display: flex;
  width: 236px;
  flex-direction: column;
  overflow-y: auto;
  color: var(--sidebar-text);
  background: var(--sidebar);
  border-right: 1px solid var(--sidebar-line);
}
.brand {
  display: flex;
  min-height: 76px;
  align-items: center;
  gap: 12px;
  padding: 16px 18px;
  color: #ffffff;
  border-bottom: 1px solid var(--sidebar-line);
}
.brand:hover { color: #ffffff; text-decoration: none; }
.brand-mark {
  display: grid;
  width: 36px;
  height: 36px;
  flex: 0 0 36px;
  place-items: center;
  color: #ffffff;
  background: var(--accent);
  border-radius: 6px;
  font-size: 13px;
  font-weight: 800;
}
.brand-copy { display: flex; flex-direction: column; font-size: 16px; font-weight: 720; line-height: 1.2; }
.brand-copy small { margin-top: 3px; color: var(--sidebar-muted); font-size: 11px; font-weight: 600; text-transform: uppercase; }

.primary-nav { flex: 1; padding: 14px 10px; }
.nav-section + .nav-section { margin-top: 18px; }
.nav-label {
  display: block;
  padding: 0 10px 6px;
  color: var(--sidebar-muted);
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
}
.nav-link {
  display: flex;
  min-height: 36px;
  align-items: center;
  margin: 2px 0;
  padding: 8px 10px;
  color: var(--sidebar-text);
  border-left: 3px solid transparent;
  border-radius: 4px;
  font-weight: 560;
}
.nav-link:hover { color: #ffffff; background: var(--sidebar-hover); text-decoration: none; }
.nav-link.active { color: #ffffff; background: var(--sidebar-active); border-left-color: var(--accent); }

.sidebar-footer {
  display: grid;
  grid-template-columns: 34px minmax(0, 1fr);
  gap: 9px;
  align-items: center;
  padding: 14px 16px;
  border-top: 1px solid var(--sidebar-line);
}
.identity-details { font-size: 11px; overflow-wrap: anywhere; margin: 5px 0; }
.identity-details summary { cursor: pointer; }
.identity-details div { margin-top: 4px; }
.user-avatar {
  display: grid;
  width: 34px;
  height: 34px;
  place-items: center;
  color: #eef1ff;
  background: #303a55;
  border-radius: 50%;
  font-size: 11px;
  font-weight: 750;
}
.user-copy { min-width: 0; }
.user-name { display: block; overflow: hidden; color: #f3f5fa; font-size: 13px; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; }
.logout-link { display: inline-block; color: var(--sidebar-muted); font-size: 12px; }
.logout-link:hover { color: #ffffff; }

.main { min-height: 100vh; margin-left: 236px; }
.topbar {
  position: sticky;
  top: 0;
  z-index: 10;
  display: flex;
  min-height: 64px;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 0 28px;
  background: var(--topbar);
  border-bottom: 1px solid var(--line);
}
.topbar-title { font-size: 14px; font-weight: 700; }
.topbar-kicker { display: block; color: var(--muted); font-size: 11px; font-weight: 650; text-transform: uppercase; }
.runtime-state { display: flex; align-items: center; gap: 8px; color: var(--muted); font-size: 12px; font-weight: 600; }
.status-dot { width: 8px; height: 8px; background: var(--accent); border-radius: 50%; box-shadow: 0 0 0 3px var(--accent-soft); }

.content { width: 100%; max-width: 1600px; margin: 0 auto; padding: 28px; }
h1 { margin: 0 0 22px; font-size: 28px; line-height: 1.2; font-weight: 730; }
h2 { margin: 34px 0 12px; font-size: 18px; line-height: 1.3; font-weight: 700; }
h3 { margin: 24px 0 10px; font-size: 15px; font-weight: 700; }
p { margin: 10px 0; }
.page-lead { max-width: 720px; margin: -12px 0 22px; color: var(--muted); }
.muted { color: var(--muted); }

.grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
.metric {
  position: relative;
  min-height: 112px;
  padding: 20px;
  overflow: hidden;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 6px;
  box-shadow: var(--shadow);
}
.metric::before { position: absolute; inset: 0 auto 0 0; width: 4px; background: var(--accent); content: ""; }
.metric:nth-child(2)::before { background: var(--amber); }
.metric:nth-child(3)::before { background: var(--info); }
.metric strong { display: block; margin-bottom: 4px; font-size: 30px; line-height: 1; font-variant-numeric: tabular-nums; }
.metric .muted { font-size: 13px; font-weight: 600; }
.metric-link { display: inline-block; margin-top: 13px; font-size: 12px; font-weight: 700; }
.section-heading { display: flex; align-items: baseline; justify-content: space-between; gap: 18px; margin-top: 34px; }
.section-heading h2 { margin: 0; }
.empty-state { margin-top: 12px; padding: 28px; color: var(--muted); text-align: center; background: var(--surface); border: 1px dashed var(--line); border-radius: 6px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; margin: 0 0 14px; }
.toolbar form { flex: 1; }
.panel { margin-top: 14px; padding: 18px; background: var(--surface); border: 1px solid var(--line); border-radius: 6px; box-shadow: var(--shadow); }
.panel h2, .panel h3 { margin-top: 0; }
.summary-list { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin: 14px 0; }
.summary-item { padding: 12px; background: var(--surface-muted); border-radius: 5px; }
.summary-item strong { display: block; font-size: 20px; font-variant-numeric: tabular-nums; }
.progress { width: 150px; height: 8px; overflow: hidden; background: var(--surface-muted); border-radius: 4px; }
.progress > span { display: block; height: 100%; background: var(--accent); }
.matrix-wrap { overflow: auto; border: 1px solid var(--line); border-radius: 6px; box-shadow: var(--shadow); }
.matrix { width: max-content; min-width: 100%; }
.matrix th:first-child, .matrix td:first-child { position: sticky; left: 0; z-index: 2; background: var(--table-head); }
.matrix-cell { min-width: 154px; max-width: 220px; white-space: normal; }
.matrix-cell strong { display: block; margin-bottom: 3px; }
.matrix-allowed { background: var(--positive-soft); }
.matrix-partial, .matrix-mixed { background: var(--amber-soft); }
.matrix-denied { color: var(--muted); background: var(--surface-muted); }
.severity-critical { color: var(--red); background: var(--red-soft); }
.severity-high { color: var(--red); background: var(--red-soft); }
.severity-medium { color: var(--amber); background: var(--amber-soft); }
.severity-low { color: var(--info); background: var(--info-soft); }
.button-secondary { color: var(--accent); background: var(--surface); }
.button-secondary:hover { color: #ffffff; }
.button-danger { color: var(--red); background: var(--surface); border-color: var(--red); }
.button-danger:hover { color: #ffffff; background: var(--red); border-color: var(--red); }
.key-value { display: grid; grid-template-columns: minmax(130px, 190px) minmax(0, 1fr); gap: 7px 16px; }
.key-value dt { color: var(--muted); font-weight: 650; }
.key-value dd { margin: 0; overflow-wrap: anywhere; }

.table-wrap {
  width: 100%;
  margin-top: 14px;
  overflow-x: auto;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 6px;
  box-shadow: var(--shadow);
}
table { width: max-content; min-width: 100%; border-collapse: separate; border-spacing: 0; }
th, td { padding: 10px 12px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); font-size: 13px; }
th {
  color: var(--muted);
  background: var(--table-head);
  font-size: 11px;
  font-weight: 750;
  text-transform: uppercase;
  white-space: nowrap;
}
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: var(--table-hover); }
td { white-space: nowrap; }
td.cell-server-services, td.cell-server-note, td.cell-privileged-access-hint, td.cell-command {
  min-width: 170px;
  max-width: 280px;
  overflow-wrap: anywhere;
  white-space: normal;
}
td.cell-connection-id { max-width: 220px; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; }

.badge { display: inline-flex; min-height: 23px; align-items: center; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 750; white-space: nowrap; }
.badge-active, .badge-approved, .badge-allowed, .badge-success { color: var(--positive); background: var(--positive-soft); }
.badge-pending, .badge-vip, .badge-warning { color: var(--amber); background: var(--amber-soft); }
.badge-denied, .badge-failed, .badge-error { color: var(--red); background: var(--red-soft); }
.badge-completed { color: var(--info); background: var(--info-soft); }

input, select, textarea, button { min-height: 36px; margin: 2px; font: inherit; letter-spacing: 0; }
input, select, textarea {
  max-width: 100%;
  padding: 7px 10px;
  color: var(--text);
  background: var(--input);
  border: 1px solid var(--line);
  border-radius: 4px;
}
input::placeholder, textarea::placeholder { color: var(--muted); }
input:focus, select:focus, textarea:focus, button:focus-visible, a:focus-visible {
  outline: 3px solid rgba(73, 103, 213, 0.22);
  outline-offset: 1px;
  border-color: var(--accent);
}
button {
  padding: 7px 13px;
  color: #ffffff;
  background: var(--accent);
  border: 1px solid var(--accent);
  border-radius: 4px;
  cursor: pointer;
  font-weight: 680;
}
button:hover { background: var(--accent-strong); border-color: var(--accent-strong); }
button:disabled { cursor: not-allowed; opacity: 0.55; }
form { margin: 10px 0 18px; }
form.inline { display: inline-flex; flex-wrap: wrap; gap: 5px; align-items: center; margin: 0; }
form:not(.inline) { max-width: 1180px; padding: 18px; background: var(--surface); border: 1px solid var(--line); border-radius: 6px; }
form p { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
label { color: var(--text); font-size: 13px; font-weight: 600; }
label input[type="checkbox"] { min-height: auto; accent-color: var(--accent); }
form[action*="/terminate"] button { color: var(--red); background: var(--surface); border-color: var(--red); }
form[action*="/terminate"] button:hover { color: #ffffff; background: var(--red); border-color: var(--red); }

.notice { padding: 12px 14px; margin: 0 0 20px; color: var(--info); background: var(--info-soft); border: 1px solid var(--line); border-left: 4px solid var(--info); border-radius: 5px; }
.notice.error { color: var(--red); background: var(--red-soft); border-left-color: var(--red); }
.notice.warning { color: var(--amber); background: var(--amber-soft); border-left-color: var(--amber); }
.notice.info, .notice.success { color: var(--positive); background: var(--positive-soft); border-left-color: var(--positive); }

pre { max-width: 100%; padding: 16px; overflow: auto; color: var(--terminal-text); background: var(--terminal); border: 1px solid var(--line); border-radius: 6px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; }
code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 0.92em; }
.terminal { border: 1px solid var(--line); border-radius: 6px; box-shadow: var(--shadow); }

.topbar-actions { display: flex; align-items: center; gap: 12px; }
.theme-switch, .locale-switch {
  display: inline-grid;
  grid-template-columns: repeat(2, minmax(54px, 1fr));
  padding: 3px;
  background: var(--surface-muted);
  border: 1px solid var(--line);
  border-radius: 6px;
}
.theme-switch button, .locale-switch a {
  display: grid;
  min-height: 28px;
  margin: 0;
  padding: 3px 9px;
  place-items: center;
  color: var(--muted);
  background: transparent;
  border: 0;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 650;
}
.theme-switch button:hover, .locale-switch a:hover { color: var(--text); background: var(--surface); text-decoration: none; }
.theme-switch button[aria-pressed="true"], .locale-switch a.active { color: var(--text); background: var(--surface); box-shadow: 0 1px 3px rgba(20, 28, 45, 0.16); }
.locale-switch { grid-template-columns: repeat(2, 38px); }
.locale-switch a { min-width: 38px; font-size: 11px; font-weight: 720; }
.page-help {
  max-width: 900px;
  margin: -10px 0 22px;
  color: var(--muted);
  border-bottom: 1px solid var(--line);
}
.page-help summary { width: max-content; padding: 6px 0 9px; color: var(--accent); cursor: pointer; font-size: 12px; font-weight: 700; }
.page-help p { max-width: 820px; margin: 0 0 14px; }
.field-help {
  display: inline-grid;
  width: 17px;
  height: 17px;
  margin-left: 3px;
  place-items: center;
  color: var(--accent);
  background: var(--accent-soft);
  border-radius: 50%;
  cursor: help;
  font-size: 11px;
  font-style: normal;
  font-weight: 750;
  vertical-align: middle;
}
.build-info { padding: 10px 16px; color: var(--sidebar-muted); border-top: 1px solid var(--sidebar-line); font-size: 11px; line-height: 1.45; }
.build-info strong { display: block; color: var(--sidebar-text); font-size: 12px; }
.docs-layout { display: grid; grid-template-columns: minmax(0, 1fr) 260px; gap: 28px; align-items: start; }
.docs-main { min-width: 0; }
.docs-section { padding: 22px 0; border-top: 1px solid var(--line); }
.docs-section:first-child { padding-top: 0; border-top: 0; }
.docs-section h2 { margin-top: 0; }
.docs-section ul { padding-left: 20px; }
.docs-toc { position: sticky; top: 86px; padding: 16px; background: var(--surface); border: 1px solid var(--line); border-radius: 6px; box-shadow: var(--shadow); }
.docs-toc strong { display: block; margin-bottom: 8px; }
.docs-toc a { display: block; padding: 4px 0; font-size: 12px; }
.build-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
.build-grid div { padding: 12px; background: var(--surface-muted); border-radius: 5px; }
.build-grid strong { display: block; margin-bottom: 3px; font-size: 12px; }
.package-rule-example { font-size: 12px; }

@media (max-width: 1050px) {
  .sidebar { width: 208px; }
  .main { margin-left: 208px; }
  .content { padding: 22px; }
  .summary-list { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 760px) {
  .sidebar { position: static; width: 100%; max-height: none; }
  .brand { min-height: 62px; }
  .primary-nav { display: flex; gap: 6px; overflow-x: auto; padding: 8px 10px; }
  .nav-section { display: flex; gap: 4px; margin: 0 !important; }
  .nav-label, .sidebar-footer, .build-info { display: none; }
  .nav-link { min-height: 34px; flex: 0 0 auto; padding: 7px 9px; border-left: 0; border-bottom: 2px solid transparent; }
  .nav-link.active { border-bottom-color: var(--accent); }
  .main { margin-left: 0; }
  .topbar { position: static; min-height: 54px; padding: 0 16px; }
  .runtime-state { display: none; }
  .topbar-actions { gap: 8px; }
  .content { padding: 20px 16px; }
  .grid { grid-template-columns: 1fr; }
  .summary-list { grid-template-columns: 1fr 1fr; }
  .key-value { grid-template-columns: 1fr; gap: 2px; }
  .key-value dd { margin-bottom: 8px; }
  h1 { font-size: 24px; }
  form:not(.inline) { padding: 14px; }
  .locale-switch { display: none; }
  .docs-layout { grid-template-columns: 1fr; }
  .docs-toc { position: static; order: -1; }
  .build-grid { grid-template-columns: 1fr; }
}
"""


_ACTIVE_NAV_SCRIPT = """
document.querySelectorAll('.nav-link').forEach(function (link) {
  var href = new URL(link.href).pathname;
  var path = window.location.pathname;
  if ((href === '/' && path === '/') || (href !== '/' && (path === href || path.indexOf(href + '/') === 0))) {
    link.classList.add('active');
    link.setAttribute('aria-current', 'page');
  }
});
document.querySelectorAll('[data-theme-choice]').forEach(function (button) {
  function updateState() {
    button.setAttribute('aria-pressed', String(document.documentElement.dataset.theme === button.dataset.themeChoice));
  }
  button.addEventListener('click', function () {
    document.documentElement.dataset.theme = button.dataset.themeChoice;
    localStorage.setItem('isolate-theme', button.dataset.themeChoice);
    document.querySelectorAll('[data-theme-choice]').forEach(function (choice) {
      choice.setAttribute('aria-pressed', String(choice.dataset.themeChoice === button.dataset.themeChoice));
    });
  });
  updateState();
});
"""


_THEME_BOOTSTRAP_SCRIPT = """
(function () {
  var saved = localStorage.getItem('isolate-theme');
  var preferred = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.dataset.theme = saved === 'dark' || saved === 'light' ? saved : preferred;
})();
"""


_SHELL_I18N = {
    "en": {
        "operations": "Operations", "summary": "Summary", "jobs": "Jobs & runbooks", "alerts": "Alert center",
        "active_sessions": "Active sessions", "history": "History", "inventory": "Inventory", "announcements": "Announcements",
        "access_control": "Access control", "requests": "Requests", "grants": "Grants", "packages": "Access packages",
        "matrix": "Access matrix", "simulator": "Policy simulator", "platform": "Platform", "gitops": "GitOps",
        "users": "Users", "notifications": "Notifications", "documentation": "Documentation", "sign_out": "Sign out",
        "bastion_control": "Bastion control", "operations_console": "Operations console", "secured": "Secured by Keycloak",
        "day": "Day", "night": "Night", "about": "About this page", "primary_nav": "Primary navigation",
        "theme": "Color theme", "language": "Language",
    },
    "ru": {
        "operations": "Операции", "summary": "Обзор", "jobs": "Задачи и ранбуки", "alerts": "Центр алертов",
        "active_sessions": "Активные сессии", "history": "История", "inventory": "Инвентарь", "announcements": "Объявления",
        "access_control": "Управление доступом", "requests": "Запросы", "grants": "Гранты", "packages": "Пакеты доступа",
        "matrix": "Матрица доступа", "simulator": "Симулятор политик", "platform": "Платформа", "gitops": "GitOps",
        "users": "Пользователи", "notifications": "Уведомления", "documentation": "Документация", "sign_out": "Выйти",
        "bastion_control": "Управление бастионом", "operations_console": "Операционная консоль", "secured": "Защищено Keycloak",
        "day": "День", "night": "Ночь", "about": "Об этой странице", "primary_nav": "Основная навигация",
        "theme": "Цветовая тема", "language": "Язык",
    },
}


_PAGE_HELP = {
    "Isolate Dashboard": {
        "en": "Operational overview of active sessions, pending access requests, recent connections, jobs, and security alerts.",
        "ru": "Операционный обзор активных сессий, запросов доступа, последних подключений, задач и алертов безопасности.",
    },
    "Jobs & Runbooks": {
        "en": "Run approved operational procedures across one host or a fleet, then monitor progress, output, retries, and cancellations.",
        "ru": "Запускайте разрешённые операции на одном сервере или группе серверов и отслеживайте прогресс, вывод, повторы и отмену.",
    },
    "Alert Center": {
        "en": "Review session risks, failed jobs, and notification delivery failures; acknowledge or resolve findings with an audit trail.",
        "ru": "Проверяйте риски сессий, ошибки задач и доставки уведомлений; подтверждайте и закрывайте события с сохранением аудита.",
    },
    "Access Matrix": {
        "en": "Inspect effective user and group access by project, identify conflicting grants, and preview the blast radius of changes.",
        "ru": "Смотрите итоговый доступ пользователей и групп по проектам, находите конфликты и оценивайте влияние изменений.",
    },
    "Active Sessions": {
        "en": "See current SSH connections, their duration and target identity, and terminate a session when an incident requires it.",
        "ru": "Смотрите текущие SSH-подключения, их длительность и целевого пользователя; при необходимости завершайте сессии.",
    },
    "History": {
        "en": "Search audited SSH connections by user, project, host ID, host name, or target address and open their session details.",
        "ru": "Ищите SSH-подключения по пользователю, проекту, ID или имени сервера и открывайте подробности сессии.",
    },
    "Access Requests": {
        "en": "Review temporary access requests, comments, tickets, notification status, and approve or deny break-glass grants.",
        "ru": "Обрабатывайте запросы временного доступа, комментарии и тикеты; одобряйте или отклоняйте break-glass доступ.",
    },
    "Inventory": {
        "en": "Browse bastion-managed hosts, service metadata, VIP markers, and privileged access guidance. Host changes are audited.",
        "ru": "Просматривайте серверы, сервисы, VIP-метки и инструкции по привилегированному доступу. Изменения аудируются.",
    },
    "Announcements": {
        "en": "Publish time-limited operational notices globally or for a project or host. Notices appear in terminal search and before connection.",
        "ru": "Публикуйте временные операционные уведомления глобально, для проекта или сервера. Они отображаются в поиске и перед подключением.",
    },
    "Session Details": {
        "en": "Inspect one connection's identity, policy decision, commands, timestamps, exit status, raw log, and replay artifacts.",
        "ru": "Изучайте identity, решение политики, команды, время, код выхода, raw-лог и replay выбранного подключения.",
    },
    "Live Session": {
        "en": "Follow newly written terminal output for an active connection. This observational view is not Web SSH.",
        "ru": "Наблюдайте новый терминальный вывод активного подключения. Это режим просмотра, а не Web SSH.",
    },
    "Session Replay": {
        "en": "Replay the recorded terminal stream with seek, speed, ANSI rendering, and raw or JSON downloads.",
        "ru": "Воспроизводите запись терминала с перемоткой, скоростью, ANSI-рендерингом и выгрузкой raw или JSON.",
    },
    "Policy Simulator": {
        "en": "Explain which grant applies to an identity, project, and host before changing production access.",
        "ru": "Проверяйте, какой grant сработает для identity, проекта и сервера до изменения production-доступа.",
    },
    "Policy GitOps": {
        "en": "Validate, compare, apply, and roll back optional Git-managed grants and project sets while tracking Redis drift.",
        "ru": "Проверяйте, сравнивайте, применяйте и откатывайте Git-managed grants/project sets с контролем drift в Redis.",
    },
    "Users": {
        "en": "Inspect identities observed in audit data together with effective grants, active sessions, and connection history.",
        "ru": "Просматривайте identity из аудита вместе с действующими grants, активными сессиями и историей подключений.",
    },
    "User Details": {
        "en": "Review one user's observed groups, access rules, active sessions, and historical activity.",
        "ru": "Проверяйте группы, правила доступа, активные сессии и историю выбранного пользователя.",
    },
    "Notifications": {
        "en": "Check recent webhook, Telegram, and email delivery outcomes for access and session events.",
        "ru": "Проверяйте доставку webhook, Telegram и email-уведомлений о доступе и сессиях.",
    },
    "Grants": {
        "en": "Manage low-level RBAC grants and project sets. Package-managed grants are changed through Access Packages.",
        "ru": "Управляйте низкоуровневыми RBAC grants и project sets. Пакетные grants изменяются через Пакеты доступа.",
    },
    "Access Packages": {
        "en": "Create reusable access profiles, preview revisions, and assign them to Keycloak users, groups, or roles.",
        "ru": "Создавайте переиспользуемые профили доступа, проверяйте ревизии и назначайте их пользователям, группам или ролям Keycloak.",
    },
    "Documentation": {
        "en": "A practical guide to identity, inventory, policies, packages, temporary access, sessions, jobs, backup, and updates.",
        "ru": "Практическое руководство по identity, инвентарю, политикам, пакетам, временному доступу, сессиям, backup и обновлениям.",
    },
}


_FIELD_HELP = {
    "en": {
        "q": "Free-text filter for the current table.", "status": "Lifecycle or execution state to display.",
        "user": "Verified Keycloak username.", "group": "Exact Keycloak group claim.", "role": "Exact signed token role.",
        "name": "Human-readable object or subject name.", "description": "Short administrator-facing purpose and scope.",
        "project": "Exact Isolate project name.", "groups": "Comma-separated Keycloak groups used by the simulator.",
        "roles": "Comma-separated signed token roles used by the simulator.",
        "host": "Optional server ID restriction.", "remote_user": "Unix account used on the target host.",
        "sudo_mode": "Whether and how the remote session elevates privileges.", "allowed_actions": "Comma-separated capabilities such as ssh, runbook, command, operate.",
        "ttl": "Assignment lifetime, for example 2h or 7d.", "ticket": "Incident or change ticket associated with the action.",
        "reason": "Operational justification stored in audit data.", "comment": "Immutable decision or review note.",
        "selector_type": "Choose an exact project, glob, or named project set.", "selector_value": "Value for the selected project selector.",
        "access_json": "JSON list of package access rules; every rule needs one selector and a remote user.",
        "default_ttl": "Default lifetime used when assignment does not specify one.", "max_ttl": "Maximum assignment lifetime allowed by this package.",
        "permanent_allowed": "Allow assignments without an expiration time.", "approval_required": "Mark this package as requiring an administrator assignment decision.",
        "admin_groups": "Comma-separated Keycloak groups allowed to assign this package.", "ticket_required": "Require a ticket for every assignment.",
        "minimum_approvals": "Required approvers; values above one block direct assignment until a multi-approval workflow is configured.",
        "package": "Package ID or exact package name.", "subject": "Identity type receiving the package: user, group, or role.",
        "revision": "Immutable package revision used for rollback.", "permanent": "Create an assignment without expiration when the package permits it.",
        "ip": "Target IPv4/IPv6 address or validated hostname.", "port": "Target SSH port.",
        "services": "Free-form searchable service inventory.", "note": "Short operational note shown in inventory.",
        "maintenance_reason": "Reason shown while new connections are paused.", "maintenance_until": "Unix timestamp when maintenance expires; empty means no deadline.",
        "severity": "Visual priority of an operational announcement.",
        "policy_action": "Capability evaluated by the production policy resolver.", "confirm": "Explicitly acknowledge this audited mutation.",
    },
    "ru": {
        "q": "Свободный текст для фильтрации текущей таблицы.", "status": "Состояние жизненного цикла или выполнения.",
        "user": "Проверенное имя пользователя Keycloak.", "group": "Точное значение группы из Keycloak token.", "role": "Точная роль из подписанного token.",
        "name": "Понятное имя объекта или субъекта.", "description": "Краткое назначение и область действия для администраторов.",
        "project": "Точное имя проекта Isolate.", "groups": "Группы Keycloak через запятую для policy simulator.",
        "roles": "Роли из подписанного token через запятую для policy simulator.",
        "host": "Необязательное ограничение по server ID.", "remote_user": "Unix-пользователь для подключения к целевому серверу.",
        "sudo_mode": "Режим повышения привилегий в удалённой сессии.", "allowed_actions": "Доступные действия через запятую: ssh, runbook, command, operate.",
        "ttl": "Срок назначения, например 2h или 7d.", "ticket": "Номер incident/change, связанный с операцией.",
        "reason": "Обоснование, сохраняемое в аудите.", "comment": "Неизменяемый комментарий к решению или ревью.",
        "selector_type": "Выберите точный проект, glob-шаблон или именованный project set.", "selector_value": "Значение выбранного project selector.",
        "access_json": "JSON-список правил пакета; каждому правилу нужен один selector и remote user.",
        "default_ttl": "Срок по умолчанию, если при назначении он не указан.", "max_ttl": "Максимально допустимый срок назначения пакета.",
        "permanent_allowed": "Разрешить назначения без срока истечения.", "approval_required": "Пакет должен назначаться администратором после проверки.",
        "admin_groups": "Группы Keycloak через запятую, которым разрешено назначать пакет.", "ticket_required": "Требовать тикет для каждого назначения.",
        "minimum_approvals": "Число согласующих; значение больше одного блокирует прямое назначение до появления multi-approval workflow.",
        "package": "ID пакета или его точное имя.", "subject": "Тип получателя пакета: user, group или role.",
        "revision": "Неизменяемая ревизия пакета для rollback.", "permanent": "Назначение без срока, если это разрешено пакетом.",
        "ip": "IPv4/IPv6 или валидированное имя целевого сервера.", "port": "SSH-порт целевого сервера.",
        "services": "Свободное searchable-описание сервисов.", "note": "Краткая операционная заметка в inventory.",
        "maintenance_reason": "Причина приостановки новых подключений.", "maintenance_until": "Unix timestamp завершения maintenance; пусто означает без срока.",
        "severity": "Визуальный приоритет операционного объявления.",
        "policy_action": "Действие, проверяемое production policy resolver.", "confirm": "Явное подтверждение аудируемого изменения.",
    },
}


def _dashboard_locale(config=None):
    default = str((config or {}).get("dashboard", {}).get("default_locale") or "en").lower()
    locale = default if default in _SHELL_I18N else "en"
    try:
        from flask import has_request_context, request, session
        if has_request_context():
            requested = str(request.args.get("lang") or "").lower()
            if requested in _SHELL_I18N:
                session["dashboard_locale"] = requested
            locale = session.get("dashboard_locale") or locale
    except (ImportError, RuntimeError):
        pass
    return locale if locale in _SHELL_I18N else "en"


def _locale_url(locale):
    try:
        from flask import has_request_context, request
        if has_request_context():
            values = request.args.to_dict(flat=False)
            values["lang"] = [locale]
            return request.path + "?" + urllib.parse.urlencode(values, doseq=True)
    except (ImportError, RuntimeError):
        pass
    return "?lang={}".format(locale)


def _page_help(title, locale):
    descriptions = _PAGE_HELP.get(str(title))
    if not descriptions and str(title).startswith("Job "):
        descriptions = {
            "en": "Inspect per-host state, output, errors, cancellation status, and retries for this job.",
            "ru": "Проверяйте состояние по серверам, вывод, ошибки, отмену и повторные запуски этой задачи.",
        }
    if not descriptions:
        return ""
    return '<details class="page-help"><summary>{}</summary><p>{}</p></details>'.format(
        html.escape(_SHELL_I18N[locale]["about"]), html.escape(descriptions.get(locale) or descriptions["en"])
    )


def _html(title, body, config=None, notice=None):
    locale = _dashboard_locale(config)
    words = _SHELL_I18N[locale]
    build = _build_info(config)
    refresh = ""
    refresh_seconds = int((config or {}).get("dashboard", {}).get("refresh_seconds") or 0)
    if refresh_seconds > 0:
        refresh = '<meta http-equiv="refresh" content="{}">'.format(refresh_seconds)
    notice_html = ""
    if notice:
        notice_html = '<div class="notice {}">{}</div>'.format(
            html.escape(notice.get("level", "info")),
            html.escape(notice.get("text", "")),
        )
    username = "Administrator"
    identity = {}
    try:
        from flask import has_request_context, session
        if has_request_context() and isinstance(session.get("identity"), dict):
            identity = session["identity"]
            username = str(identity.get("username") or username)
    except (ImportError, RuntimeError):
        pass
    initials = "".join(part[:1] for part in username.replace(".", " ").split()[:2]).upper() or "AD"
    admin_groups = (config or {}).get("dashboard", {}).get("admin_groups") or (config or {}).get("history", {}).get("admin_groups") or []
    matched_groups = sorted(set(identity.get("groups") or []) & set(admin_groups))
    labels = ("Роль Dashboard", "Группы доступа", "Группы OIDC", "Роли Keycloak") if locale == "ru" else ("Dashboard role", "Access groups", "OIDC groups", "Keycloak roles")
    identity_details = '<details class="identity-details"><summary>{}: {}</summary>{}</details>'.format(
        labels[0], "Admin" if is_dashboard_admin(identity, config or {}) else "—",
        "".join('<div><strong>{}</strong>: {}</div>'.format(html.escape(label), html.escape(", ".join(values) or "—")) for label, values in zip(labels[1:], (matched_groups, identity.get("groups") or [], identity.get("roles") or []))),
    )
    field_help_script = """
(function () {{
  var help = {field_help};
  document.querySelectorAll('input[name], select[name], textarea[name]').forEach(function (field) {{
    var description = help[field.name];
    if (!description || field.type === 'hidden') return;
    field.title = field.title || description;
    var label = field.closest('label');
    if (label && !label.querySelector('.field-help')) {{
      var marker = document.createElement('span');
      marker.className = 'field-help'; marker.textContent = 'i'; marker.title = description;
      marker.setAttribute('aria-label', description); label.appendChild(marker);
    }}
  }});
}})();
""".format(field_help=json.dumps(_FIELD_HELP[locale], ensure_ascii=False).replace("</", "<\\/"))
    return """<!doctype html>
<html lang="{locale}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">{refresh}<title>{title}</title>
<script>{theme_bootstrap_script}</script>
<style>{css}</style></head><body>
<div class="app-shell">
  <aside class="sidebar">
    <a class="brand" href="/" aria-label="Isolate dashboard">
      <span class="brand-mark">IS</span>
      <span class="brand-copy">Isolate <small>{bastion_control}</small></span>
    </a>
    <nav class="primary-nav" aria-label="{primary_nav}">
      <div class="nav-section"><span class="nav-label">{operations}</span>
        <a class="nav-link" href="/">{summary}</a><a class="nav-link" href="/jobs">{jobs}</a><a class="nav-link" href="/alerts">{alerts}</a><a class="nav-link" href="/sessions/active">{active_sessions}</a><a class="nav-link" href="/history">{history}</a><a class="nav-link" href="/inventory">{inventory}</a><a class="nav-link" href="/announcements">{announcements}</a>
      </div>
      <div class="nav-section"><span class="nav-label">{access_control}</span>
        <a class="nav-link" href="/access">{requests}</a><a class="nav-link" href="/grants">{grants}</a><a class="nav-link" href="/packages">{packages}</a><a class="nav-link" href="/policy/matrix">{matrix}</a><a class="nav-link" href="/policy/simulate">{simulator}</a>
      </div>
      <div class="nav-section"><span class="nav-label">{platform}</span>
        <a class="nav-link" href="/policy/gitops">{gitops}</a><a class="nav-link" href="/users">{users}</a><a class="nav-link" href="/notifications">{notifications}</a><a class="nav-link" href="/docs">{documentation}</a>
      </div>
    </nav>
    <div class="build-info"><strong>v{version}</strong>{revision} &middot; schema {schema}<br>Python {python}</div>
    <div class="sidebar-footer">
      <span class="user-avatar">{initials}</span>
      <span class="user-copy"><span class="user-name">{username}</span>{identity_details}<a class="logout-link" href="/logout">{sign_out}</a></span>
    </div>
  </aside>
  <main class="main">
    <header class="topbar"><div><span class="topbar-kicker">Isolate v2</span><span class="topbar-title">{operations_console}</span></div><div class="topbar-actions"><div class="locale-switch" aria-label="{language}"><a class="{en_active}" href="{en_url}">EN</a><a class="{ru_active}" href="{ru_url}">RU</a></div><div class="theme-switch" aria-label="{theme}"><button type="button" data-theme-choice="light" aria-pressed="false">{day}</button><button type="button" data-theme-choice="dark" aria-pressed="false">{night}</button></div><div class="runtime-state"><span class="status-dot"></span>{secured}</div></div></header>
    <div class="content">{notice}{page_help}{body}</div>
  </main>
</div>
<script>{active_nav_script}{field_help_script}</script>
</body></html>""".format(
        locale=locale,
        refresh=refresh,
        title=html.escape(str(title)),
        theme_bootstrap_script=_THEME_BOOTSTRAP_SCRIPT,
        css=_DASHBOARD_CSS,
        initials=html.escape(initials),
        username=html.escape(username),
        identity_details=identity_details,
        version=html.escape(str(build.get("version") or "unknown")),
        revision=html.escape(str(build.get("revision_short") or "unknown")),
        schema=html.escape(str(build.get("schema_version") or "n/a")),
        python=html.escape(str(build.get("python") or "unknown")),
        notice=notice_html,
        page_help=_page_help(title, locale),
        body=body,
        active_nav_script=_ACTIVE_NAV_SCRIPT,
        field_help_script=field_help_script,
        en_active="active" if locale == "en" else "",
        ru_active="active" if locale == "ru" else "",
        en_url=html.escape(_locale_url("en"), quote=True),
        ru_url=html.escape(_locale_url("ru"), quote=True),
        **{key: html.escape(str(value)) for key, value in words.items()}
    )


def _table(rows, columns):
    header = "".join("<th scope=\"col\">{}</th>".format(html.escape(str(label))) for key, label in columns)
    body = ""
    for row in rows:
        cells = []
        for key, _ in columns:
            value = row.get(key) or ""
            safe_html = key in (
                "raw", "project_link", "history", "details", "replay", "live", "control",
                "user_link", "package_link", "edit", "actions", "progress", "source_link", "severity_badge",
            )
            rendered = str(value) if safe_html else html.escape(str(value))
            normalized = str(value).strip().lower()
            if not safe_html and key == "server_vip_marker" and rendered:
                rendered = '<span class="badge badge-vip">{}</span>'.format(rendered)
            elif not safe_html and key == "status" and rendered:
                badge_class = "badge-{}".format("".join(ch for ch in normalized if ch.isalnum() or ch == "-") or "status")
                rendered = '<span class="badge {}">{}</span>'.format(badge_class, rendered)
            elif not safe_html and key == "result" and rendered:
                if normalized in ("allowed", "ok", "success") or normalized.startswith("exit=0"):
                    badge_class = "badge-success"
                elif "denied" in normalized or "failed" in normalized or (normalized.startswith("exit=") and normalized != "exit=0"):
                    badge_class = "badge-error"
                else:
                    badge_class = "badge-completed"
                rendered = '<span class="badge {}">{}</span>'.format(badge_class, rendered)
            cell_class = "cell-{}".format(str(key).replace("_", "-"))
            cells.append('<td class="{}">{}</td>'.format(cell_class, rendered))
        body += "<tr>{}</tr>".format("".join(cells))
    return '<div class="table-wrap"><table><thead><tr>{}</tr></thead><tbody>{}</tbody></table></div>'.format(header, body)


def _split_values(value):
    return [item.strip() for item in str(value or "").replace("\n", ",").split(",") if item.strip()]


def _optional_bool(value):
    if value in (None, ""):
        return None
    normalized = str(value).strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise ValueError("boolean field must be true or false")


def _format_ts(value):
    if not value:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(value)))
    except (TypeError, ValueError, OverflowError):
        return str(value)


def _parse_json_object(value, field_name="JSON parameters"):
    try:
        result = json.loads(value or "{}")
    except (TypeError, ValueError) as exc:
        raise ValueError("{} are invalid: {}".format(field_name, exc)) from exc
    if not isinstance(result, dict):
        raise ValueError("{} must be a JSON object".format(field_name))
    return result


def _parse_json_list(value, field_name="JSON value"):
    try:
        result = json.loads(value or "[]")
    except (TypeError, ValueError) as exc:
        raise ValueError("{} is invalid: {}".format(field_name, exc)) from exc
    if not isinstance(result, list):
        raise ValueError("{} must be a JSON list".format(field_name))
    return result


def _package_form_payload(form, current=None):
    current = current or {}
    lifecycle = current.get("lifecycle") or {}
    approval = current.get("approval") or {}
    return {
        "name": str(form.get("name") or current.get("name") or "").strip(),
        "description": str(form.get("description") or "").strip(),
        "status": str(form.get("status") or current.get("status") or "enabled"),
        "access": _parse_json_list(form.get("access_json"), "package access JSON"),
        "lifecycle": {
            "default_ttl": str(form.get("default_ttl") or "").strip() or None,
            "max_ttl": str(form.get("max_ttl") or "").strip() or None,
            "permanent_allowed": form.get("permanent_allowed") == "true",
        },
        "approval": {
            "required": form.get("approval_required") == "true",
            "admin_groups": _split_values(form.get("admin_groups")),
            "ticket_required": form.get("ticket_required") == "true",
            "minimum_approvals": int(form.get("minimum_approvals") or approval.get("minimum_approvals") or 1),
        },
    }


def _documentation_body(locale, build):
    if locale == "ru":
        title = "Документация Isolate"
        lead = "Краткое практическое руководство для администраторов bastion-платформы. Примеры безопасны для чтения, но production-значения следует проверять через preview и policy simulator."
        toc_title = "На этой странице"
        sections = [
            ("identity", "Identity и вход", """
<p>Сотрудник подключается к bastion под своим Unix/AD-пользователем и выполняет <code>isolate login</code>. Device Flow открывает Keycloak в браузере, а локальный cache хранит token. Команды <code>s</code>, <code>g</code>, история и access workflow каждый раз используют только проверенные JWT claims.</p>
<pre>isolate login
isolate whoami
s redis
g 10703</pre>
<p>Группы из редактируемого файла не считаются доверенными: подпись, issuer, audience и срок JWT проверяются через защищённый JWKS cache.</p>"""),
            ("inventory", "Инвентарь и подключение", """
<p>Project объединяет серверы. Host содержит адрес, имя, remote user по умолчанию, сервисы, заметку и optional VIP/privileged access hint. Поиск <code>s</code> видит только разрешённые policy серверы; <code>g</code> подключается только после точного host match.</p>
<pre>isolate host list --project payments-prod
isolate host show 10703
isolate host update 10703 --services "nginx, redis" --note "API frontend"
isolate host maintenance 10703 --until 2h --reason "CHG-1042"
isolate host check 10703 --ssh</pre>
<p>Maintenance mode блокирует новые подключения, но не завершает активные сессии. Группы обхода задаются явно в config.</p>"""),
            ("policy", "Project sets и grants", """
<p>Project set объединяет exact projects и glob patterns. Grant связывает user/group/role с selector, remote user, sudo mode и allowed actions. Без matching grant доступ закрыт.</p>
<pre>isolate project-set add prod-apps --project payments-prod --project-glob '*-stage'
isolate grant add --group Support-L2 --project-set prod-apps --remote-user support --sudo-mode none
isolate grant explain --user demo.alex --group Support-L2 --host 10703</pre>"""),
            ("packages", "Пакеты доступа", """
<p>Access Package — именованный шаблон, который включает несколько правил, TTL и approval route. Его можно назвать по внутреннему стандарту и назначить одновременно группам, пользователям или ролям. Назначение создаёт управляемые grants; редактировать их вручную нельзя.</p>
<pre>isolate package create --file support-readonly.yml
isolate package preview "Support Read-Only" --file support-readonly-v2.yml
isolate package apply "Support Read-Only" --file support-readonly-v2.yml --yes
isolate package assign "Support Read-Only" --group Support-L1 --group Support-L2 --ttl 7d --ticket CHG-1042 --yes
isolate package revisions "Support Read-Only"
isolate package rollback "Support Read-Only" --revision 1 --yes</pre>
<p>Перед apply показывается число затронутых subjects и операций create/update/delete. Ревизии неизменяемы, поэтому rollback воспроизводим.</p>"""),
            ("temporary", "Временный доступ", """
<p>Если постоянного grant нет, пользователь создаёт break-glass request. Администратор получает уведомление, проверяет тикет и назначает TTL; временный grant перестаёт работать после <code>expires_at</code>.</p>
<pre>isolate access request --project payments-prod --host 10703 --remote-user dba --sudo-mode none --reason "Incident diagnostics" --ticket INC-2048
isolate access approve --id 42 --ttl 2h --comment "Approved for incident window"</pre>"""),
            ("operations", "Сессии, jobs и аудит", """
<p>History и Session Details показывают policy decision, целевой host, remote user, JSONL events и raw terminal transcript. Replay восстанавливается из raw log. Structured command events появляются только после установки target shell hooks.</p>
<p>Jobs &amp; Runbooks запускает заранее проверенные операции по одному серверу или fleet. Произвольные команды должны включаться отдельно и ограничиваться grants, scopes, allowlist и подтверждением.</p>
<pre>isolate announcement add --project payments-prod --severity warning --ttl 2h --text "Deploy window"
isolate user activity demo.alex
isolate export history --format csv --output history.csv</pre>
<p>Announcements видны в <code>s</code> и перед <code>g</code>. Inventory, History, Users и Access Matrix поддерживают выгрузки CSV/JSON.</p>"""),
            ("lifecycle", "Backup, GitOps и обновление", """
<p>Перед релизом создайте service backup и проверьте health. GitOps для grants/project sets остаётся opt-in; при <code>enforce_git</code> ручные policy mutations блокируются.</p>
<pre>sudo /opt/auth/scripts/isolate-backup.sh create
git pull --ff-only
sudo bash /opt/auth/scripts/fix-perms.sh
curl -fsS http://127.0.0.1:8080/health</pre>
<p>Для бесшовного обновления запускайте два dashboard экземпляра за reverse proxy и выводите старый instance после успешной health-проверки нового. Активные SSH-сессии wrapper не следует перезапускать принудительно.</p>"""),
        ]
    else:
        title = "Isolate Documentation"
        lead = "A practical guide for bastion administrators. Examples are safe to read, but production values should be reviewed through preview and the policy simulator."
        toc_title = "On this page"
        sections = [
            ("identity", "Identity and sign-in", """
<p>An employee enters the bastion with their own Unix/AD account and runs <code>isolate login</code>. Device Flow opens Keycloak in a browser, while the local cache stores tokens. <code>s</code>, <code>g</code>, history, and access workflows authorize only verified JWT claims.</p>
<pre>isolate login
isolate whoami
s redis
g 10703</pre>
<p>Editable cached groups are never trusted. JWT signature, issuer, audience, and expiration are checked through the protected JWKS cache.</p>"""),
            ("inventory", "Inventory and connections", """
<p>A project groups hosts. A host stores its address, name, default remote user, services, notes, and optional VIP or privileged-access guidance. <code>s</code> returns only policy-visible hosts; <code>g</code> connects only after an exact host match.</p>
<pre>isolate host list --project payments-prod
isolate host show 10703
isolate host update 10703 --services "nginx, redis" --note "API frontend"
isolate host maintenance 10703 --until 2h --reason "CHG-1042"
isolate host check 10703 --ssh</pre>
<p>Maintenance mode blocks new connections without terminating active sessions. Bypass groups must be configured explicitly.</p>"""),
            ("policy", "Project sets and grants", """
<p>A project set combines exact projects and glob patterns. A grant maps a user, group, or role to a selector, remote user, sudo mode, and allowed actions. Access is denied without a matching grant.</p>
<pre>isolate project-set add prod-apps --project payments-prod --project-glob '*-stage'
isolate grant add --group Support-L2 --project-set prod-apps --remote-user support --sudo-mode none
isolate grant explain --user demo.alex --group Support-L2 --host 10703</pre>"""),
            ("packages", "Access packages", """
<p>An Access Package is a named template containing several access rules, lifecycle limits, and an approval route. Use any internal name and assign it to Keycloak users, groups, or roles. Assignments materialize managed grants that cannot be edited directly.</p>
<pre>isolate package create --file support-readonly.yml
isolate package preview "Support Read-Only" --file support-readonly-v2.yml
isolate package apply "Support Read-Only" --file support-readonly-v2.yml --yes
isolate package assign "Support Read-Only" --group Support-L1 --group Support-L2 --ttl 7d --ticket CHG-1042 --yes
isolate package revisions "Support Read-Only"
isolate package rollback "Support Read-Only" --revision 1 --yes</pre>
<p>Preview reports affected subjects and grant create/update/delete operations. Revisions are immutable, making rollback reproducible.</p>"""),
            ("temporary", "Temporary access", """
<p>When no permanent grant exists, a user creates a break-glass request. An administrator receives a notification, reviews the ticket, and approves a TTL. The temporary grant stops matching after <code>expires_at</code>.</p>
<pre>isolate access request --project payments-prod --host 10703 --remote-user dba --sudo-mode none --reason "Incident diagnostics" --ticket INC-2048
isolate access approve --id 42 --ttl 2h --comment "Approved for incident window"</pre>"""),
            ("operations", "Sessions, jobs, and audit", """
<p>History and Session Details expose policy decisions, target host, remote user, JSONL events, and raw terminal transcripts. Replay is generated from raw logs. Structured commands appear only when target shell hooks are installed.</p>
<p>Jobs &amp; Runbooks executes reviewed operations on one host or a fleet. Arbitrary commands remain separately gated by grants, scopes, allowlists, and confirmation.</p>
<pre>isolate announcement add --project payments-prod --severity warning --ttl 2h --text "Deploy window"
isolate user activity demo.alex
isolate export history --format csv --output history.csv</pre>
<p>Announcements appear in <code>s</code> and before <code>g</code>. Inventory, History, Users, and Access Matrix provide CSV/JSON downloads.</p>"""),
            ("lifecycle", "Backup, GitOps, and updates", """
<p>Create a service backup and verify health before a release. GitOps for grants and project sets is opt-in; <code>enforce_git</code> blocks manual policy mutations.</p>
<pre>sudo /opt/auth/scripts/isolate-backup.sh create
git pull --ff-only
sudo bash /opt/auth/scripts/fix-perms.sh
curl -fsS http://127.0.0.1:8080/health</pre>
<p>For a seamless dashboard update, run two instances behind a reverse proxy and remove the old instance after the new health check passes. Do not forcibly restart active SSH wrapper sessions.</p>"""),
        ]
    toc = "".join('<a href="#{}">{}</a>'.format(section_id, html.escape(heading)) for section_id, heading, _ in sections)
    content = "".join('<section class="docs-section" id="{}"><h2>{}</h2>{}</section>'.format(
        section_id, html.escape(heading), content
    ) for section_id, heading, content in sections)
    build_labels = ("Версия", "Ревизия", "Собрано", "Python", "Schema", "Uptime") if locale == "ru" else ("Version", "Revision", "Built", "Python", "Schema", "Uptime")
    values = (
        build.get("version") or "unknown", build.get("revision") or "unknown", build.get("built_at") or "unknown",
        build.get("python") or "unknown", build.get("schema_version") or "n/a", "{}s".format(build.get("uptime_seconds") or 0),
    )
    build_html = "".join('<div><strong>{}</strong>{}</div>'.format(html.escape(str(label)), html.escape(str(value))) for label, value in zip(build_labels, values))
    return '<h1>{}</h1><p class="page-lead">{}</p><div class="docs-layout"><div class="docs-main"><section class="docs-section"><h2>{}</h2><div class="build-grid">{}</div></section>{}</div><aside class="docs-toc"><strong>{}</strong>{}</aside></div>'.format(
        html.escape(title), html.escape(lead), "Сборка" if locale == "ru" else "Build", build_html, content, html.escape(toc_title), toc
    )


def _host_form_values(form, partial=False):
    mapping = {
        "project": "project_name",
        "name": "server_name",
        "ip": "server_ip",
        "port": "server_port",
        "user": "server_user",
        "services": "server_services",
        "note": "server_note",
        "privileged_provider": "privileged_access_provider",
        "privileged_url": "privileged_access_url",
        "privileged_hint": "privileged_access_hint",
        "proxy_id": "proxy_id",
        "maintenance_until": "maintenance_until",
        "maintenance_reason": "maintenance_reason",
    }
    result = {}
    for source, target in mapping.items():
        value = form.get(source)
        if value not in (None, "") or (not partial and source in form):
            result[target] = value
    for source, target in (("vip", "server_vip"), ("nosudo", "server_nosudo"), ("maintenance", "maintenance_enabled")):
        value = _optional_bool(form.get(source))
        if value is not None:
            result[target] = value
    return result


def create_app(config=None):
    from authlib.integrations.base_client import OAuthError
    from authlib.integrations.flask_client import OAuth
    from flask import Flask, Response, abort, g, jsonify, redirect, render_template_string, request, send_file, session, url_for
    from joserfc.errors import JoseError
    from requests.exceptions import RequestException

    config = config or load_config()
    app = Flask(__name__)
    app.secret_key = _secret_key(config)
    app.extensions["isolate_build_info"] = get_build_info(config, _DASHBOARD_STARTED_AT)
    oauth = OAuth(app)

    @app.before_request
    def assign_request_id():
        g.request_id = secrets.token_hex(16)

    @app.after_request
    def attach_request_id(response):
        response.headers["X-Request-ID"] = g.request_id
        return response

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error("Dashboard request failed: request_id=%s method=%s path=%s", g.request_id, request.method, request.path)
        return '<h1>Internal Server Error</h1><p>Request ID: {}</p>'.format(g.request_id), 500

    issuer = (config.get("keycloak", {}).get("issuer") or "").rstrip("/")
    oauth.register(
        name="keycloak",
        client_id=config.get("keycloak", {}).get("client_id"),
        client_secret=config.get("keycloak", {}).get("client_secret"),
        server_metadata_url=issuer + "/.well-known/openid-configuration",
        client_kwargs={
            "scope": " ".join(config.get("keycloak", {}).get("scopes") or ["openid", "profile", "email"]),
            "default_timeout": (
                float(config.get("keycloak", {}).get("http_connect_timeout", 2)),
                float(config.get("keycloak", {}).get("http_read_timeout", 3)),
            ),
        },
    )

    def current_identity():
        identity = session.get("identity")
        if not identity:
            return None
        if identity.get("exp") and int(identity["exp"]) <= int(time.time()):
            session.clear()
            return None
        return identity

    def require_admin():
        identity = current_identity()
        if identity is None:
            return redirect(url_for("login"))
        if not is_dashboard_admin(identity, config):
            abort(403)
        return identity

    def csrf_token():
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    def validate_csrf():
        if request.form.get("csrf_token") != session.get("csrf_token"):
            abort(403)

    def require_mutation_confirmation():
        if config.get("dashboard", {}).get("require_mutation_confirmation", True):
            if request.form.get("confirm") != "true":
                raise ValueError("explicit confirmation is required")

    def require_manual_policy_edit():
        if config.get("policy_as_code", {}).get("enforce_git", False):
            raise ValueError("manual policy editing is disabled because enforced GitOps is active")

    def audit_admin(action, admin, outcome, details=None):
        record = {
            "event": "dashboard_admin_action",
            "action": action,
            "username": admin.get("username"),
            "keycloak_sub": admin.get("keycloak_sub"),
            "outcome": outcome,
            "source": "isolate-dashboard",
        }
        record.update(details or {})
        prepare_and_dispatch(record, config.get("logging", {}))

    def notify_dashboard(redis, event_name, record, admin, extra=None):
        try:
            result = notify_access_event(config, event_name, record, actor=admin, extra=extra)
        except NotificationError as exc:
            set_notification_status(redis, record.get("id"), {"ok": False, "errors": [str(exc)], "sent": []})
            return {"level": "error", "text": "Action completed, but notification failed: {}".format(exc)}
        set_notification_status(redis, record.get("id"), {"ok": not bool(result.get("errors")), "errors": result.get("errors") or [], "sent": result.get("sent") or []})
        if result.get("errors"):
            return {"level": "warning", "text": "Action completed with notification warning: {}".format("; ".join(result["errors"]))}
        return None

    @app.route("/health")
    def health():
        result = run_health_checks(config)
        public_result = {
            "ok": result["ok"],
            "status": result["status"],
            "checks": {name: {"ok": bool(check.get("ok"))} for name, check in result["checks"].items()},
        }
        response = jsonify(public_result)
        response.status_code = 200 if result["ok"] else 503
        return response

    def status_filter_links(current):
        statuses = [("all", None), ("pending", "pending"), ("approved", "approved"), ("denied", "denied")]
        links = []
        for label, value in statuses:
            href = "/access" if value is None else "/access?status={}".format(value)
            text = "<strong>{}</strong>".format(label) if current == value else html.escape(label)
            links.append('<a href="{}">{}</a>'.format(href, text))
        return " ".join(links)

    def access_table(rows, token, access_cfg):
        default_ttl = html.escape(str(access_cfg.get("default_ttl", "2h")))
        header = (
            "<th>id</th><th>status</th><th>user</th><th>project</th><th>host</th><th>ticket</th>"
            "<th>remote_user</th><th>sudo</th><th>reason</th><th>decision</th><th>expires</th><th>grant</th><th>comments</th><th>notify</th><th>actions</th>"
        )
        body = ""
        for row in rows:
            cells = [
                html.escape(str(row.get("id") or "")),
                html.escape(str(row.get("status") or "")),
                html.escape(str(row.get("requester") or "")),
                html.escape(str(row.get("project") or "")),
                html.escape(str(row.get("host") or "")),
                html.escape(str(row.get("ticket") or "")),
                html.escape(str(row.get("remote_user") or "")),
                html.escape(str(row.get("sudo_mode") or "")),
                html.escape(str(row.get("reason") or "")),
                html.escape(str(row.get("decision_reason") or "")),
                html.escape(str(row.get("expires_at") or "")),
                html.escape(str(row.get("grant_id") or "")),
                html.escape("; ".join("{}: {}".format(c.get("username") or "", c.get("text") or "") for c in row.get("comments") or [])),
                html.escape(str((row.get("notification_status") or {}).get("ok", ""))),
            ]
            actions = ""
            if row.get("status") == "pending":
                request_id = html.escape(str(row.get("id") or ""))
                remote_user = html.escape(str(row.get("remote_user") or ""))
                sudo_mode = html.escape(str(row.get("sudo_mode") or ""))
                actions = """
<form class="inline" method="post">
  <input type="hidden" name="csrf_token" value="{token}">
  <input type="hidden" name="id" value="{request_id}">
  <input type="hidden" name="action" value="approve">
  <input name="ttl" value="{default_ttl}" size="5" title="TTL">
  <input name="remote_user" value="{remote_user}" placeholder="remote_user" size="10">
  <input name="sudo_mode" value="{sudo_mode}" placeholder="sudo_mode" size="8">
  <input name="comment" placeholder="comment" size="12">
  <button type="submit">Approve</button>
</form>
<form class="inline" method="post">
  <input type="hidden" name="csrf_token" value="{token}">
  <input type="hidden" name="id" value="{request_id}">
  <input type="hidden" name="action" value="deny">
  <input name="reason" placeholder="reason" size="12">
  <input name="comment" placeholder="comment" size="12">
  <button type="submit">Deny</button>
</form>""".format(
                    token=html.escape(token),
                    request_id=request_id,
                    default_ttl=default_ttl,
                    remote_user=remote_user,
                    sudo_mode=sudo_mode,
                )
            else:
                request_id = html.escape(str(row.get("id") or ""))
                actions = """
<form class="inline" method="post">
  <input type="hidden" name="csrf_token" value="{token}">
  <input type="hidden" name="id" value="{request_id}">
  <input type="hidden" name="action" value="repeat">
  <input name="reason" placeholder="reason" size="14">
  <input name="ticket" placeholder="ticket" size="10">
  <button type="submit">Request again</button>
</form>""".format(token=html.escape(token), request_id=request_id)
            body += "<tr>{}<td>{}</td></tr>".format("".join("<td>{}</td>".format(cell) for cell in cells), actions)
        return "<table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>".format(header, body)

    @app.route("/login")
    def login():
        redirect_uri = config.get("dashboard", {}).get("public_url", "").rstrip("/") + url_for("callback")
        try:
            return oauth.keycloak.authorize_redirect(redirect_uri)
        except RequestException as exc:
            return identity_provider_unavailable(exc)

    def identity_provider_unavailable(error):
        app.logger.warning("OIDC provider unavailable: request_id=%s error_type=%s", g.request_id, type(error).__name__)
        return '<h1>Sign-in temporarily unavailable</h1><p>Please retry sign-in shortly.</p><p>Request ID: {}</p>'.format(g.request_id), 503, {"Retry-After": "10"}

    @app.route("/auth/callback")
    def callback():
        try:
            token = oauth.keycloak.authorize_access_token()
        except RequestException as exc:
            return identity_provider_unavailable(exc)
        except (OAuthError, JoseError) as exc:
            error_code = str(getattr(exc, "error", "") or "unknown")
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", error_code):
                error_code = "unknown"
            app.logger.warning("OIDC sign-in rejected: request_id=%s error_type=%s error_code=%s", g.request_id, type(exc).__name__, error_code)
            abort(401, description="Sign-in could not be verified. Please start a new sign-in.")
        claims = token.get("userinfo") or {}
        if not isinstance(claims, dict) or not claims:
            abort(401, description="Keycloak did not return verified OIDC claims")
        identity = normalize_claims(claims)
        if not is_dashboard_admin(identity, config):
            abort(403)
        session["identity"] = identity
        return redirect(url_for("index"))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    def index():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        active = list_active_sessions(redis)
        pending = list_access_requests(redis, status="pending")
        notices = list_announcements(redis, active_only=True)
        recent = read_history(config["logging"]["base_path"], admin, limit=10, admin_groups=config.get("dashboard", {}).get("admin_groups") or [])
        body = """
<h1>Operations Overview</h1>
<p class="page-lead">Current bastion activity, access requests, and recent SSH connections.</p>
<div class="grid">
<div class="metric"><strong>{}</strong><span class="muted">active sessions</span><br><a class="metric-link" href="/sessions/active">Review sessions</a></div>
<div class="metric"><strong>{}</strong><span class="muted">pending access requests</span><br><a class="metric-link" href="/access?status=pending">Review requests</a></div>
<div class="metric"><strong>{}</strong><span class="muted">recent connections</span><br><a class="metric-link" href="/history">Open history</a></div>
<div class="metric"><strong>{}</strong><span class="muted">active announcements</span><br><a class="metric-link" href="/announcements?active=1">Review notices</a></div>
</div>
""".format(len(active), len(pending), len(recent), len(notices))
        body += '<div class="section-heading"><h2>Recent Activity</h2><a href="/history">View all history</a></div>'
        if recent:
            recent_rows = []
            for item in recent[:5]:
                row = dict(item)
                connection_id = row.get("connection_id") or row.get("session_id")
                if connection_id:
                    row["details"] = '<a href="/session/{}">details</a>'.format(html.escape(str(connection_id)))
                recent_rows.append(row)
            body += _table(recent_rows, [
                ("time", "time"), ("username", "user"), ("project", "project"),
                ("host_id", "host"), ("remote_user", "remote user"), ("result", "result"), ("details", "details"),
            ])
        else:
            body += '<div class="empty-state">No SSH connections have been recorded yet.</div>'
        return _html("Isolate Dashboard", body, config=config)

    @app.route("/jobs", methods=["GET", "POST"])
    def jobs_console():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            try:
                require_mutation_confirmation()
                action = request.form.get("action")
                if action == "queue_runbook":
                    parameters = _parse_json_object(request.form.get("parameters"), "runbook parameters")
                    timeout = request.form.get("timeout") or None
                    result = create_runbook_fleet(
                        redis,
                        config,
                        admin,
                        request.form.get("runbook_id"),
                        _split_values(request.form.get("host_ids")),
                        parameters=parameters,
                        timeout=int(timeout) if timeout else None,
                        confirmed=True,
                    )
                    audit_admin("runbook_fleet_queue", admin, "success", {
                        "fleet_id": result["fleet_id"], "job_count": result["count"],
                    })
                    notice = {"level": "success", "text": "Queued fleet {} with {} job(s).".format(result["fleet_id"], result["count"])}
                elif action == "retry_fleet":
                    fleet_id = str(request.form.get("fleet_id") or "")
                    summary = next((row for row in fleet_progress(list_jobs(redis, limit=10000)) if row["fleet_id"] == fleet_id), None)
                    if summary is None:
                        raise JobError("fleet was not found")
                    retried = [retry_job(redis, config, job_id, admin) for job_id in summary["failed_job_ids"]]
                    if not retried:
                        raise JobError("fleet has no failed hosts to retry")
                    audit_admin("job_fleet_retry", admin, "success", {"fleet_id": fleet_id, "job_count": len(retried)})
                    notice = {"level": "success", "text": "Retried {} failed host(s) in fleet {}.".format(len(retried), fleet_id)}
                else:
                    raise JobError("unknown jobs action")
            except (JobError, ValueError) as exc:
                audit_admin("jobs_action", admin, "denied", {"error": str(exc)})
                notice = {"level": "error", "text": str(exc)}

        all_jobs = list_jobs(redis, limit=10000)
        rows = filter_jobs(
            all_jobs,
            status=request.args.get("status") or None,
            user=request.args.get("user") or None,
            project=request.args.get("project") or None,
            host=request.args.get("host") or None,
            job_type=request.args.get("type") or None,
        )[: int(config.get("dashboard", {}).get("jobs_max_results") or 250)]
        status_counts = {name: sum(1 for row in all_jobs if row.get("status") == name) for name in ("queued", "running", "completed", "failed")}
        body = """<h1>Jobs &amp; Runbooks</h1>
<p class="page-lead">Queue policy-authorized diagnostics, monitor execution, inspect output, and retry failed hosts.</p>
<div class="summary-list">
<div class="summary-item"><strong>{queued}</strong><span class="muted">queued</span></div>
<div class="summary-item"><strong>{running}</strong><span class="muted">running</span></div>
<div class="summary-item"><strong>{completed}</strong><span class="muted">completed</span></div>
<div class="summary-item"><strong>{failed}</strong><span class="muted">failed</span></div>
</div>""".format(**status_counts)

        runbook_cfg = config.get("runbooks", {}) or {}
        available = []
        if runbook_cfg.get("enabled", False):
            for item in list_runbooks(config):
                class_cfg = runbook_cfg.get(item.get("class"), {}) or {}
                if item.get("class") == "operational" and not class_cfg.get("enabled", False):
                    continue
                if set(admin.get("groups") or []) & set(class_cfg.get("allowed_groups") or []):
                    available.append(item)
        if available:
            options = "".join('<option value="{}">{}: {}</option>'.format(
                html.escape(str(item["id"])), html.escape(str(item["id"])), html.escape(str(item.get("title") or item["id"])),
            ) for item in available)
            body += """<div class="panel"><h2>Queue runbook</h2>
<form method="post"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="queue_runbook">
<p><label>Runbook <select name="runbook_id" required>{options}</select></label>
<label>Host IDs <input name="host_ids" placeholder="10001, 10002" required></label>
<label>Timeout <input name="timeout" type="number" min="1" placeholder="default"></label></p>
<p><label>Parameters JSON <textarea name="parameters" rows="3" cols="72">{{}}</textarea></label></p>
<p><label><input type="checkbox" name="confirm" value="true" required> confirm execution on all selected hosts</label> <button type="submit">Queue runbook</button></p>
</form></div>""".format(token=html.escape(csrf_token()), options=options)
        else:
            body += '<div class="notice warning">No runbook class is enabled for your verified Keycloak groups.</div>'

        fleets = fleet_progress(all_jobs)
        if fleets:
            fleet_rows = []
            for fleet in fleets:
                row = dict(fleet)
                row["progress"] = '<div class="progress" title="{percent}%"><span style="width:{percent}%"></span></div><small>{finished}/{total} finished</small>'.format(
                    percent=int(fleet["progress_percent"]), finished=fleet["finished"], total=fleet["total"]
                )
                row["counts"] = "ok={} failed={} running={} queued={}".format(
                    fleet["completed"], fleet["failed"] + fleet["timed_out"], fleet["running"], fleet["queued"]
                )
                if fleet["failed_job_ids"]:
                    row["actions"] = """<form class="inline" method="post"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="retry_fleet"><input type="hidden" name="fleet_id" value="{fleet_id}"><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button class="button-secondary">Retry failed</button></form>""".format(
                        token=html.escape(csrf_token()), fleet_id=html.escape(fleet["fleet_id"])
                    )
                fleet_rows.append(row)
            body += "<h2>Fleet rollouts</h2>" + _table(fleet_rows, [
                ("fleet_id", "fleet"), ("runbook_id", "runbook"), ("username", "user"),
                ("status", "status"), ("progress", "progress"), ("counts", "results"), ("actions", "actions"),
            ])

        body += """<h2>Job history</h2><form class="inline" method="get">
<select name="status"><option value="">all statuses</option>{status_options}</select>
<select name="type"><option value="">all types</option><option value="runbook">runbook</option><option value="remote-command">remote command</option></select>
<input name="user" value="{user}" placeholder="user"><input name="project" value="{project}" placeholder="project"><input name="host" value="{host}" placeholder="host id"><button>Filter</button></form>""".format(
            status_options="".join('<option value="{0}">{0}</option>'.format(value) for value in ("queued", "running", "completed", "failed", "cancelled", "timed_out")),
            user=html.escape(request.args.get("user", "")), project=html.escape(request.args.get("project", "")), host=html.escape(request.args.get("host", "")),
        )
        job_rows = []
        for job in rows:
            row = dict(job)
            row["created"] = _format_ts(job.get("created_at"))
            row["operation"] = job.get("runbook_id") or str(job.get("command") or "")[:80]
            row["details"] = '<a href="/job/{}">open</a>'.format(html.escape(str(job.get("id"))))
            job_rows.append(row)
        body += _table(job_rows, [
            ("id", "id"), ("created", "created"), ("status", "status"), ("type", "type"),
            ("operation", "operation"), ("username", "user"), ("project", "project"),
            ("host_id", "host"), ("exit_code", "exit"), ("details", "details"),
        ]) if job_rows else '<div class="empty-state">No jobs match the selected filters.</div>'
        return _html("Jobs & Runbooks", body, config=config, notice=notice)

    @app.route("/job/<job_id>")
    def job_details(job_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        job = get_job(redis, job_id)
        if job is None:
            abort(404)
        jobs_path = (config.get("command_execution", {}) or {}).get("jobs_path", "/opt/auth/jobs")
        output = read_job_output(
            job,
            max_bytes=int((config.get("command_execution", {}) or {}).get("max_return_bytes", 262144)),
            jobs_path=jobs_path,
            job_id=job_id,
        )
        body = """<h1>Job {job_id}</h1><p class="page-lead">Execution details and captured output.</p>
<div class="panel"><dl class="key-value">
<dt>Status</dt><dd><span class="badge badge-{status}">{status}</span></dd>
<dt>Type</dt><dd>{type}</dd><dt>Runbook</dt><dd>{runbook}</dd><dt>User</dt><dd>{user}</dd>
<dt>Project / host</dt><dd>{project} / <a href="/history?host={host}">{host}</a></dd>
<dt>Remote identity</dt><dd>{remote_user} ({sudo_mode})</dd><dt>Created</dt><dd>{created}</dd>
<dt>Started</dt><dd>{started}</dd><dt>Finished</dt><dd>{finished}</dd><dt>Exit code</dt><dd>{exit_code}</dd>
<dt>Error</dt><dd>{error}</dd><dt>Fleet / attempt</dt><dd>{fleet} / {attempt}</dd>
</dl></div>""".format(
            job_id=html.escape(str(job_id)), status=html.escape(str(job.get("status") or "unknown")),
            type=html.escape(str(job.get("type") or "")), runbook=html.escape(str(job.get("runbook_id") or "")),
            user=html.escape(str(job.get("username") or "")), project=html.escape(str(job.get("project") or "")),
            host=html.escape(str(job.get("host_id") or "")), remote_user=html.escape(str(job.get("remote_user") or "")),
            sudo_mode=html.escape(str(job.get("sudo_mode") or "")), created=html.escape(_format_ts(job.get("created_at"))),
            started=html.escape(_format_ts(job.get("started_at"))), finished=html.escape(_format_ts(job.get("finished_at"))),
            exit_code=html.escape(str(job.get("exit_code") if job.get("exit_code") is not None else "")),
            error=html.escape(str(job.get("error") or "")), fleet=html.escape(str(job.get("fleet_id") or "single")),
            attempt=html.escape(str(job.get("attempt") or 1)),
        )
        if job.get("status") in ("queued", "running"):
            body += """<form class="inline" method="post" action="/job/{}/cancel"><input type="hidden" name="csrf_token" value="{}"><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button class="button-danger">Cancel job</button></form>""".format(html.escape(str(job_id)), html.escape(csrf_token()))
        if job.get("status") in ("failed", "timed_out"):
            body += """<form class="inline" method="post" action="/job/{}/retry"><input type="hidden" name="csrf_token" value="{}"><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Retry job</button></form>""".format(html.escape(str(job_id)), html.escape(csrf_token()))
        body += "<h2>Output</h2><pre>{}</pre>".format(html.escape(output or "No output was captured."))
        body += "<h2>Authorization snapshot</h2><pre>{}</pre>".format(html.escape(json.dumps({
            "groups": job.get("groups") or [], "roles": job.get("roles") or [], "grant_id": job.get("grant_id"),
            "policy_action": job.get("policy_action") or "command", "command_sha256": job.get("command_sha256"),
        }, indent=2, sort_keys=True)))
        return _html("Job {}".format(job_id), body, config=config)

    @app.route("/job/<job_id>/cancel", methods=["POST"])
    def job_cancel(job_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        validate_csrf()
        try:
            require_mutation_confirmation()
            record = request_job_cancel(redis_client(config), job_id, admin)
            if record is None:
                abort(404)
            audit_admin("job_cancel", admin, "success", {"job_id": job_id})
        except (JobError, ValueError) as exc:
            audit_admin("job_cancel", admin, "denied", {"job_id": job_id, "error": str(exc)})
            abort(409, description=str(exc))
        return redirect(url_for("job_details", job_id=job_id))

    @app.route("/job/<job_id>/retry", methods=["POST"])
    def job_retry(job_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        validate_csrf()
        try:
            require_mutation_confirmation()
            record = retry_job(redis_client(config), config, job_id, admin)
            audit_admin("job_retry", admin, "success", {"job_id": record["id"], "retry_of": job_id})
        except (JobError, ValueError) as exc:
            audit_admin("job_retry", admin, "denied", {"job_id": job_id, "error": str(exc)})
            abort(409, description=str(exc))
        return redirect(url_for("job_details", job_id=record["id"]))

    @app.route("/alerts", methods=["GET", "POST"])
    def alert_center():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            try:
                require_mutation_confirmation()
                alert_id = request.form.get("alert_id")
                known = {row["id"] for row in collect_alerts(redis, config)}
                if alert_id not in known:
                    raise DashboardDataError("alert was not found")
                state = update_alert_state(
                    redis, alert_id, admin, request.form.get("action"), comment=request.form.get("comment") or None
                )
                audit_admin("alert_{}".format(request.form.get("action")), admin, "success", {
                    "alert_id": alert_id, "status": state.get("status"),
                })
                notice = {"level": "success", "text": "Alert state updated."}
            except (DashboardDataError, ValueError) as exc:
                audit_admin("alert_action", admin, "denied", {"error": str(exc)})
                notice = {"level": "error", "text": str(exc)}
        rows = collect_alerts(
            redis,
            config,
            status=request.args.get("status") or None,
            kind=request.args.get("kind") or None,
            user=request.args.get("user") or None,
            project=request.args.get("project") or None,
        )
        all_rows = collect_alerts(redis, config)
        counts = {name: sum(1 for row in all_rows if row.get("status") == name) for name in ("open", "acknowledged", "resolved")}
        body = """<h1>Alert Center</h1><p class="page-lead">Session risk, failed jobs, and notification delivery failures in one operational queue.</p>
<div class="summary-list"><div class="summary-item"><strong>{open}</strong><span class="muted">open</span></div><div class="summary-item"><strong>{acknowledged}</strong><span class="muted">acknowledged</span></div><div class="summary-item"><strong>{resolved}</strong><span class="muted">resolved</span></div><div class="summary-item"><strong>{total}</strong><span class="muted">total</span></div></div>
<form class="inline" method="get"><select name="status"><option value="">all statuses</option><option>open</option><option>acknowledged</option><option>resolved</option></select><select name="kind"><option value="">all kinds</option><option value="long_session">long session</option><option value="vip_session">VIP</option><option value="privileged_session">privileged</option><option value="unusual_source_ip">unusual source</option><option value="failed_job">failed job</option><option value="notification_delivery_failed">notification failure</option></select><input name="user" value="{user}" placeholder="user"><input name="project" value="{project}" placeholder="project"><button>Filter</button></form>""".format(
            total=len(all_rows), user=html.escape(request.args.get("user", "")), project=html.escape(request.args.get("project", "")), **counts
        )
        alert_rows = []
        for alert in rows:
            row = dict(alert)
            row["created"] = _format_ts(alert.get("created_at"))
            row["severity_badge"] = '<span class="badge severity-{}">{}</span>'.format(
                html.escape(str(alert.get("severity") or "medium")), html.escape(str(alert.get("severity") or "medium"))
            )
            row["message"] = alert.get("details")
            if alert.get("source_type") == "session":
                row["source_link"] = '<a href="/session/{}">session</a>'.format(html.escape(str(alert.get("source_id"))))
            elif alert.get("source_type") == "job":
                row["source_link"] = '<a href="/job/{}">job {}</a>'.format(html.escape(str(alert.get("source_id"))), html.escape(str(alert.get("source_id"))))
            else:
                row["source_link"] = '<a href="/access?id={}">request {}</a>'.format(html.escape(str(alert.get("source_id"))), html.escape(str(alert.get("source_id"))))
            buttons = []
            if alert.get("status") == "open":
                buttons.append('<button name="action" value="acknowledge" class="button-secondary">Acknowledge</button>')
            if alert.get("status") != "resolved":
                buttons.append('<button name="action" value="resolve">Resolve</button>')
            else:
                buttons.append('<button name="action" value="reopen" class="button-secondary">Reopen</button>')
            buttons.append('<button name="action" value="comment" class="button-secondary">Comment</button>')
            row["control"] = '<form class="inline" method="post"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="alert_id" value="{}"><input name="comment" placeholder="optional comment">{}<label><input type="checkbox" name="confirm" value="true" required> confirm</label></form>'.format(
                html.escape(csrf_token()), html.escape(alert["id"]), "".join(buttons)
            )
            row["comments_count"] = len(alert.get("comments") or [])
            alert_rows.append(row)
        body += _table(alert_rows, [
            ("created", "created"), ("severity_badge", "severity"), ("status", "status"), ("title", "alert"),
            ("username", "user"), ("project", "project"), ("host_id", "host"), ("message", "details"),
            ("source_link", "source"), ("comments_count", "comments"), ("control", "actions"),
        ]) if alert_rows else '<div class="empty-state">No alerts match the selected filters.</div>'
        return _html("Alert Center", body, config=config, notice=notice)

    @app.route("/policy/matrix", methods=["GET", "POST"])
    def access_matrix():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        grants = load_grants(redis)
        project_sets = load_project_sets(redis)
        hosts = list_hosts(redis)
        defaults = {**config.get("policy", {}), **config.get("ssh", {})}
        matrix = build_access_matrix(grants, project_sets, hosts, defaults=defaults)
        preview = None
        notice = None
        if request.method == "POST":
            validate_csrf()
            try:
                selector_type = request.form.get("selector_type")
                if selector_type not in ("project", "project_set", "project_glob"):
                    raise DashboardDataError("invalid selector type")
                candidate = {
                    "subject": request.form.get("subject"), "name": request.form.get("name"),
                    "replace_grant_id": request.form.get("replace_grant_id") or None,
                    selector_type: request.form.get("selector_value"),
                    "host": request.form.get("host") or None,
                    "remote_user": request.form.get("remote_user") or None,
                    "sudo_mode": request.form.get("sudo_mode") or "none",
                    "allowed_actions": _split_values(request.form.get("allowed_actions") or "ssh"),
                }
                preview = preview_grant_change(grants, project_sets, hosts, candidate, defaults=defaults)
            except (DashboardDataError, ValueError) as exc:
                notice = {"level": "error", "text": str(exc)}
        subject_query = (request.args.get("subject") or "").lower()
        selected_project = request.args.get("project") or ""
        rows = [row for row in matrix["rows"] if not subject_query or subject_query in "{}:{}".format(row["subject"], row["name"]).lower()]
        projects = [project for project in matrix["projects"] if not selected_project or project == selected_project]
        header = '<th scope="col">subject</th>' + "".join('<th scope="col">{}</th>'.format(html.escape(project)) for project in projects)
        matrix_rows = ""
        for row in rows:
            cells = ['<td><strong>{}:{}</strong></td>'.format(html.escape(row["subject"]), html.escape(row["name"]))]
            for project in projects:
                cell = row["cells"][project]
                detail = "{}/{} hosts".format(cell["allowed_hosts"], cell["total_hosts"])
                if cell["remote_users"]:
                    detail += "<br>{}".format(html.escape(", ".join(cell["remote_users"])))
                if cell["actions"]:
                    detail += "<br><small>{}</small>".format(html.escape(", ".join(cell["actions"])))
                cells.append('<td class="matrix-cell matrix-{}"><strong>{}</strong>{}</td>'.format(
                    html.escape(cell["state"]), html.escape(cell["state"]), detail
                ))
            matrix_rows += "<tr>{}</tr>".format("".join(cells))
        body = """<h1>Access Matrix</h1><p class="page-lead">Effective group, role, and user access across projects, calculated with the production policy resolver.</p>
<p><a href="/export/access-matrix?format=csv">Download CSV</a> &middot; <a href="/export/access-matrix?format=json">Download JSON</a></p>
<form class="inline" method="get"><input name="subject" value="{subject_query}" placeholder="group or user"><select name="project"><option value="">all projects</option>{project_options}</select><button>Filter</button></form>
<div class="matrix-wrap"><table class="matrix"><thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table></div>""".format(
            subject_query=html.escape(request.args.get("subject", "")),
            project_options="".join('<option value="{}">{}</option>'.format(html.escape(project), html.escape(project)) for project in matrix["projects"]),
            header=header, rows=matrix_rows,
        )
        finding_type = request.args.get("finding") or ""
        findings = [item for item in matrix["findings"] if not finding_type or item.get("type") == finding_type]
        for finding in findings:
            finding["finding_summary"] = finding.get("details")
        body += '<h2>Policy findings</h2><form class="inline" method="get"><select name="finding"><option value="">all findings</option><option>conflict</option><option>redundant</option><option>shadowed</option></select><button>Filter</button></form>'
        body += _table(findings, [
            ("type", "type"), ("subject", "subject"), ("project", "project"), ("host_id", "host"),
            ("grant_ids", "grants"), ("finding_summary", "details"),
        ]) if findings else '<div class="empty-state">No conflicting, redundant, or shadowed grants were found for current inventory.</div>'
        body += """<div class="panel"><h2>Preview grant blast radius</h2><p class="muted">This form never applies policy. It compares the current resolver result with a hypothetical additional grant.</p>
<form method="post"><input type="hidden" name="csrf_token" value="{token}"><p><select name="subject"><option>group</option><option>user</option><option>role</option></select><input name="name" placeholder="subject name" required><select name="selector_type"><option>project</option><option>project_set</option><option>project_glob</option></select><input name="selector_value" placeholder="selector" required><input name="host" placeholder="optional host"></p><p><input name="replace_grant_id" placeholder="optional grant id to replace"><input name="remote_user" placeholder="remote user" required><select name="sudo_mode"><option>none</option><option>sudo-i</option></select><input name="allowed_actions" value="ssh" placeholder="ssh,runbook"><button>Preview</button></p></form></div>""".format(token=html.escape(csrf_token()))
        if preview is not None:
            body += "<h2>Blast radius preview</h2><p><strong>Gained:</strong> {} &nbsp; <strong>Lost:</strong> {} &nbsp; <strong>Changed:</strong> {}</p>".format(
                preview["counts"]["gained"], preview["counts"]["lost"], preview["counts"]["changed"]
            )
            impacts = []
            for impact in preview["impacts"]:
                row = dict(impact)
                row["before_summary"] = json.dumps(impact["before"], sort_keys=True)
                row["after_summary"] = json.dumps(impact["after"], sort_keys=True)
                impacts.append(row)
            body += _table(impacts, [
                ("change", "change"), ("project", "project"), ("host_id", "host"),
                ("server_name", "server"), ("before_summary", "before"), ("after_summary", "after"),
            ]) if impacts else '<div class="empty-state">The hypothetical grant does not change effective access.</div>'
        return _html("Access Matrix", body, config=config, notice=notice)

    @app.route("/sessions/active")
    def active_sessions():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        rows = list_active_sessions(redis)
        token = csrf_token()
        termination_enabled = config.get("session_control", {}).get("terminate_enabled", False)
        for row in rows:
            if not row.get("server_name") and row.get("host_id"):
                host_record = get_host(redis, row.get("host_id"))
                if host_record is not None:
                    row["server_name"] = host_record.get("server_name")
            row["started"] = _format_ts(row.get("started_at"))
            connection_id = html.escape(str(row.get("connection_id") or ""))
            username = str(row.get("username") or "")
            row["user_link"] = '<a href="/user/{}">{}</a>'.format(urllib.parse.quote(username, safe=""), html.escape(username))
            row["live"] = '<a href="/session/{}/live">live</a>'.format(connection_id)
            if termination_enabled:
                row["control"] = """
<form class="inline" method="post" action="/sessions/{connection_id}/terminate">
  <input type="hidden" name="csrf_token" value="{token}">
  <input type="hidden" name="confirm" value="true">
  <input name="reason" placeholder="reason" size="12">
  <button type="submit">Terminate</button>
</form>""".format(connection_id=connection_id, token=html.escape(token))
        return _html("Active Sessions", "<h1>Active Sessions</h1>" + _table(rows, [
            ("started", "started"), ("duration_seconds", "duration_s"), ("user_link", "user"),
            ("project", "project"), ("host_id", "host"), ("server_name", "host name"), ("target_host", "target"),
            ("remote_user", "remote_user"), ("connection_id", "connection_id"), ("live", "view"), ("control", "control")
        ]), config=config)

    @app.route("/sessions/<connection_id>/terminate", methods=["POST"])
    def terminate_session(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        validate_csrf()
        if not config.get("session_control", {}).get("terminate_enabled", False):
            abort(403)
        try:
            require_mutation_confirmation()
            record = request_session_termination(
                redis_client(config), connection_id, admin, reason=request.form.get("reason") or None
            )
            audit_admin("session_terminate", admin, "requested", {"connection_id": connection_id})
        except (SessionControlError, ValueError) as exc:
            audit_admin("session_terminate", admin, "denied", {"connection_id": connection_id})
            return _html("Session Control", "<h1>Session Control</h1>", config=config, notice={"level": "error", "text": str(exc)}), 409
        return redirect(url_for("active_sessions"))

    @app.route("/history")
    def history():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        rows = read_history(
            config["logging"]["base_path"],
            admin,
            query=request.args.get("q"),
            user=request.args.get("user"),
            project=request.args.get("project"),
            host=request.args.get("host"),
            limit=int(request.args.get("limit", 50)),
            admin_groups=config.get("dashboard", {}).get("admin_groups") or [],
        )
        redis = redis_client(config)
        for row in rows:
            connection_id = row.get("connection_id") or row.get("session_id")
            username = str(row.get("username") or "")
            if not row.get("server_name") and row.get("host_id"):
                host_record = get_host(redis, row.get("host_id"))
                if host_record is not None:
                    row["server_name"] = host_record.get("server_name")
            row["user_link"] = '<a href="/user/{}">{}</a>'.format(urllib.parse.quote(username, safe=""), html.escape(username))
            if connection_id:
                row["details"] = '<a href="/session/{}">details</a>'.format(html.escape(str(connection_id)))
            if row.get("raw_log_path"):
                row["raw"] = '<a href="/raw/{}/{}">raw</a>'.format(
                    urllib.parse.quote(str(row.get("username") or ""), safe=""),
                    urllib.parse.quote(str(row.get("connection_id") or row.get("session_id") or ""), safe=""),
                )
        export_links = '<p><a href="/export/history?format=csv">Download CSV</a> &middot; <a href="/export/history?format=json">Download JSON</a></p>'
        return _html("History", "<h1>History</h1>" + export_links + _table(rows, [
            ("time", "time"), ("user_link", "user"), ("project", "project"), ("host_id", "host"),
            ("server_name", "host name"), ("target", "target"), ("remote_user", "remote_user"),
            ("result", "result"), ("details", "details"), ("raw", "raw")
        ]), config=config)

    @app.route("/export/<kind>")
    def export_data(kind):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        output_format = request.args.get("format", "csv")
        if kind == "inventory":
            rows = list_hosts(redis, project=request.args.get("project"), query=request.args.get("q"))
        elif kind == "grants":
            rows = list_grant_records(redis, project=request.args.get("project"))
        elif kind == "users":
            rows = list_user_profiles(config["logging"]["base_path"])
        elif kind == "history":
            rows = read_history(
                config["logging"]["base_path"], admin, query=request.args.get("q"), user=request.args.get("user"),
                project=request.args.get("project"), host=request.args.get("host"), limit=min(int(request.args.get("limit", 100)), 1000),
                admin_groups=config.get("dashboard", {}).get("admin_groups") or [],
            )
        elif kind == "access-matrix":
            matrix = build_access_matrix(
                load_grants(redis), load_project_sets(redis), list_hosts(redis),
                defaults={**config.get("policy", {}), **config.get("ssh", {})},
            )
            rows = flatten_access_matrix(matrix)
        else:
            abort(404)
        try:
            content, mimetype = render_export(rows, output_format)
        except ExportError:
            abort(400)
        response = Response(content, mimetype=mimetype)
        response.headers["Content-Disposition"] = "attachment; filename=isolate-{}.{}".format(kind, output_format)
        return response

    @app.route("/access", methods=["GET", "POST"])
    def access():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action")
            request_id = request.form.get("id")
            try:
                if action == "approve":
                    ttl = parse_duration(request.form.get("ttl"), default=config.get("access", {}).get("default_ttl", "2h"))
                    max_ttl = parse_duration(config.get("access", {}).get("max_ttl", "24h"))
                    remote_user = request.form.get("remote_user") or None
                    sudo_mode = request.form.get("sudo_mode") or None
                    record, grant = approve_access_request(
                        redis,
                        request_id,
                        admin,
                        ttl,
                        remote_user=remote_user,
                        sudo_mode=sudo_mode,
                        max_ttl=max_ttl,
                        comment=request.form.get("comment") or None,
                    )
                    notice = notify_dashboard(redis, "access_request_approved", record, admin, extra={"grant": grant})
                    notice = notice or {"level": "info", "text": "Access request approved"}
                elif action == "deny":
                    record = deny_access_request(redis, request_id, admin, reason=request.form.get("reason"), comment=request.form.get("comment") or None)
                    notice = notify_dashboard(redis, "access_request_denied", record, admin)
                    notice = notice or {"level": "info", "text": "Access request denied"}
                elif action == "repeat":
                    record = repeat_access_request(redis, request_id, admin, reason=request.form.get("reason") or None, ticket=request.form.get("ticket") or None, config=config)
                    notice = notify_dashboard(redis, "access_request_created", record, admin)
                    notice = notice or {"level": "info", "text": "Access request repeated"}
            except Exception as exc:
                notice = {"level": "error", "text": str(exc)}
        status = request.args.get("status")
        if status == "all":
            status = None
        rows = list_access_requests(
            redis,
            status=status,
            user=request.args.get("user") or None,
            project=request.args.get("project") or None,
            ticket=request.args.get("ticket") or None,
        )
        body = """
<h1>Access Requests</h1>
<form method="get">
  <input name="user" value="{user}" placeholder="user">
  <input name="project" value="{project}" placeholder="project">
  <input name="ticket" value="{ticket}" placeholder="ticket">
  <button type="submit">Filter</button>
</form>
<p>{links}</p>{table}
""".format(
            user=html.escape(request.args.get("user") or ""),
            project=html.escape(request.args.get("project") or ""),
            ticket=html.escape(request.args.get("ticket") or ""),
            links=status_filter_links(status),
            table=access_table(rows, csrf_token(), config.get("access", {})),
        )
        return _html("Access Requests", body, config=config, notice=notice)

    @app.route("/inventory", methods=["GET", "POST"])
    def inventory():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action")
            try:
                require_mutation_confirmation()
                if action == "add":
                    host = create_host(redis, _host_form_values(request.form), updated_by=admin.get("username"))
                    notice = {"level": "info", "text": "Host {} added".format(host.get("server_id"))}
                    audit_admin("host_add", admin, "applied", {"host_id": host.get("server_id")})
                elif action == "bulk_update":
                    host_ids = _split_values(request.form.get("host_ids"))
                    if not host_ids or len(host_ids) > 200:
                        raise ValueError("between 1 and 200 host ids are required")
                    updates = _host_form_values(request.form, partial=True)
                    if not updates:
                        raise ValueError("at least one bulk update field is required")
                    bulk_update_hosts(redis, host_ids, updates, updated_by=admin.get("username"))
                    changed = [str(host_id) for host_id in host_ids]
                    notice = {"level": "info", "text": "Updated hosts: {}".format(", ".join(changed))}
                    audit_admin("host_bulk_update", admin, "applied", {"host_ids": changed, "count": len(changed)})
                elif action == "connectivity_check":
                    host = get_host(redis, request.form.get("host_id"))
                    if host is None:
                        raise ValueError("host not found")
                    result = check_host(host, config, timeout=config.get("connectivity", {}).get("default_timeout", 3))
                    save_check(redis, result, ttl=config.get("connectivity", {}).get("result_ttl", 3600))
                    notice = {"level": "info" if result.get("ok") else "warning", "text": "Host {}: {}".format(host.get("server_id"), "reachable" if result.get("ok") else result.get("error"))}
                    audit_admin("host_connectivity_check", admin, "completed", {"host_id": host.get("server_id"), "ok": result.get("ok")})
                else:
                    raise ValueError("unknown inventory action")
            except (ConnectivityError, HostValidationError, ValueError) as exc:
                audit_admin("inventory_mutation", admin, "denied", {"action": action})
                notice = {"level": "error", "text": str(exc)}
        project = request.args.get("project") or None
        query = request.args.get("q") or None
        rows = list_hosts(redis, project=project, query=query)
        for row in rows:
            row["project_link"] = '<a href="/history?project={}">{}</a>'.format(
                html.escape(str(row.get("project_name") or "")),
                html.escape(str(row.get("project_name") or "")),
            )
            row["history"] = '<a href="/history?host={}">history</a>'.format(html.escape(str(row.get("server_id") or "")))
            row["details"] = '<a href="/inventory/{}/edit">edit</a>'.format(html.escape(str(row.get("server_id") or "")))
            last_check = get_last_check(redis, row.get("server_id"))
            row["connectivity"] = "unknown" if not last_check else ("reachable" if last_check.get("ok") else "failed")
            row["control"] = '<form method="post" class="inline"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="action" value="connectivity_check"><input type="hidden" name="host_id" value="{}"><input type="hidden" name="confirm" value="true"><button type="submit">Check</button></form>'.format(html.escape(csrf_token()), html.escape(str(row.get("server_id") or "")))
        body = """
<h1>Inventory</h1>
<p><a href="/export/inventory?format=csv">Download CSV</a> &middot; <a href="/export/inventory?format=json">Download JSON</a></p>
<form method="get">
  <input name="project" value="{project}" placeholder="project">
  <input name="q" value="{query}" placeholder="search">
  <button type="submit">Search</button>
</form>
<h2>Add host</h2>
<form method="post" class="inline">
  <input type="hidden" name="csrf_token" value="{csrf}"><input type="hidden" name="action" value="add">
  <input name="project" placeholder="project" required><input name="name" placeholder="name" required>
  <input name="ip" placeholder="IP" required><input name="port" value="22" size="5">
  <input name="user" placeholder="remote user" required><input name="services" placeholder="services">
  <select name="vip"><option value="false">standard</option><option value="true">VIP</option></select>
  <label><input type="checkbox" name="confirm" value="true" required> confirm</label><button type="submit">Add</button>
</form>
<h2>Bulk update</h2>
<form method="post" class="inline">
  <input type="hidden" name="csrf_token" value="{csrf}"><input type="hidden" name="action" value="bulk_update">
  <input name="host_ids" placeholder="10001,10002" required><input name="project" placeholder="new project">
  <input name="user" placeholder="new remote user"><input name="services" placeholder="new services">
  <select name="vip"><option value="">keep VIP</option><option value="true">VIP</option><option value="false">not VIP</option></select>
  <select name="maintenance"><option value="">keep maintenance</option><option value="true">maintenance</option><option value="false">available</option></select>
  <label><input type="checkbox" name="confirm" value="true" required> confirm</label><button type="submit">Apply</button>
</form>
""".format(
            project=html.escape(project or ""),
            query=html.escape(query or ""),
            csrf=html.escape(csrf_token()),
        )
        body += _table(rows, [
            ("project_link", "project"), ("server_id", "id"), ("server_ip", "ip"), ("server_name", "name"),
            ("server_vip_marker", "vip"), ("server_user", "user"), ("server_services_display", "services"),
            ("maintenance_marker", "state"), ("maintenance_reason", "maintenance reason"),
            ("server_note", "note"), ("privileged_access_provider", "privileged"), ("privileged_access_hint", "hint"),
            ("connectivity", "connectivity"), ("control", "check"), ("history", "history"), ("details", "edit")
        ])
        return _html("Inventory", body, config=config, notice=notice)

    @app.route("/inventory/<server_id>/edit", methods=["GET", "POST"])
    def inventory_edit(server_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            try:
                require_mutation_confirmation()
                host = update_host(
                    redis,
                    server_id,
                    _host_form_values(request.form),
                    updated_by=admin.get("username"),
                    expected_revision=request.form.get("revision") or None,
                )
                if host is None:
                    abort(404)
                audit_admin("host_update", admin, "applied", {"host_id": server_id})
                notice = {"level": "info", "text": "Host updated"}
            except (HostValidationError, ValueError) as exc:
                audit_admin("host_update", admin, "denied", {"host_id": server_id})
                notice = {"level": "error", "text": str(exc)}
        host = get_host(redis, server_id)
        if host is None:
            abort(404)
        body = """
<h1>Edit Host {server_id}</h1>
<form method="post">
<input type="hidden" name="csrf_token" value="{csrf}">
<input type="hidden" name="revision" value="{revision}">
<p>Project <input name="project" value="{project}" required> Name <input name="name" value="{name}" required></p>
<p>IP <input name="ip" value="{ip}" required> Port <input name="port" value="{port}" required> User <input name="user" value="{user}" required></p>
<p>Services <input name="services" value="{services}" size="60"></p>
<p>Note <input name="note" value="{note}" size="80"></p>
<p>VIP <select name="vip"><option value="false">false</option><option value="true" {vip_selected}>true</option></select>
No sudo <select name="nosudo"><option value="false">false</option><option value="true" {nosudo_selected}>true</option></select></p>
<p>Maintenance <select name="maintenance"><option value="false">false</option><option value="true" {maintenance_selected}>true</option></select>
Until <input name="maintenance_until" value="{maintenance_until}"> Reason <input name="maintenance_reason" value="{maintenance_reason}" size="60"></p>
<p>Provider <input name="privileged_provider" value="{provider}"> URL <input name="privileged_url" value="{provider_url}" size="45"></p>
<p>Privileged hint <input name="privileged_hint" value="{provider_hint}" size="80"> Proxy ID <input name="proxy_id" value="{proxy_id}"></p>
<label><input type="checkbox" name="confirm" value="true" required> confirm update</label>
<button type="submit">Save</button>
</form>
""".format(
            server_id=html.escape(str(server_id)), csrf=html.escape(csrf_token()), revision=html.escape(str(host.get("_revision") or "")),
            project=html.escape(str(host.get("project_name") or "")), name=html.escape(str(host.get("server_name") or "")),
            ip=html.escape(str(host.get("server_ip") or "")), port=html.escape(str(host.get("server_port") or 22)),
            user=html.escape(str(host.get("server_user") or "")), services=html.escape(str(host.get("server_services") or "")),
            note=html.escape(str(host.get("server_note") or "")), vip_selected="selected" if host.get("server_vip") else "",
            nosudo_selected="selected" if host.get("server_nosudo") else "", provider=html.escape(str(host.get("privileged_access_provider") or "")),
            provider_url=html.escape(str(host.get("privileged_access_url") or "")), provider_hint=html.escape(str(host.get("privileged_access_hint") or "")),
            proxy_id=html.escape(str(host.get("proxy_id") or "")),
            maintenance_selected="selected" if host.get("maintenance_enabled") else "",
            maintenance_until=html.escape(str(host.get("maintenance_until") or "")),
            maintenance_reason=html.escape(str(host.get("maintenance_reason") or "")),
        )
        return _html("Edit Host", body, config=config, notice=notice)

    @app.route("/announcements", methods=["GET", "POST"])
    def announcements():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action")
            try:
                require_mutation_confirmation()
                if action == "add":
                    active_count = len(list_announcements(redis, active_only=True))
                    maximum = int(config.get("announcements", {}).get("max_active", 100))
                    if active_count >= maximum:
                        raise AnnouncementError("active announcement limit reached")
                    ttl = parse_duration(request.form.get("ttl")) if request.form.get("ttl") else None
                    record = create_announcement(
                        redis, request.form.get("text"), admin.get("username"),
                        project=request.form.get("project") or None, host=request.form.get("host") or None,
                        severity=request.form.get("severity") or "info",
                        expires_at=int(time.time()) + ttl if ttl else None,
                    )
                    audit_admin("announcement_add", admin, "applied", {"announcement_id": record.get("id")})
                    notice = {"level": "info", "text": "Announcement published"}
                elif action == "remove":
                    result = delete_announcement(redis, request.form.get("id"))
                    audit_admin("announcement_remove", admin, "applied", {"announcement_id": result.get("id")})
                    notice = {"level": "info", "text": "Announcement removed"}
                else:
                    raise AnnouncementError("unknown announcement action")
            except (AnnouncementError, ValueError) as exc:
                audit_admin("announcement_mutation", admin, "denied", {"action": action})
                notice = {"level": "error", "text": str(exc)}
        rows = list_announcements(
            redis, project=request.args.get("project") or None, host=request.args.get("host") or None,
            active_only=request.args.get("active") == "1",
        )
        token = html.escape(csrf_token())
        for row in rows:
            row["scope"] = "host:{}".format(row.get("host")) if row.get("host") else ("project:{}".format(row.get("project")) if row.get("project") else "global")
            row["status"] = "active" if not row.get("expires_at") or int(row.get("expires_at")) > int(time.time()) else "expired"
            row["actions"] = '<form method="post" class="inline"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="action" value="remove"><input type="hidden" name="id" value="{}"><input type="hidden" name="confirm" value="true"><button type="submit">Remove</button></form>'.format(token, html.escape(str(row.get("id") or "")))
        body = """
<h1>Announcements</h1>
<form method="post" class="inline">
  <input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="add">
  <input name="text" placeholder="Operational notice" size="50" required>
  <input name="project" placeholder="project"><input name="host" placeholder="host id">
  <select name="severity"><option value="info">info</option><option value="warning">warning</option><option value="critical">critical</option></select>
  <input name="ttl" placeholder="2h" size="6"><label><input type="checkbox" name="confirm" value="true" required> confirm</label>
  <button type="submit">Publish</button>
</form>
<p><a href="/announcements?active=1">Active only</a> &middot; <a href="/announcements">All</a></p>
""".format(token=token)
        body += _table(rows, [
            ("id", "id"), ("status", "status"), ("severity", "severity"), ("scope", "scope"),
            ("text", "text"), ("created_by", "author"), ("expires_at", "expires"), ("actions", "actions"),
        ])
        return _html("Announcements", body, config=config, notice=notice)

    @app.route("/session/<connection_id>")
    def session_details(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        details = find_session(config["logging"]["base_path"], connection_id)
        if details is None:
            abort(404)
        summary = details.get("summary") or {}
        if not summary.get("server_name") and summary.get("host_id"):
            try:
                host_record = get_host(redis_client(config), summary.get("host_id"))
            except Exception:
                host_record = None
            if host_record is not None:
                summary["server_name"] = host_record.get("server_name")
        raw_link = ""
        replay_link = ""
        replay_json_link = ""
        live_link = ""
        try:
            active_record = get_session(redis_client(config), connection_id)
        except Exception:
            active_record = None
        if active_record and active_record.get("status") == "active":
            live_link = '<a href="/session/{}/live">live</a>'.format(html.escape(str(connection_id)))
        if summary.get("raw_log_path"):
            raw_link = '<a href="/raw/{}/{}">raw transcript</a>'.format(
                html.escape(str(summary.get("username") or "")),
                html.escape(str(connection_id)),
            )
            replay_link = '<a href="/replay/{}">replay</a>'.format(html.escape(str(connection_id)))
            replay_json_link = '<a href="/replay/{}.json">replay.json</a>'.format(html.escape(str(connection_id)))
        summary_rows = [
            {"key": key, "value": summary.get(key)}
            for key in ("time", "username", "project", "host_id", "server_name", "target", "remote_user", "result", "connection_id", "session_id")
        ]
        event_rows = []
        command_rows = []
        for event in details.get("events") or []:
            if event.get("event") == "command":
                command_rows.append(
                    {
                        "time": _format_ts(event.get("ts")),
                        "cwd": event.get("cwd"),
                        "command": event.get("command"),
                        "exit_code": event.get("exit_code"),
                        "shell": event.get("shell"),
                    }
                )
                continue
            event_rows.append(
                {
                    "time": _format_ts(event.get("ts")),
                    "event": event.get("event"),
                    "project": event.get("project"),
                    "host_id": event.get("host_id"),
                    "remote_user": event.get("remote_user"),
                    "exit_code": event.get("exit_code"),
                }
            )
        body = "<h1>Session Details</h1>"
        body += "<p>{} {} {} {} <a href=\"/session/{}/events.json\">events.json</a></p>".format(raw_link, replay_link, replay_json_link, live_link, html.escape(str(connection_id)))
        body += "<h2>Summary</h2>" + _table(summary_rows, [("key", "field"), ("value", "value")])
        if command_rows:
            body += "<h2>Commands</h2>" + _table(command_rows, [
                ("time", "time"), ("cwd", "cwd"), ("command", "command"), ("exit_code", "exit"), ("shell", "shell")
            ])
        body += "<h2>Timeline</h2>" + _table(event_rows, [
            ("time", "time"), ("event", "event"), ("project", "project"), ("host_id", "host"),
            ("remote_user", "remote_user"), ("exit_code", "exit")
        ])
        return _html("Session Details", body, config=config)

    @app.route("/session/<connection_id>/events.json")
    def session_events_json(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        details = find_session(config["logging"]["base_path"], connection_id)
        if details is None:
            abort(404)
        return app.response_class(
            response=json.dumps(details.get("events") or [], indent=2, sort_keys=True),
            status=200,
            mimetype="application/json",
        )

    @app.route("/session/<connection_id>/live.json")
    def session_live_json(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        active = get_session(redis, connection_id)
        details = find_session(config["logging"]["base_path"], connection_id)
        if details is None and active is None:
            abort(404)
        raw_path = (details or {}).get("raw_log_path")
        replay_data = parse_raw_replay(
            raw_path,
            max_bytes=int(config.get("session_control", {}).get("live_tail_bytes", 262144)),
            tail=True,
        )
        return jsonify({
            "active": bool(active and active.get("status") == "active"),
            "session": active or {},
            "duration": replay_data.get("duration"),
            "chunks": replay_data.get("chunks") or [],
            "plain": replay_data.get("plain") or "",
            "readable": replay_data.get("readable") or "",
            "error": replay_data.get("error"),
        })

    @app.route("/session/<connection_id>/live")
    def session_live(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        connection_id_safe = html.escape(str(connection_id))
        body = """
<h1>Live Session</h1>
<p><a href="/session/{connection_id}">details</a> <span id="state">loading</span>
  <label><input type="checkbox" id="readableToggle"> Readable text</label></p>
<link rel="stylesheet" href="/static/vendor/xterm/xterm.css">
<div id="terminal" style="background:#111;padding:12px;height:70vh;"></div>
<pre id="readable" style="display:none;max-height:70vh;overflow:auto;"></pre>
<script type="module">
import {{ Terminal }} from "/static/vendor/xterm/xterm.mjs";
const terminal = new Terminal({{rows: 50, cols: 180, scrollback: 5000, disableStdin: true, convertEol: false, theme: {{background: "#111111"}}}});
terminal.open(document.getElementById("terminal"));
const terminalElement = document.getElementById("terminal");
const readableElement = document.getElementById("readable");
document.getElementById("readableToggle").onchange = (event) => {{
  terminalElement.style.display = event.target.checked ? "none" : "block";
  readableElement.style.display = event.target.checked ? "block" : "none";
}};
async function refreshLive() {{
  const response = await fetch("/session/{connection_id}/live.json", {{cache: "no-store"}});
  if (!response.ok) {{ document.getElementById("state").textContent = "unavailable"; return; }}
  const data = await response.json();
  terminal.reset();
  terminal.write((data.chunks || []).map(chunk => chunk.data).join("") || data.plain || "");
  readableElement.textContent = data.readable || data.plain || "";
  document.getElementById("state").textContent = data.active ? "active" : "completed";
  if (data.active) setTimeout(refreshLive, 2000);
}}
refreshLive();
</script>
""".format(connection_id=connection_id_safe)
        return _html("Live Session", body, config=config)

    @app.route("/replay/<connection_id>.json")
    def replay_json(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        details = find_session(config["logging"]["base_path"], connection_id)
        if details is None:
            abort(404)
        replay = parse_raw_replay(details.get("raw_log_path"), max_bytes=int(config.get("replay", {}).get("max_bytes", 10485760)))
        return app.response_class(
            response=json.dumps(replay, indent=2, sort_keys=True),
            status=200,
            mimetype="application/json",
        )

    @app.route("/replay/<connection_id>")
    def replay(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        details = find_session(config["logging"]["base_path"], connection_id)
        if details is None:
            abort(404)
        replay_data = parse_raw_replay(details.get("raw_log_path"), max_bytes=int(config.get("replay", {}).get("max_bytes", 10485760)))
        readable = html.escape(replay_data.get("readable") or replay_data.get("plain") or "")
        error = replay_data.get("error")
        default_speed = html.escape(str(config.get("replay", {}).get("default_speed", 1)))
        body = """
<h1>Session Replay</h1>
<p><a href="/session/{connection_id}">details</a> <a href="/replay/{connection_id}.json" download>replay.json</a></p>
<p>
  <button id="play">Play</button>
  <button id="pause">Pause</button>
  <button id="reset">Reset</button>
  <select id="speed"><option value="0.5">0.5x</option><option value="1">1x</option><option value="2">2x</option><option value="5">5x</option></select>
  <label><input type="checkbox" id="plainToggle"> Readable text</label>
  <span id="clock">0.00 / 0.00</span>
</p>
<input id="scrubber" type="range" min="0" max="0" step="0.01" value="0" style="width:100%;">
<link rel="stylesheet" href="/static/vendor/xterm/xterm.css">
<div id="terminal" class="terminal" style="background:#111;padding:12px;height:62vh;"></div>
<pre id="fallback" style="display:none;max-height:62vh;overflow:auto;">{readable}</pre>
<script type="module">
import {{ Terminal }} from "/static/vendor/xterm/xterm.mjs";
let chunks = [];
let timers = [];
let speed = {default_speed};
let cursor = 0;
let duration = 0;
const terminalElement = document.getElementById("terminal");
const fallback = document.getElementById("fallback");
const emulator = new Terminal({{rows: 40, cols: 160, scrollback: 10000, disableStdin: true, convertEol: false, theme: {{background: "#111111"}}}});
emulator.open(terminalElement);
const scrubber = document.getElementById("scrubber");
const clock = document.getElementById("clock");
document.getElementById("speed").value = String(speed);
function clearTimers() {{ timers.forEach(clearTimeout); timers = []; }}
function renderUntil(index) {{
  cursor = Math.max(0, Math.min(index, chunks.length));
  emulator.reset();
  emulator.write(chunks.slice(0, cursor).map(c => c.data).join(""));
  const t = chunks[cursor - 1] ? chunks[cursor - 1].t : 0;
  scrubber.value = t;
  clock.textContent = t.toFixed(2) + " / " + duration.toFixed(2);
}}
function play() {{
  clearTimers();
  speed = parseFloat(document.getElementById("speed").value || "1");
  const base = chunks[cursor] ? chunks[cursor].t : 0;
  for (let i = cursor; i < chunks.length; i++) {{
    timers.push(setTimeout(() => {{
      emulator.write(chunks[i].data);
      cursor = i + 1;
      scrubber.value = chunks[i].t;
      clock.textContent = chunks[i].t.toFixed(2) + " / " + duration.toFixed(2);
    }}, Math.max(0, (chunks[i].t - base) * 1000 / speed)));
  }}
}}
document.getElementById("play").onclick = play;
document.getElementById("pause").onclick = clearTimers;
document.getElementById("reset").onclick = () => {{ clearTimers(); renderUntil(0); }};
document.getElementById("plainToggle").onchange = (event) => {{
  clearTimers();
  terminalElement.style.display = event.target.checked ? "none" : "block";
  fallback.style.display = event.target.checked ? "block" : "none";
  if (!event.target.checked) renderUntil(cursor);
}};
scrubber.oninput = () => {{
  clearTimers();
  const t = parseFloat(scrubber.value || "0");
  let index = chunks.findIndex(c => c.t > t);
  if (index < 0) index = chunks.length;
  renderUntil(index);
}};
fetch("/replay/{connection_id}.json").then(r => r.json()).then(data => {{
  chunks = data.chunks || [];
  duration = data.duration || (chunks.length ? chunks[chunks.length - 1].t : 0);
  scrubber.max = duration;
  clock.textContent = "0.00 / " + duration.toFixed(2);
  if (!chunks.length) {{ terminalElement.style.display = "none"; fallback.style.display = "block"; }}
}});
</script>
""".format(connection_id=html.escape(str(connection_id)), readable=readable, default_speed=default_speed)
        if error:
            body = '<div class="notice warning">{}</div>'.format(html.escape(str(error))) + body
        return _html("Session Replay", body, config=config)

    @app.route("/policy/simulate", methods=["GET", "POST"])
    def policy_simulate():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        result = None
        values = request.form if request.method == "POST" else request.args
        if values.get("project") or values.get("host"):
            redis = redis_client(config)
            host_id = str(values.get("host") or "").strip() or None
            host = get_host(redis, host_id) if host_id else None
            project = str(values.get("project") or "").strip() or (host or {}).get("project_name")
            identity = {
                "username": str(values.get("user") or "policy-preview").strip(),
                "groups": _split_values(values.get("groups")),
                "roles": _split_values(values.get("roles")),
            }
            action = str(values.get("policy_action") or "ssh").strip()
            try:
                decision = resolve_grant(
                    identity, project=project, host=host, grants=load_grants(redis),
                    project_sets=load_project_sets(redis),
                    defaults={**config.get("policy", {}), **config.get("ssh", {})}, action=action,
                )
                result = {"allowed": True, "identity": identity, "project": project, "host": host, "action": action, "decision": decision}
            except PolicyDenied as exc:
                result = {"allowed": False, "identity": identity, "project": project, "host_id": host_id, "action": action, "reason": str(exc)}
        body = """
<h1>Policy Simulator</h1>
<form method="post" class="inline">
<input name="user" value="{user}" placeholder="username"><input name="groups" value="{groups}" placeholder="Group-A,Group-B">
<input name="roles" value="{roles}" placeholder="roles"><input name="project" value="{project}" placeholder="project">
<input name="host" value="{host}" placeholder="host id"><select name="policy_action"><option>ssh</option><option>runbook</option><option>operate</option><option>command</option></select>
<button type="submit">Simulate</button>
</form>
""".format(**{name: html.escape(str(values.get(name) or "")) for name in ("user", "groups", "roles", "project", "host")})
        if result is not None:
            decision = result.get("decision") or {}
            matched = decision.get("matched_rule") or {}
            summary = {
                "result": "ALLOWED" if result.get("allowed") else "DENIED",
                "reason": result.get("reason"),
                "grant_id": matched.get("id"),
                "remote_user": decision.get("remote_user"),
                "sudo_mode": decision.get("sudo_mode"),
                "allowed_actions": decision.get("allowed_actions"),
            }
            level = "info" if result.get("allowed") else "error"
            body += '<div class="notice {}"><strong>{}</strong></div>'.format(level, summary["result"])
            body += "<h2>Decision</h2><pre>{}</pre>".format(html.escape(json.dumps(summary, indent=2, sort_keys=True)))
            body += "<details><summary>Full evaluation</summary><pre>{}</pre></details>".format(html.escape(json.dumps(result, indent=2, sort_keys=True)))
        return _html("Policy Simulator", body, config=config)

    @app.route("/policy/gitops", methods=["GET", "POST"])
    def policy_gitops():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        cfg = config.get("policy_as_code", {}) or {}
        notice = None
        status = None
        if request.method == "POST":
            validate_csrf()
            try:
                require_mutation_confirmation()
                action = request.form.get("action")
                if action == "sync":
                    status = sync_git_policy(config, redis, dry_run=False, confirmed=True)
                    audit_admin("policy_git_sync", admin, "applied", {"commit": status.get("commit")})
                    notice = {"level": "info", "text": "Approved Git policy synchronized"}
                elif action == "rollback":
                    revision = request.form.get("revision")
                    status = rollback_policy(config, redis, revision, confirmed=True)
                    audit_admin("policy_rollback", admin, "applied", {"revision": revision})
                    notice = {"level": "warning", "text": "Policy rolled back; pause the sync timer if Git still contains the newer revision"}
                else:
                    raise ValueError("unknown GitOps action")
            except (GitOpsError, PolicyBundleError, OSError, ValueError) as exc:
                notice = {"level": "error", "text": str(exc)}
        elif cfg.get("enabled") and request.args.get("refresh") == "1":
            try:
                status = git_policy_status(config, redis)
            except (GitOpsError, PolicyBundleError, OSError, ValueError) as exc:
                notice = {"level": "error", "text": str(exc)}
        revisions = list_policy_snapshots(config)
        body = "<h1>Policy GitOps</h1><pre>{}</pre>".format(html.escape(json.dumps({
            "enabled": bool(cfg.get("enabled")), "enforce_git": bool(cfg.get("enforce_git")),
            "repository": cfg.get("repository"), "branch": cfg.get("branch"),
            "bundle": cfg.get("git_bundle_path"), "approval_required": True,
        }, indent=2, sort_keys=True)))
        body += '<p><a href="/policy/gitops?refresh=1">Fetch status, drift and blast radius</a></p>'
        if status is not None:
            body += "<h2>Result</h2><pre>{}</pre>".format(html.escape(json.dumps(status, indent=2, sort_keys=True)))
        token = html.escape(csrf_token())
        if cfg.get("enabled"):
            body += '<form method="post" class="inline"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="action" value="sync"><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Sync approved revision</button></form>'.format(token)
        body += "<h2>Rollback revisions</h2>" + _table(revisions, [("revision_id", "revision"), ("created_at", "created"), ("source", "source")])
        body += '<form method="post" class="inline"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="action" value="rollback"><input name="revision" placeholder="revision id" required><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Rollback</button></form>'.format(token)
        return _html("Policy GitOps", body, config=config, notice=notice)

    @app.route("/users")
    def users():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        profiles = list_user_profiles(config["logging"]["base_path"])
        active_users = {row.get("username") for row in list_active_sessions(redis_client(config))}
        for profile in profiles:
            username = str(profile.get("username") or "")
            profile["user_link"] = '<a href="/user/{}">{}</a>'.format(urllib.parse.quote(username, safe=""), html.escape(username))
            profile["active"] = "yes" if username in active_users else ""
            profile["groups_display"] = ", ".join(profile.get("groups") or [])
            profile["last_seen_display"] = _format_ts(profile.get("last_seen"))
        export_links = '<p><a href="/export/users?format=csv">Download CSV</a> &middot; <a href="/export/users?format=json">Download JSON</a></p>'
        return _html("Users", "<h1>Users</h1>" + export_links + _table(profiles, [
            ("user_link", "user"), ("groups_display", "groups"), ("last_seen_display", "last_seen"),
            ("connection_count", "connections"), ("active", "active"),
        ]), config=config)

    @app.route("/user/<username>")
    def user_details(username):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        profiles = {row["username"]: row for row in list_user_profiles(config["logging"]["base_path"])}
        profile = profiles.get(username, {"username": username, "groups": [], "roles": []})
        redis = redis_client(config)
        active = [row for row in list_active_sessions(redis) if row.get("username") == username]
        history_rows = read_history(
            config["logging"]["base_path"], admin, user=username, limit=200,
            admin_groups=config.get("dashboard", {}).get("admin_groups") or [],
        )
        subjects = {("user", username)}
        subjects.update(("group", group) for group in profile.get("groups") or [])
        subjects.update(("role", role) for role in profile.get("roles") or [])
        grants = [row for row in list_grant_records(redis) if (row.get("subject"), row.get("name")) in subjects]
        activity = user_activity_summary(
            config["logging"]["base_path"], username, limit=20, active_sessions=active,
            grants=list_grant_records(redis), access_requests=list_access_requests(redis),
        )
        metrics = activity.get("metrics") or {}
        body = """
<h1>User {username}</h1>
<div class="grid">
  <div class="metric"><strong>{connections}</strong><span class="muted">connections</span></div>
  <div class="metric"><strong>{active}</strong><span class="muted">active sessions</span></div>
  <div class="metric"><strong>{failures}</strong><span class="muted">recent failures</span></div>
  <div class="metric"><strong>{grants}</strong><span class="muted">grant candidates</span></div>
  <div class="metric"><strong>{requests}</strong><span class="muted">access requests</span></div>
</div>
<h2>Identity observed in audit</h2><pre>{profile}</pre>
<h2>Top projects</h2>{top_projects}
""".format(
            username=html.escape(username), connections=metrics.get("connections", 0), active=metrics.get("active_sessions", 0),
            failures=metrics.get("recent_failures", 0), grants=metrics.get("grant_candidates", 0), requests=metrics.get("access_requests", 0),
            profile=html.escape(json.dumps(profile, indent=2, sort_keys=True)),
            top_projects=_table(activity.get("top_projects") or [], [("project", "project"), ("connections", "connections")]),
        )
        body += "<h2>Effective grant candidates</h2>" + _table(grants, [
            ("id", "id"), ("subject", "subject"), ("name", "name"), ("project", "project"),
            ("project_set", "project_set"), ("project_glob", "glob"), ("host", "host"),
            ("remote_user", "remote_user"), ("sudo_mode", "sudo"), ("allowed_actions", "actions"),
        ])
        body += "<h2>Active sessions</h2>" + _table(active, [
            ("started_at", "started"), ("project", "project"), ("host_id", "host"), ("remote_user", "remote_user"),
        ])
        body += "<h2>Recent sessions</h2>" + _table(history_rows, [
            ("time", "time"), ("project", "project"), ("host_id", "host"), ("target", "target"),
            ("remote_user", "remote_user"), ("result", "result"),
        ])
        body += "<h2>Recent access requests</h2>" + _table(activity.get("access_requests") or [], [
            ("id", "id"), ("status", "status"), ("project", "project"), ("host", "host"),
            ("remote_user", "remote_user"), ("ticket", "ticket"), ("created_at", "created"),
        ])
        return _html("User Details", body, config=config)

    @app.route("/notifications")
    def notification_status():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        sinks = []
        for index, sink in enumerate(config.get("notifications", {}).get("sinks") or []):
            sinks.append({"index": index, "type": sink.get("type"), "configured": "yes"})
        deliveries = []
        for record in list_access_requests(redis_client(config)):
            status = record.get("notification_status") or {}
            deliveries.append({
                "request_id": record.get("id"), "status": record.get("status"), "requester": record.get("requester"),
                "ok": status.get("ok"), "sent": ", ".join(str(item.get("type")) for item in status.get("sent") or []),
                "errors": "; ".join(status.get("errors") or []), "updated_at": status.get("updated_at"),
            })
        session_deliveries = []
        for record in list_session_records(redis_client(config)):
            for delivery in record.get("alert_deliveries") or []:
                session_deliveries.append({
                    "connection_id": record.get("connection_id"), "alert": delivery.get("alert"),
                    "user": record.get("username"), "ok": delivery.get("ok"),
                    "sent": ", ".join(str(item.get("type")) for item in delivery.get("sent") or []),
                    "errors": "; ".join(delivery.get("errors") or []), "updated_at": delivery.get("ts"),
                })
        body = "<h1>Notification Delivery</h1><h2>Configured sinks</h2>" + _table(sinks, [("index", "#"), ("type", "type"), ("configured", "configured")])
        body += "<h2>Access request delivery status</h2>" + _table(deliveries, [
            ("request_id", "request"), ("status", "status"), ("requester", "requester"),
            ("ok", "ok"), ("sent", "sent"), ("errors", "errors"), ("updated_at", "updated"),
        ])
        body += "<h2>Session alert delivery status</h2>" + _table(session_deliveries, [
            ("connection_id", "connection"), ("alert", "alert"), ("user", "user"),
            ("ok", "ok"), ("sent", "sent"), ("errors", "errors"), ("updated_at", "updated"),
        ])
        return _html("Notifications", body, config=config)

    @app.route("/packages", methods=["GET", "POST"])
    def packages():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action")
            try:
                require_mutation_confirmation()
                require_manual_policy_edit()
                if not config.get("access_packages", {}).get("enabled", True):
                    raise AccessPackageError("access packages are disabled")
                if action == "create":
                    package = create_package(
                        redis, _package_form_payload(request.form), actor=admin.get("username"),
                        max_rules=config.get("access_packages", {}).get("max_rules", 50),
                    )
                    notice = {"level": "success", "text": "Access package created: {}".format(package["name"])}
                elif action == "assign":
                    package = get_package(redis, request.form.get("package"))
                    if package is None:
                        raise AccessPackageError("access package was not found")
                    allowed_admins = set((package.get("approval") or {}).get("admin_groups") or [])
                    if allowed_admins and not allowed_admins.intersection(admin.get("groups") or []):
                        raise AccessPackageError("your Keycloak groups cannot assign this package")
                    names = _split_values(request.form.get("name"))
                    maximum = int(config.get("access_packages", {}).get("max_assignments_per_operation") or 100)
                    if not names or len(names) > maximum:
                        raise AccessPackageError("provide between 1 and {} subject names".format(maximum))
                    for name in names:
                        assign_package(
                            redis, package["id"], request.form.get("subject"), name,
                            actor=admin.get("username"), ttl=str(request.form.get("ttl") or "").strip() or None,
                            permanent=request.form.get("permanent") == "true", ticket=request.form.get("ticket"),
                        )
                    notice = {"level": "success", "text": "Package assigned to {} subject(s)".format(len(names))}
                elif action == "unassign":
                    assignment, deleted = unassign_package(redis, request.form.get("id"), actor=admin.get("username"))
                    notice = {"level": "success", "text": "Assignment {} revoked; {} managed grant(s) removed".format(assignment["id"], deleted)}
                else:
                    raise AccessPackageError("unknown package action")
                audit_admin("package_{}".format(action), admin, "applied", {"package": request.form.get("package")})
            except (AccessPackageError, ValueError) as exc:
                audit_admin("package_{}".format(action or "mutation"), admin, "denied")
                notice = {"level": "error", "text": str(exc)}

        package_rows = []
        for package in list_packages(redis):
            row = dict(package)
            row["rules"] = len(package.get("access") or [])
            row["package_link"] = '<a href="/packages/{}">open</a>'.format(urllib.parse.quote(str(package["id"]), safe=""))
            package_rows.append(row)
        assignments = list_assignments(redis)
        for row in assignments:
            row["expires"] = _format_ts(row.get("expires_at")) or "permanent"
            row["package_link"] = '<a href="/packages/{}">{}</a>'.format(
                urllib.parse.quote(str(row.get("package_id") or ""), safe=""), html.escape(str(row.get("package_name") or ""))
            )
        token = html.escape(csrf_token())
        example = html.escape(json.dumps([{
            "id": "support-prod", "project_set": "prod-apps", "remote_user": "support",
            "sudo_mode": "none", "allowed_actions": ["ssh", "runbook"],
        }], indent=2))
        body = "<h1>Access Packages</h1>" + _table(package_rows, [
            ("id", "id"), ("name", "name"), ("status", "status"), ("revision", "revision"),
            ("rules", "rules"), ("description", "description"), ("package_link", "details"),
        ])
        body += """
<h2>Create package</h2><form method="post">
<input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="create">
<p><label>Name <input name="name" required placeholder="Support Read-Only"></label><label>Status <select name="status"><option>enabled</option><option>disabled</option></select></label></p>
<p><label>Description <input name="description" size="72" placeholder="Read-only production access for support teams"></label></p>
<p><label>Access rules <textarea name="access_json" rows="10" cols="92" required>{example}</textarea></label></p>
<p><label>Default TTL <input name="default_ttl" placeholder="7d" size="8"></label><label>Max TTL <input name="max_ttl" placeholder="30d" size="8"></label><label><input type="checkbox" name="permanent_allowed" value="true"> Permanent allowed</label></p>
<p><label><input type="checkbox" name="approval_required" value="true"> Approval required</label><label>Admin groups <input name="admin_groups" placeholder="DevSecOps, OS-admin"></label><label><input type="checkbox" name="ticket_required" value="true"> Ticket required</label><label>Minimum approvals <input type="number" name="minimum_approvals" min="1" value="1" size="5"></label></p>
<p><label><input type="checkbox" name="confirm" value="true" required> Confirm</label><button>Create package</button></p></form>
<h2>Assign package</h2><form method="post" class="inline">
<input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="assign">
<input name="package" placeholder="package id or name" required><select name="subject"><option>group</option><option>user</option><option>role</option></select>
<input name="name" placeholder="one or comma-separated subjects" required size="34"><input name="ttl" placeholder="7d" size="8"><input name="ticket" placeholder="CHG-1042">
<label><input type="checkbox" name="permanent" value="true"> Permanent</label><label><input type="checkbox" name="confirm" value="true" required> Confirm</label><button>Assign</button></form>
<h2>Assignments</h2>{assignments}
<h2>Revoke assignment</h2><form method="post" class="inline"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="unassign"><input name="id" placeholder="assignment id" required><label><input type="checkbox" name="confirm" value="true" required> Confirm</label><button class="button-danger">Unassign</button></form>
""".format(token=token, example=example, assignments=_table(assignments, [
            ("id", "id"), ("package_link", "package"), ("subject", "subject"), ("name", "name"),
            ("status", "status"), ("expires", "expires"), ("ticket", "ticket"), ("grant_ids", "grants"),
        ]))
        return _html("Access Packages", body, config=config, notice=notice)

    @app.route("/packages/<package_id>", methods=["GET", "POST"])
    def package_details(package_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        package = get_package(redis, package_id)
        if package is None:
            abort(404)
        notice = None
        preview = None
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action")
            try:
                if action == "preview":
                    payload = _package_form_payload(request.form, current=package)
                    preview = preview_package_update(
                        redis, package["id"], payload, actor=admin.get("username"),
                        max_rules=config.get("access_packages", {}).get("max_rules", 50),
                    )
                    notice = {"level": "info", "text": "Preview completed; no changes were applied"}
                elif action == "update":
                    require_mutation_confirmation()
                    require_manual_policy_edit()
                    payload = _package_form_payload(request.form, current=package)
                    package, _ = update_package(
                        redis, package["id"], payload, actor=admin.get("username"),
                        expected_revision=request.form.get("expected_revision"),
                        max_rules=config.get("access_packages", {}).get("max_rules", 50),
                    )
                    audit_admin("package_update", admin, "applied", {"package_id": package["id"], "revision": package["revision"]})
                    notice = {"level": "success", "text": "Package updated and assignments synchronized"}
                elif action == "rollback":
                    require_mutation_confirmation()
                    require_manual_policy_edit()
                    package, _ = rollback_package(
                        redis, package["id"], int(request.form.get("revision")), actor=admin.get("username"),
                        expected_revision=request.form.get("expected_revision"),
                    )
                    audit_admin("package_rollback", admin, "applied", {"package_id": package["id"], "revision": package["revision"]})
                    notice = {"level": "success", "text": "Package rollback created revision {}".format(package["revision"])}
                else:
                    raise AccessPackageError("unknown package action")
            except (AccessPackageError, ValueError) as exc:
                audit_admin("package_{}".format(action or "mutation"), admin, "denied", {"package_id": package_id})
                notice = {"level": "error", "text": str(exc)}
        token = html.escape(csrf_token())
        lifecycle = package.get("lifecycle") or {}
        approval = package.get("approval") or {}
        checked = lambda value: " checked" if value else ""
        selected = lambda value, expected: " selected" if value == expected else ""
        body = '<p><a href="/packages">Back to packages</a></p><h1>{}</h1>'.format(html.escape(str(package["name"])))
        body += '<dl class="key-value"><dt>ID</dt><dd>{}</dd><dt>Revision</dt><dd>{}</dd><dt>Updated by</dt><dd>{}</dd><dt>Updated</dt><dd>{}</dd></dl>'.format(
            html.escape(str(package["id"])), html.escape(str(package["revision"])), html.escape(str(package.get("updated_by") or "")), html.escape(_format_ts(package.get("updated_at")))
        )
        if preview:
            body += '<div class="panel"><h2>Preview</h2><p><strong>{}</strong> affected subjects, <strong>{}</strong> grant changes; revision {} to {}.</p><pre>{}</pre></div>'.format(
                preview["affected_subjects"], preview["grant_change_count"], preview["from_revision"], preview["to_revision"], html.escape(json.dumps(preview["assignments"], indent=2, sort_keys=True))
            )
        body += """
<h2>Edit and preview</h2><form method="post">
<input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="expected_revision" value="{revision}">
<p><label>Name <input name="name" value="{name}" required></label><label>Status <select name="status"><option{enabled}>enabled</option><option{disabled}>disabled</option></select></label></p>
<p><label>Description <input name="description" value="{description}" size="72"></label></p>
<p><label>Access rules <textarea name="access_json" rows="14" cols="92" required>{access}</textarea></label></p>
<p><label>Default TTL <input name="default_ttl" value="{default_ttl}" size="8"></label><label>Max TTL <input name="max_ttl" value="{max_ttl}" size="8"></label><label><input type="checkbox" name="permanent_allowed" value="true"{permanent}> Permanent allowed</label></p>
<p><label><input type="checkbox" name="approval_required" value="true"{required}> Approval required</label><label>Admin groups <input name="admin_groups" value="{admin_groups}"></label><label><input type="checkbox" name="ticket_required" value="true"{ticket_required}> Ticket required</label><label>Minimum approvals <input type="number" name="minimum_approvals" min="1" value="{minimum_approvals}" size="5"></label></p>
<p><button name="action" value="preview" class="button-secondary">Preview</button><label><input type="checkbox" name="confirm" value="true"> Confirm apply</label><button name="action" value="update">Apply revision</button></p></form>
<h2>Revision history</h2>{revisions}
<h2>Rollback</h2><form method="post" class="inline"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="expected_revision" value="{revision}"><input type="hidden" name="action" value="rollback"><input type="number" name="revision" min="1" placeholder="revision" required><label><input type="checkbox" name="confirm" value="true" required> Confirm</label><button class="button-danger">Create rollback revision</button></form>
""".format(
            token=token, revision=html.escape(str(package["revision"])), name=html.escape(str(package["name"])),
            description=html.escape(str(package.get("description") or "")), access=html.escape(json.dumps(package.get("access") or [], indent=2, sort_keys=True)),
            enabled=selected(package.get("status"), "enabled"), disabled=selected(package.get("status"), "disabled"),
            default_ttl=html.escape(str(lifecycle.get("default_ttl") or "")), max_ttl=html.escape(str(lifecycle.get("max_ttl") or "")),
            permanent=checked(lifecycle.get("permanent_allowed")), required=checked(approval.get("required")),
            admin_groups=html.escape(", ".join(approval.get("admin_groups") or [])), ticket_required=checked(approval.get("ticket_required")),
            minimum_approvals=html.escape(str(approval.get("minimum_approvals") or 1)),
            revisions=_table(list_package_revisions(redis, package["id"]), [
                ("revision", "revision"), ("status", "status"), ("updated_by", "updated_by"),
                ("updated_at", "updated_at"), ("rolled_back_from", "rollback source"),
            ]),
        )
        return _html("Access Packages", body, config=config, notice=notice)

    @app.route("/docs")
    def documentation():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        locale = _dashboard_locale(config)
        return _html("Documentation", _documentation_body(locale, _build_info(config)), config=config)

    @app.route("/grants", methods=["GET", "POST"])
    def grants():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action")
            try:
                require_mutation_confirmation()
                require_manual_policy_edit()
                bundle = export_bundle(redis)
                if action == "grant_save":
                    grant_id = str(request.form.get("id") or "").strip() or None
                    selector_type = request.form.get("selector_type")
                    selector_value = str(request.form.get("selector_value") or "").strip()
                    if selector_type not in ("project", "project_glob", "project_set") or not selector_value:
                        raise ValueError("one project selector is required")
                    grant = {
                        "schema_version": 2,
                        "subject": request.form.get("subject"),
                        "name": str(request.form.get("name") or "").strip(),
                        selector_type: selector_value,
                        "host": str(request.form.get("host") or "").strip() or None,
                        "remote_user": str(request.form.get("remote_user") or "").strip(),
                        "sudo_mode": request.form.get("sudo_mode") or "none",
                        "allowed_actions": _split_values(request.form.get("allowed_actions")) or ["ssh"],
                    }
                    if grant_id:
                        grant["id"] = grant_id
                        replaced = False
                        for index, current in enumerate(bundle["grants"]):
                            if str(current.get("id")) == grant_id:
                                if current.get("managed_by") == "access_package":
                                    raise ValueError("grant {} is managed by access package {}; edit the package instead".format(
                                        grant_id, current.get("package_name") or current.get("package_id")
                                    ))
                                bundle["grants"][index] = grant
                                replaced = True
                                break
                        if not replaced:
                            raise ValueError("grant not found: {}".format(grant_id))
                    else:
                        bundle["grants"].append(grant)
                elif action == "grant_remove":
                    grant_id = str(request.form.get("id") or "").strip()
                    current = next((row for row in bundle["grants"] if str(row.get("id")) == grant_id), None)
                    if current and current.get("managed_by") == "access_package":
                        raise ValueError("grant {} is managed by access package {}; unassign it through Access Packages".format(
                            grant_id, current.get("package_name") or current.get("package_id")
                        ))
                    before = len(bundle["grants"])
                    bundle["grants"] = [row for row in bundle["grants"] if str(row.get("id")) != grant_id]
                    if len(bundle["grants"]) == before:
                        raise ValueError("grant not found: {}".format(grant_id))
                elif action == "grant_bulk_action":
                    grant_ids = set(_split_values(request.form.get("ids")))
                    selected_action = str(request.form.get("allowed_action") or "").strip()
                    mode = request.form.get("mode")
                    if not grant_ids or not selected_action or mode not in ("add", "remove"):
                        raise ValueError("grant ids, action, and mode are required")
                    matched = set()
                    for grant in bundle["grants"]:
                        if str(grant.get("id")) not in grant_ids:
                            continue
                        if grant.get("managed_by") == "access_package":
                            raise ValueError("bulk editing package-managed grants is not allowed")
                        matched.add(str(grant.get("id")))
                        actions = set(grant.get("allowed_actions") or ["ssh"])
                        if mode == "add":
                            actions.add(selected_action)
                        else:
                            actions.discard(selected_action)
                        grant["allowed_actions"] = sorted(actions)
                    if matched != grant_ids:
                        raise ValueError("one or more grant ids were not found")
                elif action == "project_set_save":
                    name = str(request.form.get("name") or "").strip()
                    if not name:
                        raise ValueError("project set name is required")
                    record = {
                        "schema_version": 2,
                        "name": name,
                        "projects": sorted(set(_split_values(request.form.get("projects")))),
                        "project_globs": sorted(set(_split_values(request.form.get("project_globs")))),
                    }
                    bundle["project_sets"] = [row for row in bundle["project_sets"] if row.get("name") != name]
                    bundle["project_sets"].append(record)
                elif action == "project_set_remove":
                    name = str(request.form.get("name") or "").strip()
                    bundle["project_sets"] = [row for row in bundle["project_sets"] if row.get("name") != name]
                elif action == "project_set_bulk_members":
                    names = set(_split_values(request.form.get("names")))
                    values = set(_split_values(request.form.get("values")))
                    member_type = request.form.get("member_type")
                    mode = request.form.get("mode")
                    if not names or not values or member_type not in ("projects", "project_globs") or mode not in ("add", "remove"):
                        raise ValueError("set names, values, member type, and mode are required")
                    matched = set()
                    for project_set in bundle["project_sets"]:
                        if project_set.get("name") not in names:
                            continue
                        matched.add(project_set["name"])
                        members = set(project_set.get(member_type) or [])
                        members = members | values if mode == "add" else members - values
                        project_set[member_type] = sorted(members)
                    if matched != names:
                        raise ValueError("one or more project sets were not found")
                else:
                    raise ValueError("unknown policy action")
                validation = validate_bundle(bundle)
                if not validation["valid"]:
                    raise PolicyBundleError("; ".join(validation["errors"]))
                changes = plan_bundle(redis, bundle, prune=True)
                save_policy_snapshot(config, redis, source="dashboard:{}".format(action))
                apply_bundle(redis, bundle, prune=True)
                audit_admin(action, admin, "applied", {"change_count": sum(len(rows) for rows in changes.values())})
                notice = {"level": "info", "text": "Policy updated"}
            except (ValueError, PolicyBundleError, OSError) as exc:
                audit_admin(action or "policy_mutation", admin, "denied")
                notice = {"level": "error", "text": str(exc)}
        grant_rows = list_grant_records(redis)
        sets = list(load_project_sets(redis).values())
        edit_grant = get_grant_record(redis, request.args.get("edit_grant")) if request.args.get("edit_grant") else None
        edit_set = next((row for row in sets if row.get("name") == request.args.get("edit_set")), None)
        for row in grant_rows:
            if row.get("managed_by") == "access_package":
                row["edit"] = '<a href="/packages/{}">managed package</a>'.format(
                    urllib.parse.quote(str(row.get("package_id") or ""), safe="")
                )
            else:
                row["edit"] = '<a href="/grants?edit_grant={}">edit</a>'.format(urllib.parse.quote(str(row.get("id") or ""), safe=""))
        for row in sets:
            row["edit"] = '<a href="/grants?edit_set={}">edit</a>'.format(urllib.parse.quote(str(row.get("name") or ""), safe=""))
        token = html.escape(csrf_token())
        edit_grant = edit_grant or {}
        edit_selector = next((name for name in ("project", "project_set", "project_glob") if edit_grant.get(name) is not None), "project")
        grant_form = {
            "id": html.escape(str(edit_grant.get("id") or "")),
            "name": html.escape(str(edit_grant.get("name") or "")),
            "selector": html.escape(str(edit_grant.get(edit_selector) or "")),
            "host": html.escape(str(edit_grant.get("host") or "")),
            "remote_user": html.escape(str(edit_grant.get("remote_user") or "")),
            "actions": html.escape(", ".join(edit_grant.get("allowed_actions") or ["ssh"])),
        }
        def selected(value, expected):
            return " selected" if value == expected else ""
        git_notice = "<p><strong>Enforced GitOps:</strong> policy is read-only here.</p>" if config.get("policy_as_code", {}).get("enforce_git", False) else ""
        body = '<h1>Grants</h1><p><a href="/export/grants?format=csv">Download CSV</a> &middot; <a href="/export/grants?format=json">Download JSON</a></p>' + git_notice + _table(grant_rows, [
            ("id", "id"), ("subject", "subject"), ("name", "name"), ("project", "project"),
            ("project_set", "project_set"), ("project_glob", "project_glob"), ("remote_user", "remote_user"),
            ("sudo_mode", "sudo"), ("allowed_actions", "actions"), ("edit", "edit")
        ])
        body += """
<h2>Add or replace grant</h2>
<form method="post" class="inline">
<input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="grant_save">
<input name="id" value="{id}" placeholder="id for update" size="8"><select name="subject"><option{subject_group}>group</option><option{subject_user}>user</option><option{subject_role}>role</option></select>
<input name="name" value="{name}" placeholder="subject name" required><select name="selector_type"><option{selector_project}>project</option><option{selector_set}>project_set</option><option{selector_glob}>project_glob</option></select>
<input name="selector_value" value="{selector}" placeholder="selector" required><input name="host" value="{host}" placeholder="optional host" size="10">
<input name="remote_user" value="{remote_user}" placeholder="remote user" required><select name="sudo_mode"><option{sudo_none}>none</option><option{sudo_i}>sudo-i</option></select>
<input name="allowed_actions" value="{actions}" placeholder="ssh,runbook"><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Save</button>
</form>
<h2>Remove grant</h2><form method="post" class="inline"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="grant_remove"><input name="id" placeholder="grant id" required><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Remove</button></form>
<h2>Bulk grant action</h2><form method="post" class="inline"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="grant_bulk_action"><input name="ids" placeholder="1,2,3" required><select name="mode"><option>add</option><option>remove</option></select><input name="allowed_action" placeholder="runbook" required><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Apply</button></form>
""".format(
            token=token, **grant_form,
            subject_group=selected(edit_grant.get("subject") or "group", "group"),
            subject_user=selected(edit_grant.get("subject"), "user"), subject_role=selected(edit_grant.get("subject"), "role"),
            selector_project=selected(edit_selector, "project"), selector_set=selected(edit_selector, "project_set"),
            selector_glob=selected(edit_selector, "project_glob"), sudo_none=selected(edit_grant.get("sudo_mode") or "none", "none"),
            sudo_i=selected(edit_grant.get("sudo_mode"), "sudo-i"),
        )
        body += "<h1>Project Sets</h1>" + _table(sets, [("name", "name"), ("projects", "projects"), ("project_globs", "globs"), ("edit", "edit")])
        edit_set = edit_set or {}
        body += """
<h2>Add or replace project set</h2><form method="post" class="inline"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="project_set_save"><input name="name" value="{set_name}" placeholder="name" required><input name="projects" value="{projects}" placeholder="prod-a,prod-b"><input name="project_globs" value="{globs}" placeholder="*-prod"><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Save</button></form>
<h2>Remove project set</h2><form method="post" class="inline"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="project_set_remove"><input name="name" placeholder="name" required><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Remove</button></form>
<h2>Bulk project-set members</h2><form method="post" class="inline"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="project_set_bulk_members"><input name="names" placeholder="set-a,set-b" required><select name="member_type"><option>projects</option><option>project_globs</option></select><select name="mode"><option>add</option><option>remove</option></select><input name="values" placeholder="project-a,*-prod" required><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Apply</button></form>
""".format(
            token=token, set_name=html.escape(str(edit_set.get("name") or "")),
            projects=html.escape(", ".join(edit_set.get("projects") or [])),
            globs=html.escape(", ".join(edit_set.get("project_globs") or [])),
        )
        return _html("Grants", body, config=config, notice=notice)

    @app.route("/raw/<user>/<connection_id>")
    def raw(user, connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        details = find_session(config["logging"]["base_path"], connection_id)
        summary = (details or {}).get("summary") or {}
        if details and str(summary.get("username") or "") == str(user) and details.get("raw_log_path"):
            return send_file(details["raw_log_path"], mimetype="text/plain")
        abort(404)

    return app


def main():
    config = load_config()
    app = create_app(config)
    dashboard = config.get("dashboard", {})
    app.run(host=dashboard.get("listen_host", "127.0.0.1"), port=int(dashboard.get("listen_port", 8080)))


if __name__ == "__main__":
    main()
