#!/usr/bin/env bash
# Install on an existing root-managed Isolate bastion. No network changes.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Run as root' >&2; exit 1; }
source_root="$(cd "$(dirname "$0")/.." && pwd)"
[[ -x /opt/auth/.venv/bin/python ]] || { echo 'Missing Isolate runtime' >&2; exit 1; }
install -d -o auth -g auth -m 0700 /opt/auth/spool
if [[ "$source_root" != /opt/auth ]]; then
  install -o root -g auth -m 0640 "$source_root/shared/isolate_audit_export.py" /opt/auth/shared/isolate_audit_export.py
fi
install -o root -g root -m 0644 "$source_root/deploy/systemd/isolate-audit-export.service" /etc/systemd/system/isolate-audit-export.service
install -d -o root -g root -m 0755 /etc/logrotate.d
install -o root -g root -m 0644 "$source_root/deploy/logrotate/isolate" /etc/logrotate.d/isolate
systemctl daemon-reload
systemctl enable --now isolate-audit-export.service
echo 'Feed: /opt/auth/spool/events.jsonl. Configure the SIEM agent separately.'
