#!/usr/bin/env bash
set -euo pipefail

install -d -o auth -g auth -m 0700 /home/auth/.ssh
install -d -o root -g root -m 0700 /demo/audit-ssh
install -d -o auth -g auth -m 0700 /opt/auth/keys
install -d -o auth -g auth -m 2770 /opt/auth/logs
install -d -o auth -g auth -m 0750 /opt/auth/cache /opt/auth/backups

if [[ ! -s /home/auth/.ssh/id_ed25519 ]]; then
  runuser -u auth -- ssh-keygen -q -t ed25519 -N '' -f /home/auth/.ssh/id_ed25519
fi

if [[ ! -s /demo/audit-ssh/id_ed25519 ]]; then
  ssh-keygen -q -t ed25519 -N '' -f /demo/audit-ssh/id_ed25519
fi

if [[ ! -s /opt/auth/keys/dashboard_secret ]]; then
  openssl rand -hex 32 > /opt/auth/keys/dashboard_secret
fi

cp /demo/audit-ssh/id_ed25519.pub /opt/auth/keys/command_audit_id_ed25519.pub
cp /home/auth/.ssh/id_ed25519.pub /demo/audit-ssh/bastion_id_ed25519.pub
chown -R auth:auth /home/auth/.ssh /opt/auth/keys /opt/auth/logs /opt/auth/cache /opt/auth/backups
chmod 0700 /home/auth/.ssh /opt/auth/keys
chmod 0600 /home/auth/.ssh/id_ed25519 /opt/auth/keys/dashboard_secret
chmod 0644 /home/auth/.ssh/id_ed25519.pub /opt/auth/keys/command_audit_id_ed25519.pub
chmod 0700 /demo/audit-ssh
chmod 0600 /demo/audit-ssh/id_ed25519
chmod 0644 /demo/audit-ssh/id_ed25519.pub /demo/audit-ssh/bastion_id_ed25519.pub

echo "Isolate demo keys and runtime volumes initialized"
