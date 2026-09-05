#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "Run as root: sudo $0 auth@bastion.example.org" >&2
  exit 1
fi

audit_bastion="${1:-}"
if [[ ! "$audit_bastion" =~ ^[A-Za-z0-9_.@:-]+$ ]]; then
  echo "A safe SSH destination such as auth@bastion.example.org is required" >&2
  exit 2
fi

source_root="$(cd "$(dirname "$0")" && pwd)"
install -d -o root -g root -m 0755 /usr/local/lib/isolate
install -o root -g root -m 0644 "$source_root/target-command-audit.bash" /usr/local/lib/isolate/command-audit.bash
install -o root -g root -m 0644 "$source_root/target-command-audit.zsh" /usr/local/lib/isolate/command-audit.zsh

cat >/etc/profile.d/isolate-command-audit.sh <<EOF
# Managed by Isolate v2. The hook is inert outside an Isolate SSH session.
export ISOLATE_AUDIT_BASTION='$audit_bastion'
if [ -n "\${ISOLATE_CONNECTION_ID:-}" ] && [ -n "\${BASH_VERSION:-}" ]; then
  . /usr/local/lib/isolate/command-audit.bash
fi
EOF
chmod 0644 /etc/profile.d/isolate-command-audit.sh

if [[ -d /etc/zsh/zshrc.d ]]; then
  cat >/etc/zsh/zshrc.d/60-isolate-command-audit.zsh <<EOF
# Managed by Isolate v2. The hook is inert outside an Isolate SSH session.
export ISOLATE_AUDIT_BASTION='$audit_bastion'
if [[ -n "\${ISOLATE_CONNECTION_ID:-}" ]]; then
  source /usr/local/lib/isolate/command-audit.zsh
fi
EOF
  chmod 0644 /etc/zsh/zshrc.d/60-isolate-command-audit.zsh
fi

install -d -o root -g root -m 0755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/60-isolate-command-audit.conf <<'EOF'
AcceptEnv ISOLATE_CONNECTION_ID ISOLATE_HOST_ID ISOLATE_PROJECT ISOLATE_HUMAN_USER
EOF

sshd -t
if command -v systemctl >/dev/null 2>&1; then
  systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service
fi

echo "Isolate command audit hook installed. Before enabling command_audit.send_env, restrict the callback key on the bastion with:"
echo 'restrict,command="/opt/auth/scripts/isolate-command-audit-ingest.py" ssh-ed25519 AAAA... isolate-command-audit'
