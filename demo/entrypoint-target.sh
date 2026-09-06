#!/usr/bin/env bash
set -euo pipefail

ssh-keygen -A

for attempt in $(seq 1 60); do
  if [[ -s /demo/audit-ssh/id_ed25519 && -s /demo/audit-ssh/bastion_id_ed25519.pub ]]; then
    break
  fi
  if [[ "$attempt" -eq 60 ]]; then
    echo "Demo SSH key volume was not initialized" >&2
    exit 1
  fi
  sleep 1
done

bastion_public_key="$(cat /demo/audit-ssh/bastion_id_ed25519.pub)"
for username in support dev dba; do
  echo "${username}:demo-target-password-disabled" | chpasswd
  install -d -o "$username" -g "$username" -m 0700 "/home/$username/.ssh"
  printf '%s\n' "$bastion_public_key" > "/home/$username/.ssh/authorized_keys"
  chown "$username:$username" "/home/$username/.ssh/authorized_keys"
  chmod 0600 "/home/$username/.ssh/authorized_keys"
done

install -o root -g isolate-audit -m 0640 /demo/audit-ssh/id_ed25519 /etc/isolate-audit/id_ed25519
cat > /etc/ssh/ssh_config.d/60-isolate-command-audit.conf <<'EOF'
Host bastion
    User auth
    IdentityFile /etc/isolate-audit/id_ed25519
    IdentitiesOnly yes
    StrictHostKeyChecking accept-new
    UserKnownHostsFile /var/lib/isolate-audit/known_hosts
    LogLevel ERROR
EOF
touch /var/lib/isolate-audit/known_hosts
chown root:isolate-audit /var/lib/isolate-audit/known_hosts
chmod 0664 /var/lib/isolate-audit/known_hosts

cat > /etc/profile.d/isolate-command-audit.sh <<'EOF'
export ISOLATE_AUDIT_BASTION=auth@bastion
if [[ -n "${ISOLATE_CONNECTION_ID:-}" && -n "${BASH_VERSION:-}" ]]; then
  . /usr/local/lib/isolate/command-audit.bash
fi
EOF
chmod 0644 /etc/profile.d/isolate-command-audit.sh

printf 'Isolate demo target: %s\n' "${DEMO_TARGET_NAME:-unknown}" > /etc/motd
echo "Target ${DEMO_TARGET_NAME:-unknown} is ready"
exec /usr/sbin/sshd -D -e
