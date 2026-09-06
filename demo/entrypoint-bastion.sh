#!/usr/bin/env bash
set -euo pipefail

echo 'alice:demo123' | chpasswd
echo 'bob:demo123' | chpasswd
echo "auth:$(openssl rand -hex 32)" | chpasswd
ssh-keygen -A

bash --norc /opt/auth/scripts/fix-perms.sh
install -d -o auth -g auth -m 0700 /home/auth/.ssh

audit_public_key="$(cat /opt/auth/keys/command_audit_id_ed25519.pub)"
printf 'restrict,command="/opt/auth/scripts/isolate-command-audit-ingest.py" %s\n' "$audit_public_key" > /home/auth/.ssh/authorized_keys
chown auth:auth /home/auth/.ssh/authorized_keys
chmod 0600 /home/auth/.ssh/authorized_keys

python3 /opt/auth/demo/seed.py

known_hosts_tmp="$(mktemp)"
for address in 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14 172.30.50.15; do
  for attempt in $(seq 1 30); do
    if ssh-keyscan -T 2 -H "$address" >> "$known_hosts_tmp" 2>/dev/null; then
      break
    fi
    if [[ "$attempt" -eq 30 ]]; then
      echo "Target $address did not expose SSH" >&2
      exit 1
    fi
    sleep 1
  done
done
install -o auth -g auth -m 0600 "$known_hosts_tmp" /opt/auth/known_hosts
rm -f "$known_hosts_tmp"

for attempt in $(seq 1 60); do
  if runuser -u auth -- /opt/auth/shared/isolate.py jwks refresh >/dev/null 2>&1; then
    break
  fi
  if [[ "$attempt" -eq 60 ]]; then
    echo "Keycloak JWKS was not ready after 120 seconds" >&2
    exit 1
  fi
  sleep 2
done

echo "Isolate demo bastion is ready on localhost:2222"
exec /usr/sbin/sshd -D -e
