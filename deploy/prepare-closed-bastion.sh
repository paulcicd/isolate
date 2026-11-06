#!/usr/bin/env bash
# Prepare a new Ubuntu bastion only. Does not create users, SSH keys or grants.
# Run as root from the uploaded source directory. Runtime requirements exclude
# optional MCP: this host intentionally exposes no MCP or Dashboard service.
set -euo pipefail

if [[ $(id -u) != 0 ]]; then
  echo 'Run as root' >&2
  exit 1
fi
source_root="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -e /opt/auth/.closed-bastion-prepared ]]; then
  echo 'Bastion already prepared; use a reviewed upgrade procedure' >&2
  exit 1
fi
if [[ -e /etc/isolate/isolate.yml || -d /opt/auth/shared ]]; then
  echo 'Existing Isolate installation detected; refusing to overwrite it' >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y python3-venv python3-pip redis-server nftables acl

getent group auth >/dev/null || groupadd --system auth
id auth >/dev/null 2>&1 || useradd --system --gid auth --home-dir /var/lib/isolate --create-home --shell /usr/sbin/nologin auth
getent group isolate-contractors >/dev/null || groupadd --system isolate-contractors
install -d -o root -g auth -m 0750 /opt/auth /etc/isolate
for directory in shared wrappers scripts tests configs deploy; do
  cp -a "$source_root/$directory" /opt/auth/
done
install -o root -g auth -m 0640 "$source_root/requirements.txt" /opt/auth/requirements.txt
python3 -m venv /opt/auth/.venv
sed '/^mcp[<>=]/d' /opt/auth/requirements.txt > /opt/auth/requirements-bastion.txt
/opt/auth/.venv/bin/python -m pip install --disable-pip-version-check -r /opt/auth/requirements-bastion.txt
/opt/auth/.venv/bin/python -m pip freeze > /opt/auth/requirements-installed.txt
chown -R root:auth /opt/auth
find /opt/auth -type d -exec chmod 0750 {} +
find /opt/auth -type f -exec chmod 0640 {} +
find /opt/auth/.venv/bin -maxdepth 1 -type f -exec chmod 0750 {} +
for directory in logs cache keys spool backups jobs; do
  install -d -o auth -g auth -m 0700 "/opt/auth/$directory"
done
install -o root -g auth -m 0640 /dev/null /opt/auth/known_hosts
install -o root -g auth -m 0640 /opt/auth/configs/closed-bastion.example.yml /etc/isolate/isolate.yml

/opt/auth/.venv/bin/python - <<'PY'
import json
import os
from pathlib import Path
import pwd
import secrets
import yaml

config_path = Path('/etc/isolate/isolate.yml')
config = yaml.safe_load(config_path.read_text())
password = secrets.token_urlsafe(48)
config['redis'] = {'host': '127.0.0.1', 'port': 6379, 'db': 0, 'username': 'isolate-runtime', 'password': password, 'socket_timeout': 3}
config_path.write_text(yaml.safe_dump(config, sort_keys=False))
auth = pwd.getpwnam('auth')
key = Path('/opt/auth/keys/audit_hmac.key')
key.write_text(secrets.token_hex(32) + '\n')
os.chmod(key, 0o600)
os.chown(key, auth.pw_uid, auth.pw_gid)
redis = pwd.getpwnam('redis')
acl = Path('/etc/redis/isolate.acl')
acl.write_text('user default off\nuser isolate-runtime on >' + password + ' ~* +@all -config -acl -shutdown -module -debug -replicaof -slaveof\n')
os.chmod(acl, 0o640)
os.chown(acl, 0, redis.pw_gid)
redis_config = Path('/etc/redis/redis.conf')
redis_config.write_text(redis_config.read_text() + '\n# Isolate closed staging\nbind 127.0.0.1 ::1\nprotected-mode yes\naclfile /etc/redis/isolate.acl\n')
PY

systemctl restart redis-server
cat > /usr/local/sbin/isolate-admin <<'EOF'
#!/bin/sh
exec /opt/auth/.venv/bin/python -I -c 'import sys; sys.path.insert(0, "/opt/auth/shared"); from isolate import main; sys.exit(main())' "$@"
EOF
cat > /usr/local/sbin/isolate-ssh <<'EOF'
#!/bin/sh
exec /opt/auth/.venv/bin/python -I /opt/auth/wrappers/ssh.py "$@"
EOF
chmod 0750 /usr/local/sbin/isolate-admin /usr/local/sbin/isolate-ssh
chown root:auth /usr/local/sbin/isolate-admin /usr/local/sbin/isolate-ssh
# No sudoers grant is installed for contractors while the realm is absent.
# The shell callback owns normal token-file cleanup. Use a dedicated timer for
# crash leftovers, without applying generic cleanup rules to all of /tmp.
cat > /etc/systemd/system/isolate-token-cleanup.service <<'EOF'
[Unit]
Description=Remove abandoned Isolate authorization files
[Service]
Type=oneshot
ExecStart=/usr/bin/find /tmp -maxdepth 1 -type f -name isolate-authorization-* -mmin +60 -delete
EOF
cat > /etc/systemd/system/isolate-token-cleanup.timer <<'EOF'
[Unit]
Description=Clean abandoned Isolate authorization files
[Timer]
OnBootSec=10min
OnUnitActiveSec=15min
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now isolate-token-cleanup.timer
bash /opt/auth/deploy/install-audit-export.sh
touch /opt/auth/.closed-bastion-prepared
chmod 0640 /opt/auth/.closed-bastion-prepared
echo 'Closed bastion runtime prepared. Contractor login and forwarding must remain disabled.'
