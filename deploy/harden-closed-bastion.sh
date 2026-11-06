#!/usr/bin/env bash
# Closed staging only: management SSH plus DNS/DHCP/NTP, no production egress.
# ISOLATE_MANAGEMENT_IP must be the administrator's observed SSH source address.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Run as root' >&2; exit 1; }
[[ -f /opt/auth/.closed-bastion-prepared ]] || { echo 'Prepare the closed runtime first' >&2; exit 1; }
: "${ISOLATE_MANAGEMENT_IP:?Supply the observed administrator SSH source IP}"
management_user="${ISOLATE_MANAGEMENT_USER:-ubuntu}"
[[ "$management_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || exit 1
id "$management_user" >/dev/null
install -d -m 0700 /etc/isolate/staging-backup
if [[ -e /etc/ssh/sshd_config.d/00-isolate-staging.conf ]]; then
  echo 'Staging SSH policy already installed; refusing an unreviewed overwrite' >&2
  exit 1
fi
cat > /etc/ssh/sshd_config.d/00-isolate-staging.conf <<EOF
# No contractor access until realm and gateway authorization are configured.
AllowUsers ${management_user}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowTcpForwarding no
AllowStreamLocalForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
EOF
/usr/sbin/sshd -t

python3 - <<'PY'
import ipaddress
import os
from pathlib import Path
management = ipaddress.ip_network(os.environ['ISOLATE_MANAGEMENT_IP'], strict=False)
dns = []
for line in Path('/run/systemd/resolve/resolv.conf').read_text().splitlines():
    if line.startswith('nameserver '):
        address = ipaddress.ip_address(line.split()[1])
        if not address.is_loopback:
            dns.append(address)
if not dns:
    raise SystemExit('No explicit upstream DNS resolver found')
rules = [
    'table inet isolate_staging {',
    'chain input { type filter hook input priority -5; policy drop;',
    'iifname "lo" accept', 'ct state established,related accept', 'ct state invalid drop',
    '{} saddr {} tcp dport 22 accept'.format('ip' if management.version == 4 else 'ip6', management),
    'udp sport 67 udp dport 68 accept', 'ip protocol icmp accept', 'meta l4proto ipv6-icmp accept', '}',
    'chain forward { type filter hook forward priority -5; policy drop; }',
    'chain output { type filter hook output priority -5; policy drop;',
    'oifname "lo" accept', 'ct state established,related accept',
]
for address in dns:
    family = 'ip' if address.version == 4 else 'ip6'
    for protocol in ('udp', 'tcp'):
        rules.append('{} daddr {} {} dport 53 accept'.format(family, address, protocol))
rules.extend(['ip daddr 169.254.169.123 udp dport 123 accept', 'udp sport 68 udp dport 67 accept',
              'ip protocol icmp accept', 'meta l4proto ipv6-icmp accept', '}', '}'])
Path('/etc/isolate/staging.nft').write_text('\n'.join(rules) + '\n')
PY
/usr/sbin/nft --check --file /etc/isolate/staging.nft
cat > /usr/local/sbin/isolate-staging-firewall <<'EOF'
#!/bin/sh
set -eu
if /usr/sbin/nft list table inet isolate_staging >/dev/null 2>&1; then
    # Replace only our table atomically; preserve unrelated host rules.
    { printf 'delete table inet isolate_staging\n'; cat /etc/isolate/staging.nft; } | /usr/sbin/nft -f -
else
    /usr/sbin/nft -f /etc/isolate/staging.nft
fi
EOF
chmod 0700 /usr/local/sbin/isolate-staging-firewall
cat > /etc/systemd/system/isolate-staging-firewall.service <<'EOF'
[Unit]
Description=Closed Isolate staging firewall
After=network-pre.target
Before=network.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/isolate-staging-firewall
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

# Automatic recovery unless an independent new SSH connection confirms access.
cat > /etc/isolate/staging-backup/rollback.sh <<'EOF'
#!/bin/sh
/usr/sbin/nft delete table inet isolate_staging 2>/dev/null || true
systemctl disable isolate-staging-firewall.service
rm -f /etc/ssh/sshd_config.d/00-isolate-staging.conf
systemctl reload ssh.service
EOF
chmod 0700 /etc/isolate/staging-backup/rollback.sh
systemd-run --quiet --unit=isolate-staging-rollback --on-active=5m /etc/isolate/staging-backup/rollback.sh
systemctl enable --now isolate-staging-firewall.service
systemctl reload ssh.service
echo 'Closed staging firewall applied; confirm a NEW SSH connection, then stop isolate-staging-rollback.timer within five minutes.'
