# Isolate Bastion Platform v2

Optional native SSH, Web SSH and API console migration:
[deployment guide](deploy/GATEWAY-MIGRATION.md),
[identity and credentials](deploy/IDENTITY-CREDENTIALS.md),
[protocol adapters](deploy/PROTOCOL-ADAPTERS.md),
[cluster operations](deploy/CLUSTER.md).

> Для быстрого локального запуска bastion, Keycloak, Redis, dashboard и пяти SSH targets используйте [Docker demo](demo/README.md).

Isolate Bastion Platform v2 is an SSH bastion access layer for large Linux fleets. It keeps the familiar `s` and `g` workflow while adding modern identity, policy, audit, temporary access, and dashboard capabilities.

The main idea is simple:

1. A human user logs in to the bastion.
2. The user runs `isolate login` and authenticates through Keycloak.
3. Isolate verifies the signed Keycloak JWT on every command and derives `username`, `groups`, and `roles` only from verified claims.
4. The `s` command shows only servers allowed by grants.
5. The `g` command checks policy, selects the correct remote user, and starts SSH.
6. Every step is written to JSONL audit logs and legacy raw transcripts.

All examples in this document use fictional users, groups, domains, projects, and hosts.

## Feature Overview

- Ubuntu 24.04 LTS and Debian 12/13 compatible bastion runtime.
- Python 3 runtime.
- Redis-backed host inventory, grants, project sets, access requests, and active sessions.
- Keycloak OIDC Device Authorization Grant for CLI login.
- Keycloak OIDC Authorization Code flow for the admin dashboard.
- Grant-based RBAC using Keycloak groups.
- Project sets and glob patterns for managing hundreds of projects.
- Per-group or per-user remote SSH user selection.
- Optional `sudo-i` or no-sudo remote shell behavior.
- Deny-by-default access model.
- Break-glass temporary access requests with approval and TTL.
- Connection history through `f` and `isolate history`.
- Active session registry.
- JSONL audit logs and legacy raw SSH transcripts.
- Lightweight Flask admin dashboard.
- Resource catalogue with owners, environments, effective access windows, and connection instructions.
- Project-scoped management roles for approvals, inventory operations, and audit.
- Optional single-use approvals of individual SSH connections, including two-person privileged approval.
- User web workspace for allowed hosts, personal sessions, history, and access requests.
- Structured host tags, CLI runbook fleets, scheduled access windows, and service change history.
- Safer SSH argv construction through `subprocess` arguments.
- Permission repair workflow for Git deploys.
- Verifiable service backups for configuration, credentials, host keys, and Redis state.
- Keycloak-protected MCP interface for policy-aware AI and automation clients.

## Concepts

### Human User

The real person using the bastion. Example fictional users:

- `demo.alex`
- `demo.bailey`
- `demo.casey`
- `demo.drew`

Human identity comes from Keycloak after `isolate login`.

### Remote User

The Linux account used on the target server. Examples:

- `support`
- `dba`
- `dev`
- `l2-support`
- `root`

The remote user is selected by grants, not by the local Linux username on the bastion.

### Project

A logical group of servers. Examples:

- `demo-prod`
- `demo-stage`
- `kube-prod`
- `payments-prod`
- `analytics-stage`

Every host record belongs to one project.

### Project Set

A reusable named selector for many projects. A project set can contain exact project names and glob patterns.

Example:

```bash
isolate project-set add prod-all --project demo-prod --project payments-prod
isolate project-set add-pattern prod-all --project-glob '*-prod'
```

### Grant

A rule that maps a Keycloak subject to allowed infrastructure and a remote SSH user.

Example:

```bash
isolate grant add --group Demo-DBA --project-set prod-all --remote-user dba --sudo-mode none
```

This means: users in Keycloak group `Demo-DBA` may connect to projects in `prod-all` as remote Linux user `dba`, without running remote `sudo -i`.

### Break-Glass Access

A temporary access request approved by an admin. Approved requests create temporary grants with an expiration timestamp.

Example:

```bash
isolate access request --project payments-prod --host 10042 --remote-user dba --sudo-mode none --reason DEMO-INC-1001
isolate access approve --id 1 --ttl 2h
```

## Requirements

### Bastion Host

Recommended target:

- Ubuntu 24.04 LTS
- Debian 12 or Debian 13

Required packages:

- Python 3
- Redis
- OpenSSH server and client
- Git
- Ansible for deployment

Install deployment dependencies:

```bash
apt update
apt install -y ansible git python3 python3-dev python3-pip python3-venv redis-tools
```

Install Python runtime dependencies:

```bash
python3 -m pip install --break-system-packages -r /opt/auth/requirements.txt
```

Dependencies are declared in `requirements.txt`:

- `redis`
- `pyzabbix`
- `geoip2`
- `PyYAML`
- `Flask`
- `Authlib`
- `joserfc` for non-deprecated local JWT/JWKS verification
- `gunicorn`
- official `mcp` Python SDK v2

## Repository Layout

Typical runtime checkout:

```text
/opt/auth
├── ansible/
├── configs/
│   ├── isolate.yml
│   └── defaults.conf
├── keys/
├── logs/
├── scripts/
│   └── fix-perms.sh
├── shared/
│   ├── bash.sh
│   ├── zsh.sh
│   ├── helper.py
│   ├── isolate.py
│   ├── isolate_access.py
│   ├── isolate_config.py
│   ├── isolate_history.py
│   ├── isolate_identity.py
│   ├── isolate_logging.py
│   ├── isolate_mcp.py
│   ├── isolate_policy.py
│   ├── isolate_sessions.py
│   ├── isolate_ssh.py
│   └── isolate_web.py
└── wrappers/
    └── ssh.py
```

Important paths:

- `/opt/auth/shared/isolate.py`: main CLI.
- `/opt/auth/shared/helper.py`: shell helper for `s`, `g`, and `p`.
- `/opt/auth/wrappers/ssh.py`: SSH wrapper executed as service user `auth`.
- `/opt/auth/configs/isolate.yml`: main config.
- `/opt/auth/configs/defaults.conf`: OpenSSH client defaults.
- `/opt/auth/logs`: JSONL audit logs and raw transcripts.
- `/opt/auth/scripts/fix-perms.sh`: permission repair script after deploy or Git update.

## Quick Deploy

### 1. Prepare Ansible Inventory

Edit `ansible/hosts.ini`:

```ini
[main]
bastion-01.example.org ansible_ssh_host=203.0.113.10 ansible_ssh_port=22 ansible_ssh_user=root
```

### 2. Run The Playbook

```bash
cd ansible
ansible-playbook main.yml -e redis_pass='CHANGE_ME_STRONG_PASSWORD'
```

The playbook should:

- create the `auth` service user;
- install Redis and system packages;
- deploy the repository to `/opt/auth`;
- install Python dependencies;
- configure sudo wrapper access;
- apply file permissions.

### 3. Enable Git Permission Repair Hooks

Git does not preserve the runtime permission model. Enable hooks and run permission repair:

```bash
cd /opt/auth
git config core.hooksPath .githooks
sudo bash /opt/auth/scripts/fix-perms.sh
```

After manual updates, run:

```bash
git pull
python3 -m pip install --break-system-packages -r /opt/auth/requirements.txt
sudo bash /opt/auth/scripts/fix-perms.sh
```

Also run it after:

```bash
git reset --hard origin/master
git checkout <branch>
```

### Production Update And Downtime

`git pull` alone is not a complete production update. CLI processes load updated Python files on their next invocation, but the dashboard, MCP server, and job worker are long-running processes. A release may also change Python dependencies, systemd units, or required permissions.

For the current in-place deployment, use this maintenance sequence:

```bash
cd /opt/auth
sudo -u auth git fetch --prune
sudo -u auth git pull --ff-only
python3 -m pip install --break-system-packages -r /opt/auth/requirements.txt
sudo bash /opt/auth/scripts/fix-perms.sh

PYTHONPYCACHEPREFIX=/tmp/isolate-pycache python3 -m compileall shared wrappers tests
PYTHONPYCACHEPREFIX=/tmp/isolate-pycache python3 -m unittest discover -s tests
sudo -u auth /opt/auth/shared/isolate.py config validate --check-paths

sudo systemctl reload isolate-dashboard.service
sudo systemctl restart isolate-mcp.service isolate-job-worker.service
```

Gunicorn dashboard reload is graceful because the supplied systemd unit sends `HUP`: new workers start before old workers finish current requests. Existing SSH sessions are separate wrapper/SSH processes and continue running with the code they already loaded. Restarting MCP and the job worker causes a short control-plane interruption; queued job records remain in Redis and are picked up after restart, while a running remote command must be checked before restarting the worker.

For strict zero-downtime releases, do not update `/opt/auth` in place. Build an immutable release and virtual environment under `/opt/isolate/releases/<git-sha>`, run preflight checks there, switch a `current` symlink, and roll two dashboard/MCP instances behind the reverse proxy one at a time. Keep Redis schemas backward-compatible across the old and new process versions, drain the job worker before switching it, and roll back by restoring the previous symlink. This release-slot workflow is recommended for a later deployment automation iteration; the current repository does not claim zero-downtime MCP/worker restarts.

## Shell Integration

### Bash

Add to `/etc/bash.bashrc`:

```bash
if [ -f /opt/auth/shared/bash.sh ]; then
    source /opt/auth/shared/bash.sh
fi
```

Reload:

```bash
source /etc/bash.bashrc
```

### Zsh

Add to `/etc/zsh/zshrc` or the relevant system zsh config:

```bash
if [ -f /opt/auth/shared/zsh.sh ]; then
    source /opt/auth/shared/zsh.sh
fi
```

Reload:

```bash
source /opt/auth/shared/zsh.sh
```

### Shell Commands Added

The shell integration exposes:

```bash
s <query>
g <project|host> [server]
p
f [query]
isolate <subcommand>
```

## Sudo Wrapper

The SSH wrapper runs as Unix user `auth`. Add this through `visudo`:

```sudoers
%auth ALL=(auth) NOPASSWD: /opt/auth/wrappers/ssh.py
```

All bastion users who should use Isolate must be members of Unix group `auth`.

Example:

```bash
usermod -aG auth demo-user
id demo-user
```

## SSH Daemon Baseline

Recommended `/etc/ssh/sshd_config` baseline:

```sshconfig
PasswordAuthentication yes
GSSAPIAuthentication no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
UseDNS no
TCPKeepAlive yes
ClientAliveInterval 36
ClientAliveCountMax 2400
UsePAM yes
```

Restart SSH:

```bash
systemctl restart ssh
systemctl status ssh
```

## Main Configuration

Isolate reads config from:

1. `/etc/isolate/isolate.yml`
2. `/opt/auth/configs/isolate.yml`

You can override the path:

```bash
export ISOLATE_CONFIG=/custom/path/isolate.yml
```

### Full Example Config

```yaml
schema_version: 2
data_root: /opt/auth

redis:
  host: 127.0.0.1
  port: 6379
  db: 0
  username: null
  password: CHANGE_ME_STRONG_PASSWORD
  ssl: false
  ssl_ca_certs: null
  ssl_certfile: null
  ssl_keyfile: null
  ssl_check_hostname: true
  socket_timeout: 3

keycloak:
  issuer: https://keycloak.example.org/realms/demo-infra
  client_id: isolate-bastion
  client_secret: CHANGE_ME_CLIENT_SECRET
  scopes:
    - openid
    - profile
    - email
    - groups
  poll_timeout: 300
  tls_verify: true
  verify_tokens: true
  expected_audience: isolate-bastion
  jwks_cache_path: /opt/auth/cache/keycloak_jwks.json
  jwks_cache_ttl: 3600

ssh:
  binary: /usr/bin/ssh
  config_path: /opt/auth/configs/defaults.conf
  allocate_tty: true
  allow_unknown_args: false
  allowed_extra_args:
    - -4
    - -6
    - -A
    - -a
    - -C
    - -v
    - -vv
    - -vvv
  default_sudo_mode: sudo-i
  fallback_remote_user: null

logging:
  base_path: /opt/auth/logs
  jsonl_name: session.jsonl
  sink: local
  fail_closed: false
  retention_days: 90
  sinks: []
  integrity:
    enabled: false
    key_file: /opt/auth/keys/audit_hmac.key
    key_id: isolate-audit-v1

history:
  admin_groups:
    - Demo-DevOps
    - Demo-Security
  default_limit: 10
  max_limit: 100

access:
  admin_groups:
    - Demo-DevOps
    - Demo-Security
  default_ttl: 2h
  max_ttl: 24h
  ticket_required: false
  ticket_pattern: "^(INC|CHG)-[0-9]+$"
  request_templates:
    dba-prod:
      remote_user: dba
      sudo_mode: none
      ttl: 2h

dashboard:
  enabled: true
  listen_host: 127.0.0.1
  listen_port: 8080
  public_url: https://bastion.example.org
  secret_key_file: /opt/auth/keys/dashboard_secret
  refresh_seconds: 15
  jobs_max_results: 250
  default_locale: en
  admin_groups:
    - Demo-DevOps
    - Demo-Security

build:
  version: 2.1.0
  revision: null
  built_at: null

access_packages:
  enabled: true
  max_rules: 50
  max_assignments_per_operation: 100

notifications:
  enabled: true
  timeout_seconds: 5
  fail_closed: false
  sinks:
    - type: webhook
      url: https://hooks.example.org/isolate
      headers:
        Authorization: "Bearer CHANGE_ME"
    - type: telegram
      bot_token: CHANGE_ME_TELEGRAM_BOT_TOKEN
      chat_id: "-1001234567890"
      parse_mode: HTML
    - type: email
      smtp_host: smtp.example.org
      smtp_port: 587
      starttls: true
      username: isolate@example.org
      password: CHANGE_ME_SMTP_PASSWORD
      from: isolate@example.org
      to:
        - devsecops@example.org

command_audit:
  enabled: false
  require_connection_id: true
  max_command_length: 4096

replay:
  max_bytes: 10485760
  default_speed: 1

policy:
  default_allowed_actions:
    - ssh
  fallback_remote_user: null

policy_as_code:
  bundle_path: /opt/auth/configs/policy.yml
  backup_dir: /opt/auth/backups
  require_confirmation: true
```

### Environment Overrides

Supported environment variables:

```bash
export ISOLATE_CONFIG=/opt/auth/configs/isolate.yml
export ISOLATE_DATA_ROOT=/opt/auth
export ISOLATE_REDIS_HOST=127.0.0.1
export ISOLATE_REDIS_PORT=6379
export ISOLATE_REDIS_DB=0
export ISOLATE_REDIS_PASS='CHANGE_ME_STRONG_PASSWORD'
# Optional when Redis ACL/TLS is configured:
# export ISOLATE_REDIS_USER='isolate'
# export ISOLATE_REDIS_SSL=true
# export ISOLATE_REDIS_CA_CERT='/etc/isolate/redis-ca.pem'
export ISOLATE_KEYCLOAK_ISSUER='https://keycloak.example.org/realms/demo-infra'
export ISOLATE_KEYCLOAK_CLIENT_ID='isolate-bastion'
export ISOLATE_KEYCLOAK_CLIENT_SECRET='CHANGE_ME_CLIENT_SECRET'
```

## SSH Client Defaults

OpenSSH client defaults live in `/opt/auth/configs/defaults.conf`:

```sshconfig
Host *
    StrictHostKeyChecking accept-new
    UserKnownHostsFile /opt/auth/known_hosts
    TCPKeepAlive yes
    ServerAliveInterval 40
    ServerAliveCountMax 3
    ConnectTimeout 180
    ForwardAgent no
    User support
    Port 22
    IdentityFile /home/auth/.ssh/id_rsa
```

Important notes:

- `StrictHostKeyChecking accept-new` is safer than global `no`.
- `IdentityFile /home/auth/.ssh/id_rsa` means the bastion service key is used for remote SSH.
- If grants use remote users such as `dba`, `dev`, or `l2-support`, the public key `/home/auth/.ssh/id_rsa.pub` must exist in each remote user's `authorized_keys`.

Example target setup:

```bash
mkdir -p /home/dba/.ssh
cat /tmp/isolate_id_rsa.pub >> /home/dba/.ssh/authorized_keys
chown -R dba:dba /home/dba/.ssh
chmod 700 /home/dba/.ssh
chmod 600 /home/dba/.ssh/authorized_keys
```

## Keycloak Setup

### CLI Login Client

For `isolate login`, configure a Keycloak OIDC client:

- Client type: OpenID Connect.
- Client authentication: ON for confidential client or OFF for public client.
- OAuth 2.0 Device Authorization Grant: ON.
- Standard flow: optional for CLI, required if the same client is used for dashboard.
- Direct access grants: OFF unless explicitly needed.
- Implicit flow: OFF.
- Service account roles: optional.
- Scopes: `openid`, `profile`, `email`, `groups`.
- Ensure `groups` are included in token claims.

### Dashboard Login Client

For the dashboard, use Authorization Code flow.

Required callback:

```text
https://bastion.example.org/auth/callback
```

If testing locally:

```text
http://127.0.0.1:8080/auth/callback
```

Dashboard access is allowed only for users whose Keycloak groups match:

```yaml
dashboard:
  admin_groups:
    - Demo-DevOps
    - Demo-Security
```

### Trusted JWKS Cache

Isolate verifies the signed `id_token` locally for every `s`, `g`, `f`, and protected admin command. Public signing keys are read from the Keycloak JWKS endpoint and cached in:

```text
/opt/auth/cache/keycloak_jwks.json
```

The cache must not be writable by ordinary bastion users. After deploy, refresh it as root or as the `auth` service user:

```bash
sudo -u auth /opt/auth/shared/isolate.py jwks refresh
```

If the cache is missing, Isolate can fetch JWKS over HTTPS at runtime, but preloading the cache avoids extra network calls on every command.

## User Login Flow

Run:

```bash
isolate login
```

The command prints a verification URL and user code:

```text
Open this URL to authorize Isolate:
https://keycloak.example.org/realms/demo-infra/device?user_code=ABCD-EFGH
Code: ABCD-EFGH
```

After approval, Isolate saves a token cache to:

```text
~/.isolate/identity.json
```

The cache contains tokens and display-only fields. Authorization does not trust editable cached `groups`; it verifies the signed JWT and extracts claims from the verified token.

Example verified identity shown by `isolate whoami`:

```json
{
  "username": "demo.alex",
  "email": "demo.alex@example.org",
  "keycloak_sub": "00000000-0000-0000-0000-000000000001",
  "groups": ["Demo-DevOps", "Demo-DBA"],
  "roles": ["demo-admin"],
  "session_id": "11111111-1111-1111-1111-111111111111"
}
```

Check current identity:

```bash
isolate whoami
```

Logout:

```bash
isolate logout
```

If token cache is missing, legacy, invalid, tampered, or expired, `s`, `g`, `f`, and protected admin commands will ask the user to run `isolate login`.

## Host Inventory

Hosts are stored in Redis as `server_*` records.

### Add Host

```bash
auth-add-host \
  --project kube-prod \
  --server-name control-plane-01 \
  --ip 192.0.2.41 \
  --port 22 \
  --user support \
  --services "api-server, etcd, scheduler" \
  --note "control-plane entrypoint"
```

Arguments:

- `--project`: project name.
- `--server-name`: friendly host name.
- `--ip`: target server IP address.
- `--port`: target SSH port.
- `--user`: default remote user from legacy config.
- `--nosudo`: legacy flag to avoid remote `sudo -i`.
- `--services`: optional free-form service inventory shown by `s`.
- `--note`: optional free-form host note.

Example searchable output:

```text
kube-prod
------
10004  | 192.0.2.41      | control-plane-01  | api-server, etcd, scheduler
```

Search can match services and notes:

```bash
s etcd
s kube-prod scheduler
```

`g` remains conservative: it connects by exact `server_id`, `server_name`, or `server_ip`, not by service/note matches.

### Inventory Admin CLI

List hosts:

```bash
isolate host list
isolate host list --project kube-prod
isolate host list --query redis
isolate host list --json
```

Show a host:

```bash
isolate host show 10004
```

Update only selected fields:

```bash
isolate host update 10004 --services "api-server, etcd, scheduler"
isolate host update 10004 --note "VIP frontend"
isolate host update 10004 --name control-plane-02
isolate host update 10004 --ip 192.0.2.42 --port 22
isolate host update 10004 --user support --nosudo true
isolate host update 10004 \
  --vip true \
  --privileged-provider Warpgate \
  --privileged-url https://warpgate.example.org \
  --privileged-hint "Use external bastion for sudo/root access"
```

`isolate host update` preserves all fields that were not passed and updates `updated_by` / `updated_at`.

Resource metadata can be managed separately from SSH routing and credentials:

```bash
isolate host update 10004 --owner "Payments Operations" --environment production
```

These fields are stored as `resource_owner` (up to 128 printable characters) and
`environment` (up to 64). Empty fields fall back to the host's `owner` and `env`
tags for catalogue display. They are searchable and included in inventory exports.

### Structured Host Tags

Hosts can carry exact string tags such as `env=prod`, `owner=payments`, and `region=nsk`:

```bash
isolate host update 10004 --tag env=prod --tag owner=payments --tag region=nsk
isolate host list --project kube-prod --tag env=prod --tag region=nsk
isolate export inventory --tag env=prod --format csv --output prod-hosts.csv
isolate host update 10004 --remove-tag region
isolate host update 10004 --clear-tags
```

Repeated `--tag key=value` selectors use exact AND matching. CLI updates merge supplied
tags with the host's existing mapping; `--remove-tag` removes named keys and
`--clear-tags` starts from an empty mapping. Conflicting values for the same selector
are rejected. Tags select inventory and fleets; they do not grant access.

Dashboard Inventory supports tag filtering and tag fields on create/edit forms;
inventory CSV/JSON download links preserve the selected filters.
Its bulk tag field replaces the complete mapping for every selected host; leave it
blank to preserve existing tags, or use the explicit clear-tags control to remove
them. A full host edit also replaces the tag mapping with the submitted field.

VIP and privileged access fields are informational. They do not change grants by themselves. Use them to document that ordinary non-sudo SSH access stays in Isolate, while sudo/root access is handled by an external privileged access provider such as Warpgate, Teleport, PAM, or another bastion.

If a VIP host is denied by policy and privileged access metadata is configured, `g` prints a hint with the external provider and URL.

### Maintenance Mode

Temporarily pause new connections to an inventory host without removing it or changing grants:

```bash
isolate host maintenance 10004 --until 2h --reason "CHG-1042 database migration"
isolate host maintenance 10004 --clear
```

`s` marks an active maintenance host as `MAINT`. `g` prints the reason and refuses a new connection. Existing SSH sessions are not terminated. Maintenance expires automatically when `maintenance_until` is reached. Emergency bypass groups must be explicitly configured:

```yaml
maintenance:
  enforce: true
  bypass_groups:
    - OS-admin
```

Legacy host records have no maintenance fields and remain available exactly as before.

### Connectivity Diagnostics

Check DNS resolution and the target TCP port without opening an interactive shell:

```bash
isolate host check 10004
isolate host check --project kube-prod --timeout 5
```

Add a non-interactive public-key authentication probe when required:

```bash
isolate host check 10004 --ssh
isolate host check 10004 --ssh --user support --json
```

The SSH probe always uses `BatchMode=yes`, disables TTY allocation, honors the configured SSH file and host-key policy, and executes only `true`. Results are cached briefly as `host_check_<server_id>` for dashboard display; these operational cache keys are not part of backups.

### Operational Announcements

Publish a global, project, or host-specific notice. Active notices are shown by `s` and immediately before `g` starts a connection:

```bash
isolate announcement add --text "Bastion maintenance at 22:00" --severity info --ttl 4h
isolate announcement add --project kube-prod --text "Deploy window is active" --severity warning --ttl 2h
isolate announcement add --host 10004 --text "Do not restart etcd" --severity critical --ttl 30m
isolate announcement list --active
isolate announcement remove --id 7
```

Creating and removing announcements requires membership in `access.admin_groups`. Records use `announcement_*` Redis keys and are included in service backups.

### Portable Exports

Inventory, grants, history, observed users, and the effective access matrix can be exported to JSON or CSV:

```bash
isolate export inventory --format csv --output inventory.csv
isolate export grants --project kube-prod --format json --output grants.json
isolate export history --user demo.alex --format csv --output history.csv
isolate export users --format json
isolate export access-matrix --format csv --output access-matrix.csv
```

History export keeps the existing self/admin visibility rules. Dashboard administrators can download the same datasets from authenticated `/export/<kind>` routes.

### User Activity Summary

Users can inspect their own recent activity; configured history/dashboard admins can inspect another user:

```bash
isolate user activity
isolate user activity demo.alex
isolate user activity demo.alex --limit 25 --json
```

The summary joins already available audit data: observed groups and roles, active/recent sessions, failure count, top projects, matching grant candidates, and break-glass requests. It does not create a second identity source and never trusts editable local groups.

### Show Host

```bash
auth-dump-host 10004
```

### Delete Host

```bash
auth-del-host 10004
```

### Project Defaults

Add defaults for a project:

```bash
auth-add-project-config kube-prod --port 22 --user support
```

Show:

```bash
auth-dump-project-config kube-prod
```

Delete:

```bash
auth-del-project-config kube-prod
```

## User Commands

### Search: `s`

Search visible servers:

```bash
s .
s kube
s control-plane
s 192.0.2.41
s 10004
```

Behavior:

- `s` reads current Keycloak identity.
- It loads grants and project sets.
- It shows only allowed hosts.
- Without a matching grant, the host is hidden.

### Connect: `g`

Connect by server id:

```bash
g 10004
```

Connect by project and server name:

```bash
g kube-prod control-plane-01
```

Connect by project and IP:

```bash
g kube-prod 192.0.2.41
```

Useful flags:

```bash
g 10004 --debug
g 10004 --nosudo
g 10004 -v
g 10004 -vvv
```

Important:

- The final remote user is selected by grant policy.
- `--nosudo` disables remote `sudo -i` for this connection.
- Grant `--sudo-mode none` makes no-sudo behavior the default for that grant.
- Grant `--sudo-mode sudo-i` runs remote `sudo -i`, which requires passwordless sudo on the target remote user.

### Projects: `p`

Show visible projects:

```bash
p
```

### History: `f`

Show your last connections:

```bash
f
```

Search your history:

```bash
f kube-prod
f 10004
f control-plane
```

Admins can search other users:

```bash
f demo.alex
```

Equivalent CLI:

```bash
isolate history
isolate history kube-prod
isolate history --user demo.alex
isolate history --project kube-prod --limit 20
isolate history --host 10004 --json
```

## Project Sets

Project sets make grants manageable at scale.

### Add Exact Projects

```bash
isolate project-set add prod-all --project kube-prod --project payments-prod
```

### Add Glob Pattern

```bash
isolate project-set add-pattern prod-all --project-glob '*-prod'
```

Equivalent:

```bash
isolate project-set add prod-all --project-glob '*-prod'
```

### List Project Sets

```bash
isolate project-set list
isolate project-set list --json
```

### Show Project Set

```bash
isolate project-set show prod-all
```

Example output:

```json
{
  "schema_version": 2,
  "name": "prod-all",
  "projects": ["kube-prod", "payments-prod"],
  "project_globs": ["*-prod"]
}
```

### Remove Exact Project

```bash
isolate project-set remove-project prod-all payments-prod
```

### Remove Glob Pattern

```bash
isolate project-set remove-pattern prod-all '*-legacy'
```

### Remove Whole Project Set

```bash
isolate project-set remove prod-all
```

## Grants

Grants are Redis records named `grant_<id>`.

### Add Group Grant For One Project

```bash
isolate grant add \
  --group Demo-DBA \
  --project payments-prod \
  --remote-user dba \
  --sudo-mode none
```

### Add Group Grant For Project Set

```bash
isolate grant add \
  --group Demo-DevOps \
  --project-set prod-all \
  --remote-user support \
  --sudo-mode none
```

### Add Group Grant With Glob

```bash
isolate grant add \
  --group Demo-Analytics \
  --project-glob 'analytics-*' \
  --remote-user data-support \
  --sudo-mode none
```

### Add Global Group Grant

```bash
isolate grant add \
  --group Demo-Platform-Admins \
  --project '*' \
  --remote-user root \
  --sudo-mode none
```

### Add User Override

```bash
isolate grant add \
  --user demo.casey \
  --project kube-prod \
  --host 10004 \
  --remote-user root \
  --sudo-mode none
```

### Grant Arguments

- `--user`: exact Keycloak username.
- `--group`: exact Keycloak group name.
- `--project`: exact project or `*`.
- `--project-glob`: glob pattern such as `*-prod`.
- `--project-set`: named project set.
- `--host`: server id, server name, or IP.
- `--remote-user`: Linux user on the target host.
- `--sudo-mode`: `none` or `sudo-i`.
- `--allowed-action`: defaults to `ssh`.

### List Grants

```bash
isolate grant list
isolate grant list --group Demo-DBA
isolate grant list --user demo.casey
isolate grant list --project payments-prod
isolate grant list --project-set prod-all
isolate grant list --json
```

### Show Grant

```bash
isolate grant show --id 7
```

### Update Grant

```bash
isolate grant update --id 7 --remote-user l2-support
isolate grant update --id 7 --sudo-mode none
isolate grant update --id 7 --project-set prod-all
isolate grant update --id 7 --host 10004
```

### Revoke Grant

By id:

```bash
isolate grant revoke --id 7
```

By selector:

```bash
isolate grant revoke --group Demo-DBA --project payments-prod
isolate grant revoke --group Demo-Analytics --project-glob 'analytics-*'
isolate grant revoke --user demo.casey --project kube-prod --host 10004
```

### Test Grant Resolution

```bash
isolate grant test \
  --user demo.alex \
  --group Demo-DBA \
  --project payments-prod \
  --host 10042
```

Expected output contains:

```json
{
  "remote_user": "dba",
  "sudo_mode": "none",
  "matched_rule": {
    "subject": "group",
    "name": "Demo-DBA"
  }
}
```

### Explain Grant Resolution

Use explain for troubleshooting real access decisions:

```bash
isolate grant explain \
  --user demo.alex \
  --group Demo-DBA \
  --project payments-prod \
  --host 10042
```

Allowed output includes matched grant metadata:

```json
{
  "allowed": true,
  "remote_user": "dba",
  "sudo_mode": "none",
  "matched_grant": {
    "id": "42",
    "subject": "group",
    "name": "Demo-DBA"
  }
}
```

Denied output includes a ready break-glass request hint:

```json
{
  "allowed": false,
  "reason": "no matching grant for project 'payments-prod'",
  "suggested_request": "isolate access request --project payments-prod --host 10042 --reason <reason>"
}
```

### Grant Precedence

More specific rules win:

1. user + host
2. user + project
3. group + host
4. group + project
5. project set
6. project glob

If nothing matches, access is denied.

Expired temporary grants are ignored.

## Recommended RBAC Design

Example fictional Keycloak groups:

- `Demo-DevOps`
- `Demo-Security`
- `Demo-DBA`
- `Demo-Developers`
- `Demo-Analytics`
- `Demo-ReadOnly`

Example mapping:

| Keycloak group | Project selector | Remote user | Sudo mode | Purpose |
| --- | --- | --- | --- | --- |
| `Demo-DevOps` | `prod-all` | `support` | `none` | Production operations |
| `Demo-Security` | `*` | `security-audit` | `none` | Audit and investigation |
| `Demo-DBA` | `db-prod` | `dba` | `none` | Database access |
| `Demo-Developers` | `*-stage` | `dev` | `none` | Staging access |
| `Demo-Analytics` | `analytics-*` | `data-support` | `none` | Analytics hosts |

Example commands:

```bash
isolate project-set add prod-all --project-glob '*-prod'
isolate project-set add db-prod --project payments-db-prod --project analytics-db-prod

isolate grant add --group Demo-DevOps --project-set prod-all --remote-user support --sudo-mode none
isolate grant add --group Demo-Security --project '*' --remote-user security-audit --sudo-mode none
isolate grant add --group Demo-DBA --project-set db-prod --remote-user dba --sudo-mode none
isolate grant add --group Demo-Developers --project-glob '*-stage' --remote-user dev --sudo-mode none
```

## Access Packages

Access Packages are reusable, administrator-defined access profiles. A package can have any meaningful internal name, such as `Support Read-Only`, `DBA Production`, or `DevOps VIP`, and may contain several project/project-set/glob rules with different remote users and actions. It also defines assignment lifetime and an approval route.

Packages do not introduce a second policy engine. An assignment materializes normal `grant_*` records, so `s`, `g`, MCP, jobs, the dashboard matrix, and `grant explain` continue to use the existing resolver. Generated grants carry `managed_by: access_package` and cannot be edited or revoked through the low-level grant UI; update the package or revoke its assignment instead.

Example package file, using fictional identities and projects:

```yaml
name: Support Read-Only
description: Read-only diagnostics for production application services
status: enabled
access:
  - id: app-production
    project_set: prod-apps
    remote_user: support
    sudo_mode: none
    allowed_actions: [ssh, runbook]
  - id: staging-command
    project_glob: "*-stage"
    remote_user: dev
    sudo_mode: none
    allowed_actions: [ssh, command, runbook]
lifecycle:
  default_ttl: 7d
  max_ttl: 30d
  permanent_allowed: true
approval:
  required: true
  admin_groups: [Demo-DevSecOps, Demo-OS-Admin]
  ticket_required: true
  minimum_approvals: 1
```

Create and inspect a package:

```bash
isolate package create --file /opt/auth/configs/support-readonly.yml
isolate package list
isolate package show "Support Read-Only"
```

Assign it to one or many Keycloak subjects. Each `--user`, `--group`, and `--role` creates an independent assignment:

```bash
isolate package assign "Support Read-Only" \
  --group Demo-Support-L1 \
  --group Demo-Support-L2 \
  --user demo.alex \
  --ttl 7d \
  --ticket CHG-1042 \
  --yes
```

Use `--permanent` only when the package allows permanent assignments. `default_ttl` is used when neither `--ttl` nor `--permanent` is provided; `max_ttl` limits administrator input. `ticket_required` rejects assignments without `--ticket`. `approval.admin_groups`, when non-empty, limits which configured access admins can assign the package. Values above `minimum_approvals: 1` intentionally block direct assignment until a multi-approver workflow is configured.

Preview and apply a new immutable revision:

```bash
isolate package preview "Support Read-Only" --file /tmp/support-readonly-v2.yml
isolate package apply "Support Read-Only" \
  --file /tmp/support-readonly-v2.yml \
  --expected-revision 1 \
  --yes
```

Preview is read-only and reports affected subjects plus grant creates, updates, and deletes. Stable rule `id` values preserve generated grant IDs between revisions. `--expected-revision` prevents an administrator from overwriting a concurrent change.

List or revoke assignments and roll back safely:

```bash
isolate package assignments --package "Support Read-Only"
isolate package unassign --id 12 --yes
isolate package revisions "Support Read-Only"
isolate package rollback "Support Read-Only" --revision 1 --expected-revision 3 --yes
```

Rollback never rewrites history. It creates a new package revision from the selected snapshot and synchronizes active assignments. GitOps prune preserves package-managed grants and project sets they reference. When `policy_as_code.enforce_git: true`, package mutation is disabled with the other manual policy operations.

## Break-Glass Access

Break-glass access creates temporary grants through approval.

### User Requests Access

```bash
isolate access request \
  --project payments-prod \
  --host 10042 \
  --remote-user dba \
  --sudo-mode none \
  --reason "Need production diagnostics" \
  --ticket INC-1001
```

Arguments:

- `--project`: required project.
- `--host`: optional exact host.
- `--remote-user`: requested target Linux user.
- `--sudo-mode`: requested sudo mode.
- `--reason`: required business reason or incident id.
- `--ticket`: optional ticket id. If `access.ticket_required: true`, it must match `access.ticket_pattern`.
- `--template`: optional request template from `access.request_templates`.
- `--starts-at`, `--ends-at`: optional access-window boundaries, as Unix seconds or ISO 8601 timestamps with an explicit timezone.

Template example:

```bash
isolate access request \
  --project payments-prod \
  --host 10042 \
  --template dba-prod \
  --reason "Check database replication lag" \
  --ticket INC-1002
```

### Admin Lists Pending Requests

```bash
isolate access list --status pending
```

Other filters:

```bash
isolate access list --user demo.alex
isolate access list --project payments-prod
isolate access list --ticket INC-1001
isolate access list --status approved
isolate access list --status denied
isolate access list --json
```

### Admin Shows Request

```bash
isolate access show --id 12
```

### Admin Approves

```bash
isolate access approve --id 12 --ttl 2h --comment "Approved for incident window"
```

Override requested remote user:

```bash
isolate access approve --id 12 --ttl 1h --remote-user l2-support --sudo-mode none
```

TTL examples:

```bash
--ttl 30m
--ttl 2h
--ttl 1d
```

`access.max_ttl` limits the maximum approval duration.

### Scheduled Access Windows

Request a future window without making access available immediately:

```bash
isolate access request --project payments-prod --host 10042 \
  --remote-user dba --sudo-mode none --reason "CHG-1003 maintenance" \
  --starts-at '2030-01-02T22:00:00+07:00' --ends-at '2030-01-02T23:00:00+07:00'
isolate access approve --id 12 --ttl 2h
```

Replace the example dates with the intended change window. ISO timestamps must
include `Z` or an offset such as `+07:00`; ambiguous local datetimes are rejected.
The approver can override the start with `--starts-at`. The effective start is
never earlier than approval time, and expiry is the earlier of the requested end
and effective start plus approved TTL. `access.max_ttl` bounds the effective
duration. An end before the effective start is rejected. Policy checks exclude
grants before their start and after expiry across CLI, SSH, jobs, and dashboard.

### Cancel, Revoke, And Renew

```bash
# Requester: cancel a still-pending request.
isolate access cancel --id 12 --yes
# Access administrator: revoke the request's issued temporary grant.
isolate access revoke --id 13 --reason "Incident resolved" --yes
# Requester: submit a renewal for fresh approval.
isolate access renew --id 14 --reason "Follow-up diagnostics" --ticket INC-1004
```

Cancellation records `cancelled`; revocation removes the linked temporary grant
and records `revoked`. Renewal of an approved request creates a new `pending`
request linked through `renewal_of`, without extending the existing grant.
Renewals also accept `--starts-at` and `--ends-at`. Decisions and lifecycle changes
retain their comment timeline and notification results. Where recorded, ownership
uses the immutable Keycloak subject; legacy records fall back to the username.

### Admin Denies

```bash
isolate access deny --id 12 --reason "Use staging environment first" --comment "No production impact confirmed"
```

### Comments And Repeat Requests

Add operational context without changing request status:

```bash
isolate access comment --id 12 --text "Waiting for service owner confirmation"
```

Create a new pending request from a previous one:

```bash
isolate access repeat --id 12 --reason "Follow-up check after deploy" --ticket INC-1003
```

Access records preserve comments as an append-only timeline:

```json
{
  "comments": [
    {
      "username": "demo.admin",
      "action": "approve",
      "text": "Approved for incident window"
    }
  ]
}
```

### Access Notifications

When notifications are enabled, Isolate sends events for request creation, approval, and denial. The access action remains successful even if Telegram, email, or webhook delivery fails, unless `notifications.fail_closed` is explicitly set to `true`.

Example workflow:

```bash
isolate access request \
  --project payments-prod \
  --host 10042 \
  --remote-user dba \
  --sudo-mode none \
  --reason DEMO-INC-1001
```

DevSecOps receives a notification with the requester, project, host, requested remote user, sudo mode, reason, and dashboard link. An admin then opens `/access`, approves with a TTL such as `2h`, and Isolate creates a temporary user grant until `expires_at`.

Notification config lives in `/opt/auth/configs/isolate.yml`:

```yaml
notifications:
  enabled: true
  timeout_seconds: 5
  fail_closed: false
  sinks:
    - type: webhook
      url: https://hooks.example.org/isolate
      headers:
        Authorization: "Bearer CHANGE_ME"

    - type: telegram
      bot_token: CHANGE_ME_TELEGRAM_BOT_TOKEN
      chat_id: "-1001234567890"
      parse_mode: HTML

    - type: email
      smtp_host: smtp.example.org
      smtp_port: 587
      starttls: true
      username: isolate@example.org
      password: CHANGE_ME_SMTP_PASSWORD
      from: isolate@example.org
      to:
        - devsecops@example.org
```

Supported events:

- `access_request_created`
- `access_request_approved`
- `access_request_denied`

Security note: notification tokens and SMTP passwords are secrets. Keep `/opt/auth/configs` owned by `auth:auth`, directory mode `0750`, and config files mode `0640`:

```bash
sudo bash /opt/auth/scripts/fix-perms.sh
ls -ld /opt/auth/configs
ls -l /opt/auth/configs/isolate.yml
```

`notifications.fail_closed: false` is the recommended default. It prevents an external Telegram, SMTP, or webhook outage from blocking emergency access approval.

### Access Admins

Access admins are configured by Keycloak groups:

```yaml
access:
  admin_groups:
    - Demo-DevOps
    - Demo-Security
  ticket_required: false
  ticket_pattern: "^(INC|CHG)-[0-9]+$"
  request_templates:
    dba-prod:
      remote_user: dba
      sudo_mode: none
      ttl: 2h
```

## Connection History

### User History

```bash
f
f kube-prod
f 10004
```

### Admin History

```bash
isolate history --user demo.alex
isolate history --project payments-prod
isolate history --host 10042
isolate history payments
isolate history --limit 50
isolate history --json
```

Output fields:

- `time`
- `user`
- `project`
- `host_id`
- `target`
- `remote_user`
- `result`

History admins are configured with:

```yaml
history:
  admin_groups:
    - Demo-DevOps
    - Demo-Security
```

Ordinary users can only see their own history.

### History Filters And Matching Exports

```bash
isolate history --project payments-prod --since 2026-11-01 --until 2026-11-06 --result failure
isolate history --since '2026-11-06T00:00:00+07:00' --result exit=255 --json
isolate export history --project payments-prod --since 2026-11-01 \
  --until 2026-11-06 --result success --format csv --output history.csv
```

`--since` and `--until` accept Unix seconds, UTC calendar dates, or ISO 8601
datetimes with an explicit timezone. A date-only `--until` includes the entire UTC
day. Datetimes without an offset are rejected. Result filters include `success`
(`exit=0`), `failure` (a nonzero recorded exit), or an exact result such as
`exit=255`, `started`, or `selected`. Existing per-user visibility and result limits
still apply. Dashboard History provides the same filter form and preserves its
filters in CSV/JSON download links.

## Active Sessions

The SSH wrapper writes active session state to Redis:

```text
active_session_<connection_id>
```

The active session record includes:

- connection id;
- username;
- project;
- host id;
- target host;
- remote user;
- source IP;
- start time;
- status.

The dashboard reads this registry to show current connections.

### Session Control And Alerts

Session control is compatible with the existing `g` flow. The wrapper still starts the same SSH process, but keeps a low-frequency Redis heartbeat and checks for an administrator termination request. Termination and risk alerts are disabled by default.

```yaml
session_control:
  enabled: true
  terminate_enabled: true
  poll_interval: 1
  heartbeat_interval: 15
  active_ttl: 86400
  live_tail_bytes: 262144
  alerts:
    enabled: true
    long_session_seconds: 14400
    vip: true
    privileged: true
    unusual_source: true
    trusted_source_cidrs:
      - 10.0.0.0/8
      - 192.0.2.0/24
```

Alerts use the same configured webhook, Telegram, and email sinks as access requests. They are emitted for VIP sessions, `root`/`sudo-i`, sources outside `trusted_source_cidrs`, and sessions longer than `long_session_seconds`. Delivery results remain visible on `/notifications` while the Redis session record exists.

Dashboard administrators can open `/sessions/active`, watch `/session/<connection_id>/live`, and request termination. CLI termination is also available:

```bash
isolate session terminate 22222222-2222-2222-2222-222222222222 \
  --reason "INC-2042 containment" \
  --yes
```

The command sets an authenticated Redis control flag. The auth-owned wrapper records `session_termination_received`, sends `SIGTERM` to the SSH process group, escalates to `SIGKILL` only if needed, restores the local TTY, and writes `ssh_end` with exit code `143`. If Redis is temporarily unavailable, an existing SSH session continues; control-plane failure does not break the data path.

### Approval Of Individual SSH Sessions

Session approvals add a decision for one connection after the normal SSH grant
check succeeds. They do not create grants, extend a grant's lifetime, or replace
the existing access-request workflow. The SSH wrapper waits before opening the
outbound connection and prints the approval request ID for the operator.

The feature is disabled by default. Enable it for exact projects, project globs,
and/or privileged sessions:

```yaml
session_approval:
  enabled: true
  required_projects: [payments-prod]
  required_project_globs: ["*-critical"]
  require_privileged: true
  minimum_approvals: 1
  privileged_minimum_approvals: 2
  request_timeout_seconds: 300
  approval_ttl_seconds: 300
  max_session_seconds: 3600
  poll_interval_seconds: 2
```

`require_privileged` covers remote `root` and `sudo-i`. For a connection requiring
approval, the effective privileged quorum is at least
`privileged_minimum_approvals`. Each approving person is identified by their
verified Keycloak subject; self-approval and a second vote by the same person are
rejected. A scoped `approver` or `project-owner` needs permission for that exact
project. Global administrators still cannot approve their own connection.

Approvers use `/session-approvals`; the requester follows their own pending and
active decisions at `/me/session-approvals`. The equivalent CLI is:

```bash
isolate session approval list --status pending --project payments-prod --json
isolate session approval show <request-uuid>
isolate session approval approve <request-uuid> --reason "INC-1001 verified" --yes
isolate session approval deny <request-uuid> --reason "Use staging first" --yes
isolate session approval revoke <request-uuid> --reason "Incident resolved" --yes
```

The pending request has a timeout. After quorum is reached,
`approval_ttl_seconds` limits how long that connection may wait to consume the
approval; it does not grant repeated connections. The UUID request is bound to
one connection ID, requester subject, source address, target routing, remote
identity, and policy decision. A different connection or changed binding needs a
new decision. At consumption, `max_session_seconds`, identity expiry, and grant
expiry bound the session deadline. Regular authorization rechecks also enforce
revocation and the currently configured quorum. Existing sessions without an approval close if a
newly applied configuration requires one.

This approval path is implemented for interactive SSH through the wrapper.
Jobs/runbooks targeting a host or proxy that requires session approval fail closed; an
interactive approval cannot be reused to authorize worker execution.

Approval records use `session_approval_*` Redis keys. Default backups include
them; add this pattern to existing custom backup patterns and service Redis ACLs
when those configurations override the defaults. Decision state and notification
results remain available for audit after a request expires or closes.

## Session Logging

Structured logs are written to:

```text
/opt/auth/logs/<user>/<session_id>/session.jsonl
```

Important event types:

- `helper_start`
- `policy_selected`
- `policy_denied`
- `ssh_start`
- `ssh_end`
- `command`
- `ssh_argument_denied`

Example event:

```json
{
  "event": "policy_selected",
  "username": "demo.alex",
  "groups": ["Demo-DBA"],
  "project": "payments-prod",
  "host_id": "10042",
  "target_host": "192.0.2.42",
  "remote_user": "dba",
  "connection_id": "22222222-2222-2222-2222-222222222222"
}
```

Raw transcripts are written as legacy `.log` files under:

```text
/opt/auth/logs/<user>/
```

The dashboard can link to raw transcripts for admins. It can also render a session details page and replay MVP from the current raw log format.

Session details:

```text
/session/<connection_id>
/session/<connection_id>/events.json
```

Replay MVP:

```text
/replay/<connection_id>
/replay/<connection_id>.json
```

Replay uses the existing raw `.log` chunks and does not attempt reliable command extraction.

Replay v2 includes:

- play, pause, reset;
- seek bar;
- current time and total duration;
- speed selector;
- `replay.json` download;
- plain transcript toggle;
- a locally vendored xterm.js terminal engine for ANSI/VT sequences, colors, cursor movement, alternate-screen applications, and Unicode;
- no external CDN dependency;
- a safely escaped plain-text fallback for malformed legacy logs.

Configure payload limits:

```yaml
replay:
  max_bytes: 10485760
  default_speed: 1
```

### Structured Command Audit

Structured command audit is separate from raw PTY replay. Isolate does not infer commands from terminal control sequences. Choose `managed` to audit every accepted command string at the execution boundary, or keep the legacy `target-hooks` mode for partial reports from target shells.

#### Managed command input

Enable in the trusted bastion config (`/etc/isolate/isolate.yml`), not in a user-writable config:

```yaml
command_audit:
  enabled: true
  mode: managed
  max_command_length: 4096
  command_timeout_seconds: 300
  send_env: false
logging:
  base_path: /opt/auth/logs
  sinks:
    - type: jsonl
      path: /opt/auth/spool/audit.jsonl
```

Run `isolate config validate --check-paths` and enable `isolate-audit-export.service` as described below. Existing `s`/`g` connections through the privileged SSH wrapper now open an `isolate>` prompt. The mode is selected by trusted configuration; a caller cannot request an unrestricted shell instead. No target hook, callback key or `AcceptEnv` changes are needed. Keycloak identity, inventory, grants and target key validation still apply, and authorization is forcibly rechecked before every submitted command is executed.

Each accepted, nonempty input line is a command string. It is signed where configured and synchronously persisted with `fsync` as `command_start` **before** a child SSH process can start. A `command` event with the same `command_id` records the result afterwards. Both reach the common `/opt/auth/spool/events.jsonl` through the exporter. If signing, a configured JSONL sink, local append or synchronization fails, execution stops. Failure while saving a result closes the managed session before the next command. The local spool/session logs remain the durable source while the exporter is stopped; the common feed catches up when it resumes. Syslog remains best effort. This does not acknowledge delivery to Wazuh.

For example, `printf '%s' 'hello world'; false` remains one complete submitted command, including spaces, quotes and compound shell syntax. Its final event includes:

```json
{
  "event": "command",
  "timestamp": "2026-10-16T13:00:00.000Z",
  "ts": 1792155600.0,
  "username": "engineer1",
  "keycloak_sub": "keycloak-subject",
  "host_id": "10042",
  "connection_id": "connection-uuid",
  "command_id": "command-uuid",
  "command": "printf '%s' 'hello world'; false",
  "exitcode": 1,
  "exit_code": 1,
  "exit_code_known": true,
  "command_status": "completed",
  "source": "isolate-managed",
  "audit_scope": "submitted_command",
  "audit_complete": true,
  "result_scope": "ssh_remote_exec"
}
```

The event also carries project, target endpoint, remote user, sudo mode, source IP, sequence, completion time and duration when available. `timestamp`/`ts` identify submission time, and `finished_at` identifies completion. Identity and host fields originate from the verified wrapper authorization rather than a target-provided environment variable. `exit_code` is retained for existing consumers; `exitcode` is its alias.

Each command opens a **new** SSH exec channel and `/bin/sh -c` process with `-T`, `-n`, `StdinNull=yes` and local `DEVNULL`. There is no remote terminal or interactive stdin, and connection multiplexing is disabled. `cd` and exported variables do not persist between commands: combine dependent actions into one submitted line, such as `cd /var/log && ls -l`. Interactive editors, password prompts, nested interactive shells and multiline interactive entry are unavailable. `sudo-i` policies use noninteractive `sudo -n -i`; targets must already permit the corresponding operation. Otherwise the remote exec returns its failure status.

This mode guarantees capture of each **accepted input string**, not each statement generated inside a script, child shell or application. A compound command gets its remote exec status, not an exit code for each subcommand. Program arguments and script bodies included in the submitted string are preserved. The mode is not a syscall recorder. Background processes can outlive their launching shell, and terminating SSH does not prove that detached target processes stopped.

OpenSSH returns 255 for transport/authentication failures and can also return a real remote status of 255. Therefore 255, signals, cancellation, revocation and timeout produce `exitcode: null`, `exit_code_known: false`, `command_status: unknown` and a reason; the observed SSH return code is kept separately. The managed session closes on an unknown result. A crash can leave a durable `command_start` without a result: treat this as an unknown outcome, not as success or proof that execution started. See [OpenSSH exit status](https://man.openbsd.org/ssh.1#EXIT_STATUS).

`exit` is an audited local session-exit action; Ctrl+D submits no fake command. Ctrl+C closes the managed session, preserving any already submitted command and reporting an unknown result if execution was interrupted. Inputs exceeding the configured limit (hard maximum 4096 characters) or containing NUL are rejected without executing either the prefix or the remainder. Rejection records contain a bounded preview and set `command_truncated`/`audit_complete` accordingly. Timeout 0 disables the per-command timeout; identity/grant/session expiry checks remain active during execution.

This applies to the classic Isolate SSH wrapper. Transparent incoming ProxyJump/forwarding does not pass through this input boundary and cannot provide this guarantee; leave it disabled for a managed-only bastion. Job workers/MCP are separate execution paths. Stop pre-upgrade unrestricted sessions before claiming managed-only coverage. The closed bastion profile enables this mode while keeping contractor connections disabled until its realm and grants are ready.

#### Legacy target hooks

For partial target-shell reports, use:

```yaml
command_audit:
  enabled: true
  mode: target-hooks
  require_connection_id: true
  require_active_session: true
  completion_grace_seconds: 30
  max_command_length: 4096
  send_env: true
  ingest_user: auth
```

Append a command event:

```bash
sudo -u auth /opt/auth/shared/isolate.py command-log append \
  --connection-id 22222222-2222-2222-2222-222222222222 \
  --host-id 10042 \
  --project payments-prod \
  --cwd /var/www \
  --exit-code 0 \
  --shell bash \
  --source target-shell-hook \
  --command "systemctl status nginx"
```

The resulting event is written to the matching `session.jsonl`:

```json
{
  "event": "command",
  "connection_id": "22222222-2222-2222-2222-222222222222",
  "username": "demo.alex",
  "project": "payments-prod",
  "host_id": "10042",
  "cwd": "/var/www",
  "command": "systemctl status nginx",
  "exit_code": 0,
  "shell": "bash",
  "source": "target-shell-hook"
}
```

Hook templates are provided for target hosts:

```text
/opt/auth/scripts/target-command-audit.bash
/opt/auth/scripts/target-command-audit.zsh
```

Roll out a target host explicitly:

```bash
sudo /path/to/isolate/scripts/install-target-command-audit.sh auth@bastion.example.org
```

The installer deploys Bash and Zsh hooks, adds the four `AcceptEnv` names to an `sshd_config.d` drop-in, validates the SSH daemon config, and reloads SSH. It is inert for connections that do not contain `ISOLATE_CONNECTION_ID`.

Use a dedicated callback key. On the bastion, restrict its `authorized_keys` entry so a compromised target cannot execute arbitrary Isolate commands:

```text
restrict,command="/opt/auth/scripts/isolate-command-audit-ingest.py" ssh-ed25519 AAAA... isolate-command-audit
```

Install the corresponding private key on the target with root-only permissions and select it through the target's SSH config for `auth@bastion.example.org`. The forced-command helper accepts only `isolate command-log append`. Isolate also verifies that the supplied project/host match the trusted session JSONL and that the connection is active or ended within the short configured grace period.

The hooks submit asynchronously with `BatchMode`, no forwarding, and a short connection timeout, so a callback outage does not delay the operator prompt. The append endpoint also checks the effective Unix account and accepts events only from `command_audit.ingest_user` (`auth` by default), which prevents interactive bastion users from submitting fabricated events through the CLI. Command audit is best effort unless targets are integrated with a central audit agent. `sudo -i` commonly strips `ISOLATE_*`; if command auditing of privileged shells is required, review a narrowly scoped `sudoers` `env_keep` rule with DevSecOps rather than preserving arbitrary environment variables.

## Admin Dashboard

The dashboard is a lightweight Flask app.

Start it:

```bash
python3 /opt/auth/shared/isolate_web.py
```

Recommended deployment:

- bind to `127.0.0.1:8080`;
- expose through Nginx or Apache;
- terminate TLS at the reverse proxy;
- restrict access by Keycloak groups.

Example config:

```yaml
dashboard:
  enabled: true
  listen_host: 127.0.0.1
  listen_port: 8080
  public_url: https://bastion.example.org
  secret_key_file: /opt/auth/keys/dashboard_secret
  refresh_seconds: 15
  default_locale: en
  self_service_enabled: true
  self_service_groups: []
  admin_groups:
    - Demo-DevOps
    - Demo-Security
```

Keycloak redirect URI:

```text
https://bastion.example.org/auth/callback
```

Routes:

- `/`: administrator summary, or redirect to the user workspace for an eligible non-admin.
- `/login`: Keycloak login.
- `/auth/callback`: OIDC callback.
- `/logout`: logout.
- `/me`: personal workspace and policy-allowed hosts.
- `/me/resources/<server_id>`: resource metadata, cached health, effective SSH identity and access expiry, and connection instructions.
- `/me/sessions`: the current user's active sessions.
- `/me/history` and `/me/history/export`: the current user's filtered history and CSV/JSON export.
- `/me/access`: create and track personal access requests, add comments, cancel pending requests, and request renewals.
- `/sessions/active`: active SSH sessions, live view, and optional force termination.
- `/jobs`: jobs/runbooks queue, fleet progress, filters, cancel, and failed-host retry.
- `/job/<job_id>`: job authorization snapshot, execution metadata, and captured output.
- `/alerts`: long/VIP/privileged/unusual sessions, failed jobs, and notification failures.
- `/history`: connection history.
- `/session/<connection_id>`: session details and timeline.
- `/session/<connection_id>/events.json`: session JSONL events.
- `/inventory`: searchable inventory, host creation, editing, and validated bulk updates.
- `/inventory/<server_id>/services`: successful discovery baseline and service changes for a host.
- `/announcements`: global/project/host operational notices with severity and TTL.
- `/access`: access requests with filters, comments, repeat, approve, and deny forms.
- `/session-approvals`: project-scoped decisions and revocation for individual SSH connections.
- `/me/session-approvals`: the current user's connection approval requests.
- `/grants`: create/edit/remove grants and project sets, plus bulk allowed-action/member operations.
- `/packages`: create and assign reusable access profiles; package details provide preview, revision apply, and rollback.
- `/policy/simulate`: visual allow/deny simulator using the production resolver.
- `/policy/matrix`: effective `user/group/role x project` access, policy findings, and blast-radius preview.
- `/policy/gitops`: signed Git policy status, drift/blast-radius refresh, sync, and rollback.
- `/users` and `/user/<username>`: observed groups, activity metrics, top projects, grants, requests, active sessions, and history.
- `/notifications`: configured sinks and delivery results for access requests and session alerts.
- `/docs`: bilingual English/Russian operator documentation with practical examples and build information.
- `/replay/<connection_id>`: xterm.js ANSI terminal replay.
- `/replay/<connection_id>.json`: parsed replay chunks.
- `/raw/<user>/<connection_id>`: raw transcript for admins.
- `/export/<inventory|grants|history|users|access-matrix>`: authenticated CSV or JSON download.

Global configuration, policy mutations, jobs administration, and user management
require membership in `dashboard.admin_groups`. Project-scoped management roles
can enter their permitted inventory, access, session, and audit pages; every object
and export is filtered again by its project. Personal `/me` routes retain their
per-user ownership checks.

### Personal User Workspace

After Keycloak sign-in, eligible non-admin users land on `/me`. They see
policy-allowed resources, their own active sessions and connection history, and their
own access requests. They can request a scheduled access window, comment on a
request, cancel a pending request, or create a renewal awaiting administrator
approval. Personal history exports preserve the selected filters and omit internal
filesystem paths. Recorded Keycloak subjects bind request, session, and history
ownership; legacy data without a subject uses the username.

`dashboard.self_service_enabled` defaults to `true`. An empty
`dashboard.self_service_groups` permits any verified signed-in identity with a
username to use its own workspace. Restrict it to exact Keycloak group names when
needed:

```yaml
dashboard:
  self_service_enabled: true
  self_service_groups: [Demo-Operators, Demo-Contractors]
```

Set `self_service_enabled: false` to disable ordinary non-admin access to the
personal workspace. Users with an assigned project management role can still
enter the resource catalogue for their authorized scope. These settings do not
grant SSH access or administrator privileges.

### Resource Catalogue

`/me` presents searchable resource cards. A card includes owner, environment,
manual and discovered services, maintenance state, the latest cached connectivity
result and check time, and the effective SSH remote user, sudo mode, and expiry.
Expiry reflects the earlier of the current identity and grant deadlines. A stale
or route-mismatched connectivity result is not presented as a fresh successful
check; browsing the catalogue never initiates a network probe.

Open `/me/resources/<server_id>` for details. The connection control copies
`g <server_id>` for use after logging in to the bastion and running
`isolate login`. Its request-access link prefills the visible host and project;
opening that link creates no request until the user confirms the form.

SSH visibility is calculated with the production grant resolver. A management
role with `inventory.read` can also view resources in its project, with a clear
"No SSH permission" indication when no SSH grant applies. A management role alone
does not enable connection or reveal credentials. Direct details and request
prefills recheck the current host and scope, including after project moves.

### Project-Scoped Management Roles

Assign management roles through the trusted runtime configuration and verified
Keycloak group membership. Role assignment is configuration-managed; there is no
new global role-assignment form in the dashboard.

```yaml
dashboard:
  admin_groups: [Demo-Platform-Admins]
  role_bindings:
    - group: Demo-Payments-Owners
      role: project-owner
      projects: [payments-prod, payments-stage]
    - group: Demo-Payments-Approvers
      role: approver
      projects: [payments-prod]
    - group: Demo-Production-Auditors
      role: auditor
      project_globs: ["*-prod"]
    - group: Demo-Payments-Inventory
      role: inventory-operator
      projects: [payments-prod, payments-stage]
```

Group names are exact, case-sensitive verified OIDC group values. `projects`
contains exact project names; `project_globs` optionally adds glob selectors.
An explicit `projects: ["*"]` grants that role across projects. Missing or malformed
scopes do not implicitly grant global access. Multiple matching bindings combine
their permissions.

| Role | Project-scoped capabilities |
| --- | --- |
| `project-owner` | Inventory read/write, access-request read/approve, session read/approve, audit read |
| `approver` | Inventory read, access-request read/approve, session approval |
| `auditor` | Inventory read, access-request read, session read, audit read |
| `inventory-operator` | Inventory read and descriptive inventory changes |

Inventory writers can edit descriptions, services, tags, owner/environment, and
maintenance, and move a host only when they hold write permission for both its
current and proposed project. The write rechecks both scopes within the Redis
transaction, including after a concurrent change. Host creation and changes to
addresses, ports, remote credentials/user, sudo defaults, proxies, VIP status, or
privileged-access settings remain global administrator operations.

Auditors can read permitted project history, session details, replay, raw logs,
and corresponding filtered exports. Access to another project, an object without
project metadata, or a global policy/user-management surface is denied. Project
roles govern management operations and never create target SSH grants.

Use the `EN` / `RU` control in the top bar to select the dashboard locale. The choice is stored in the authenticated Flask session. Navigation, compact per-page explanations, and input-field help are localized without changing data or policy values. Day/night theme remains a browser-local preference.

The sidebar shows the product version, short build revision, schema version, and Python runtime. `/docs` shows the full build metadata. Production packages should set immutable values through the systemd environment or CI/CD:

```bash
ISOLATE_VERSION=2.1.0
ISOLATE_BUILD_SHA=0123456789abcdef
ISOLATE_BUILD_DATE=2026-09-10T12:00:00Z
```

The administrator `/` overview, `/sessions/active`, and `/access` pages auto-refresh when
`dashboard.refresh_seconds` is greater than `0`. Set it to `0` to disable refresh.
History filters and self-service forms do not auto-refresh or discard unfinished input.

Access approval from the dashboard supports:

- TTL, for example `30m`, `2h`, or `1d`;
- optional remote user override;
- optional sudo mode override;
- ticket/user/project filters;
- approve and deny comments;
- repeat request action;
- scheduled start and requested end window;
- revocation of approved temporary access;
- notification warnings;
- denial reason.

Dashboard POST actions use a per-session CSRF token and explicit confirmation. Host edit forms carry an optimistic revision token, so a stale browser form cannot overwrite a newer host update. Policy mutations create a private snapshot first. When `policy_as_code.enforce_git` is true, manual grant/project-set forms are read-only and Git is the only static-policy writer.

### Jobs And Runbooks Console

The console uses the existing signed asynchronous job records and worker. It does not execute commands in the Flask process. A dashboard administrator can queue an enabled typed runbook for one host, a comma-separated fleet of host IDs, or hosts selected by project and exact AND-matched tags. Explicit host IDs cannot be mixed with project/tag selectors. Before any job is created, Isolate validates the complete fleet, runbook parameters, current Keycloak groups, effective grant action (`runbook` or `operate`), remote user, sudo mode, timeout, and configured fleet limit.

```yaml
runbooks:
  enabled: true
  max_fleet_hosts: 100
  read_only:
    allowed_groups: [Demo-DevOps]
    allow_sudo: false
    require_confirmation: true
```

Each fleet child remains a normal `job_*` record accepted by the existing worker and additionally carries `fleet_id`, slot, size, and attempt metadata. Fleet progress counts only the newest attempt for each host. Retry is limited to failed or timed-out jobs, verifies the original HMAC authorization signature, and re-evaluates current inventory, grants, runbook configuration, groups, remote identity, and sudo policy. Cancel and retry require CSRF plus explicit confirmation and emit dashboard admin audit events.

### Jobs And Runbooks From The CLI

The CLI uses the same signed queue and worker; it does not run remote commands in
the calling process:

```bash
isolate runbook list
isolate runbook show service-status
isolate runbook preview service-status --host 10004 --param service=nginx
isolate runbook run service-status --host 10004 --param service=nginx --yes
isolate runbook preview uptime --project payments-prod --tag env=prod
isolate runbook run uptime --tag env=prod --tag owner=payments --yes
isolate job list --status failed --json
isolate job show 12
isolate job output 12
isolate job cancel 12 --yes
isolate job retry 12 --yes
```

Use repeated or comma-separated `--host` IDs, or a project/tag selector; explicit
IDs cannot be mixed with dynamic selectors. Tag selectors use exact AND matching.
An omitted selector never defaults to the whole inventory. Preview validates the
complete selected fleet, parameters, grants, remote identities, and runbook-class
permissions without queueing jobs. Run, cancel, and retry require `--yes`.

Jobs/runbooks CLI operations require a Linux bastion. They load the root-managed
trusted runtime configuration and bind the signed cached token to the real Unix
account, rather than accepting execution settings or identity authority from
`ISOLATE_CONFIG`. Users can inspect and control their own jobs; cross-user operations
require trusted platform-administrator authorization. Own-job retry passes current
verified identity claims and checks current policy, so the original group snapshot
cannot retain removed group privileges. Output reads are bounded and use the
configured jobs directory. `isolate jobs` is an alias for `isolate job`.

### Alert Center

The alert center aggregates existing runtime sources without replacing them:

- active/recent `active_session_*` records for VIP, root/sudo, unusual-source, and long-session alerts;
- failed and timed-out `job_*` records;
- failed access-request and session-alert notification deliveries.

Acknowledge, resolve, reopen, and comments are stored separately as `dashboard_alert_state_*`. This means an operator action cannot alter the original session, job, or delivery evidence. Add `dashboard_alert_state_*` to custom backup/Redis ACL configurations when overriding the defaults.

### Access Matrix

The access matrix invokes the same grant resolver as `s`, `g`, MCP, and the worker. Every cell shows effective host coverage, remote users, and allowed actions for a subject/project pair. Findings identify equal-precedence grants with conflicting or identical outcomes and grants shadowed across the current inventory. A preview can simulate a new grant or replace an existing grant ID and reports gained, lost, and changed host access. Preview is read-only and never writes Redis policy.

## MCP Server

Isolate includes an opt-in MCP v2 resource server for AI clients and automation. It uses the official Python MCP SDK, stateless Streamable HTTP, Keycloak bearer tokens, and the same Redis inventory and grant resolver as `s` and `g`. It does not trust `~/.isolate/identity.json`. Remote command execution is disabled by default and runs through a separate asynchronous worker when explicitly enabled.

The read and self-service surface exposes:

- `identity_whoami`: verified Keycloak identity and granted MCP scopes;
- `inventory_search`: only hosts allowed by the caller's existing Isolate grants;
- `host_get`: one policy-filtered host record;
- `grant_explain`: the caller's own effective access decision;
- `history_search`: only the caller's own connection history;
- `access_request_create`: creates a pending break-glass request but never approves it;
- `access_request_list`: own requests by default; all matching requests only for access admins;
- `access_request_show`: one own request or any request for an access admin;
- `access_request_comment`: appends an attributed comment to a visible request;
- `isolate://inventory/projects`: projects visible to the caller;
- `isolate://inventory/hosts/<server_id>`: policy-filtered host resource.

The phase-two approval surface additionally exposes:

- `access_request_approve`: creates an expiring user grant from a pending request;
- `access_request_deny`: closes a pending request with a decision reason.

The phase-three administration and jobs surface exposes:

- `inventory_host_add`: dry-run or add a validated host;
- `inventory_host_update`: dry-run or update selected fields with optimistic revision protection;
- `grant_list` and `grant_show`: read grants for policy administrators;
- `project_set_list` and `project_set_show`: read named project sets;
- `policy_preview`: simulate `ssh` or `command` decisions without changing policy;
- `runbook_list` and `runbook_show`: discover typed runbooks allowed by the caller's scope and groups;
- `runbook_execute`: queue a policy-authorized read-only or operational runbook;
- `command_job_create`: queue an authorized non-interactive command;
- `command_job_list`, `command_job_show`, and `command_job_output`: inspect own jobs or all jobs as an execution admin;
- `command_job_cancel`: cancel a queued or running job.

Inventory mutations use `dry_run=true` by default. Applying an update requires `dry_run=false`, `confirm=true`, and the `current_revision` returned by the latest preview as `expected_revision`. This prevents a stale MCP client from overwriting a newer inventory change.

Approval and denial require all of the following:

- the verified Keycloak identity belongs to one of `access.admin_groups`;
- the access token contains the configured `mcp.approval_scope`;
- the tool call explicitly passes `confirm=true`;
- the requester is not the approver when `prevent_self_approval` is enabled;
- the request is still pending, its project/host still exists, and its TTL does not exceed `access.max_ttl`.

This two-factor authorization prevents an ordinary member of an admin group from approving through an MCP client that was not granted the privileged scope. Read tools never trigger approval as a side effect.

Approval and denial also take a short atomic Redis decision lock under `access_request_lock_*`. This prevents two MCP workers from deciding the same pending request concurrently; lock records expire automatically and are ignored by access-request listings.

Every domain operation emits an `mcp_tool_call` audit event through the configured audit sinks. Tokens, client secrets, and complete tool arguments are not written to audit records.

### Keycloak Configuration For MCP

Use a separate audience for MCP access tokens, for example `isolate-mcp`. Do not reuse an ID token or the CLI identity cache as an MCP bearer credential.

Configure Keycloak so access tokens presented to Isolate contain:

- issuer equal to the configured realm issuer;
- `aud` containing `isolate-mcp` through an audience mapper;
- `groups` through a group membership mapper;
- realm roles when role-based grants are required;
- `scope` containing `isolate.read`;
- `scope` containing `isolate.self-service` for users allowed to create temporary access requests.
- `scope` containing `isolate.approve` only for MCP clients and administrators allowed to approve or deny requests.
- `scope` containing `isolate.inventory.write` for inventory administrators;
- `scope` containing `isolate.policy.read` for grant, project-set, and policy-preview access;
- `scope` containing `isolate.runbook` for approved read-only diagnostics;
- `scope` containing `isolate.operate` only for identities approved for operational runbooks;
- `scope` containing `isolate.execute` for users allowed to submit remote command jobs.

`access.admin_groups` remains the source of truth for access administrators. The `isolate.approve` scope is an additional requirement, not a replacement for the group check. Assign the approval client scope narrowly and do not include it in every user's default token.

For a manually registered public MCP client, enable Standard Flow, disable Client Authentication, require PKCE `S256`, and register only the exact redirect URIs used by the MCP client. Automatic OAuth onboarding additionally depends on the client's and Keycloak deployment's support for the current MCP OAuth registration mechanism. The Isolate MCP endpoint always publishes RFC 9728 protected-resource metadata and can also accept a correctly obtained Keycloak bearer token directly.

### MCP Configuration

Production example:

```yaml
mcp:
  enabled: true
  listen_host: 127.0.0.1
  listen_port: 8090
  public_url: https://mcp-bastion.example.org/mcp
  issuer: https://id.example.org/realms/demo-infra
  expected_audience: isolate-mcp
  jwks_cache_path: /opt/auth/cache/keycloak_mcp_jwks.json
  jwks_cache_ttl: 3600
  tls_verify: true
  required_scopes:
    - isolate.read
  self_service_scope: isolate.self-service
  approval_scope: isolate.approve
  inventory_write_scope: isolate.inventory.write
  policy_read_scope: isolate.policy.read
  execute_scope: isolate.execute
  runbook_scope: isolate.runbook
  operate_scope: isolate.operate
  inventory_admin_groups:
    - Demo-Platform-Admins
  policy_admin_groups:
    - Demo-DevSecOps
  execution_admin_groups:
    - Demo-DevSecOps
  prevent_self_approval: true
  require_mutation_confirmation: true
  allowed_hosts:
    - mcp-bastion.example.org
  allowed_origins:
    - https://mcp-bastion.example.org
  max_results: 100
  max_request_body_size: 1048576
```

`public_url` is the canonical MCP resource identifier and must include `/mcp`. `allowed_hosts` contains exact HTTP `Host` values accepted by the MCP transport's DNS-rebinding protection. Add both `host` and `host:*` only when clients legitimately use both forms. `allowed_origins` is required only for browser clients that send an `Origin` header.

The MCP verifier validates the JWT signature through the auth-owned JWKS cache and checks `iss`, strict `aud`, `exp`, and `nbf` on every HTTP request. Unlike CLI ID-token compatibility, `azp` alone is not accepted as the MCP audience.

Example access-admin configuration shared by CLI, dashboard, and MCP:

```yaml
access:
  admin_groups:
    - Demo-DevSecOps
    - Demo-Platform-Admins
  default_ttl: 2h
  max_ttl: 24h
```

An MCP approval token must contain both one of these verified groups and `scope: isolate.approve`. Keeping `prevent_self_approval` and `require_mutation_confirmation` enabled is strongly recommended.

### MCP Runbooks

Runbooks are typed commands executed through the same asynchronous worker as command jobs. They do not enable arbitrary shell input: every executable and option is defined in the auth-owned source catalog, and caller parameters are validated before a job is signed. The worker renders the runbook again and rechecks its definition hash, host routing, Keycloak group snapshot, effective grant action, remote user, and sudo mode immediately before SSH.

The built-in read-only catalog contains 15 runbooks:

| Runbook | Purpose | Parameters |
| --- | --- | --- |
| `uptime` | Uptime and load averages | none |
| `disk-usage` | Filesystem type and space usage | none |
| `inode-usage` | Filesystem inode usage | none |
| `memory` | Memory and swap usage | none |
| `cpu-processes` | Processes sorted by CPU | none |
| `memory-processes` | Processes sorted by memory | none |
| `top-snapshot` | One non-interactive top sample | none |
| `atop-snapshot` | One parseable atop sample | none |
| `service-status` | Full systemd unit status | `service` |
| `service-active` | Systemd active state | `service` |
| `journal-tail` | Recent service journal | `service`, optional `lines` (default 200, max 2000) |
| `failed-services` | Failed systemd units | none |
| `listening-sockets` | Listening TCP/UDP sockets | none |
| `network-addresses` | Interface and address summary | none |
| `network-routes` | Routing table | none |

The operational catalog contains `service-restart`, `dns-cache-flush`, and `deploy-diagnostics`. Operational runbooks are present in code but hidden and denied until `runbooks.operational.enabled` is explicitly enabled. `dns-cache-flush` only flushes `systemd-resolved`; application cache deletion must use a separately reviewed fixed helper and must never accept an arbitrary filesystem path.

Runbooks have four independent authorization gates:

1. `runbooks.enabled` is true, and operational runbooks additionally require `runbooks.operational.enabled`;
2. the verified token contains `isolate.runbook` or, for operational actions, `isolate.operate`;
3. the verified identity belongs to the configured group for that runbook class;
4. the effective host grant contains `runbook` or, for operational actions, `operate` in `allowed_actions`.

Recommended first rollout for read-only diagnostics:

```yaml
runbooks:
  enabled: true
  disabled: []
  read_only:
    allowed_groups:
      - Demo-Technical-Support
      - Demo-DevOps
    allow_sudo: false
    require_confirmation: true
  operational:
    enabled: false
    allowed_groups: []
    allow_sudo: false
    require_confirmation: true
```

Grant diagnostic access only where it is needed:

```bash
isolate grant update --id 7 \
  --allowed-action ssh \
  --allowed-action runbook
```

Example MCP calls:

```json
{"name":"runbook_list","arguments":{}}
{"name":"runbook_execute","arguments":{"runbook_id":"uptime","host_id":"10042","confirm":true}}
{"name":"runbook_execute","arguments":{"runbook_id":"journal-tail","host_id":"10042","parameters":{"service":"nginx.service","lines":100},"confirm":true}}
```

After security review, enable operational actions for a smaller group and selected grants:

```yaml
runbooks:
  enabled: true
  operational:
    enabled: true
    allowed_groups:
      - Demo-Platform-Operators
    allow_sudo: false
    require_confirmation: true
```

```bash
isolate grant update --id 12 \
  --allowed-action ssh \
  --allowed-action runbook \
  --allowed-action operate
```

Use a dedicated remote account with narrowly scoped permissions where possible. Set `runbooks.operational.allow_sudo: true` only after reviewing the remote `sudoers` rules and only for grants that intentionally resolve to `sudo_mode: sudo-i`. The worker uses `sudo -n`, so password prompts fail closed.

Operational examples:

```json
{"name":"runbook_execute","arguments":{"runbook_id":"service-restart","host_id":"10042","parameters":{"service":"nginx.service"},"confirm":true}}
{"name":"runbook_execute","arguments":{"runbook_id":"deploy-diagnostics","host_id":"10042","parameters":{"service":"payments-api.service","lines":300},"confirm":true}}
```

Runbook jobs are inspected with the existing `command_job_list`, `command_job_show`, `command_job_output`, and `command_job_cancel` tools. Audit events contain the runbook id and class plus the command SHA-256, but do not copy the full command or parameters into the central audit record. Output remains protected under `/opt/auth/jobs`.

### Remote Command Jobs

Command execution has four independent gates:

1. `command_execution.enabled` is true;
2. the verified token contains `isolate.execute`;
3. the verified user belongs to `command_execution.allowed_groups`;
4. the effective host grant contains `command` in `allowed_actions`.

Existing grants contain only `ssh`, so enabling the worker does not grant command execution automatically. Add the action only to selected grants:

```bash
isolate grant update --id 7 \
  --allowed-action ssh \
  --allowed-action command
```

Start with constrained, near-arbitrary patterns:

```yaml
command_execution:
  enabled: true
  allowed_groups:
    - Demo-Technical-Support
    - Demo-DevOps
    - Demo-Integration-Support
  allow_arbitrary_commands: false
  allowed_command_patterns:
    - '^uptime$'
    - '^whoami$'
    - '^systemctl (status|is-active) [a-zA-Z0-9_.@-]+$'
    - '^journalctl -u [a-zA-Z0-9_.@-]+ -n [0-9]{1,4}$'
  allow_sudo: false
  require_confirmation: true
  default_timeout: 60
  max_timeout: 900
  max_command_length: 4096
  max_output_bytes: 1048576
  max_return_bytes: 262144
  jobs_path: /opt/auth/jobs
  signing_key_file: /opt/auth/keys/job_hmac.key
  remote_shell: /bin/sh
```

For teams that genuinely require shell operators, the explicit high-risk mode is:

```yaml
command_execution:
  enabled: true
  allowed_groups:
    - Demo-DevOps
  allow_arbitrary_commands: true
  allow_sudo: false
```

This mode permits shell syntax such as pipes and redirects on hosts where the caller has a `command` grant. It still requires `confirm=true`, a verified Keycloak token, an allowed group, a matching project/host grant, and the `isolate.execute` scope. It is intentionally non-interactive: no PTY, password prompts, editors, or full-screen programs. The worker uses the `auth` user's SSH key and the `remote_user` resolved by policy.

Set `allow_sudo: true` only when selected grants use `sudo_mode: sudo-i` and the remote account has the intended passwordless sudo policy. Command jobs invoke sudo non-interactively, so a password prompt fails rather than hanging.

Job metadata is stored as `job_*` in Redis. Output is stored under `/opt/auth/jobs` with mode `0600`; central audit records contain the command SHA-256 rather than the complete command text. The job record itself contains the command and must be treated as sensitive operational data.

Each job's immutable authorization envelope is HMAC-signed. The worker also creates an auth-owned one-time claim file before starting SSH, so a user with accidental Redis write access cannot forge or replay command jobs. Generate the signing key before enabling execution:

```bash
sudo install -d -o auth -g auth -m 0700 /opt/auth/keys
openssl rand -hex 32 | sudo tee /opt/auth/keys/job_hmac.key >/dev/null
sudo chown auth:auth /opt/auth/keys/job_hmac.key
sudo chmod 0600 /opt/auth/keys/job_hmac.key
```

### MCP Deployment

Install or update dependencies:

```bash
sudo python3 -m pip install --break-system-packages -r /opt/auth/requirements.txt
```

Install the service and environment file:

```bash
sudo install -o root -g root -m 0644 /opt/auth/deploy/systemd/isolate-mcp.service /etc/systemd/system/
sudo install -o root -g root -m 0644 /opt/auth/deploy/systemd/isolate-job-worker.service /etc/systemd/system/
sudo install -o root -g root -m 0644 /opt/auth/deploy/systemd/isolate-mcp.env /etc/default/isolate-mcp
sudo bash /opt/auth/scripts/fix-perms.sh
sudo systemctl daemon-reload
sudo systemctl enable --now isolate-mcp.service
sudo systemctl enable --now isolate-job-worker.service
```

The service runs as `auth`, binds only to `127.0.0.1:8090`, uses two stateless Uvicorn workers, and can write only the trusted JWKS cache and configured audit spool. Put nginx or another HTTPS reverse proxy in front of it. A starting configuration is available at `/opt/auth/deploy/nginx/isolate-mcp.conf`.

Ansible installation is disabled by default. Enable it explicitly after configuring Keycloak and `mcp`:

```bash
ansible-playbook -i ansible/hosts.ini ansible/main.yml \
  -e isolate_enable_mcp_server=true \
  -e isolate_enable_job_worker=true
```

### MCP Verification

Validate the configuration and service:

```bash
sudo -u auth /opt/auth/shared/isolate.py config validate --check-paths
curl -i http://127.0.0.1:8090/health
curl -i -X POST http://127.0.0.1:8090/mcp -H 'Host: 127.0.0.1:8090' -H 'Content-Type: application/json' -d '{}'
journalctl -u isolate-mcp.service
journalctl -u isolate-job-worker.service
```

The unauthenticated MCP request must return `401` with a `WWW-Authenticate` header containing `resource_metadata`. Use the MCP Inspector or another OAuth-capable MCP client for a complete login and tool-call test.

MCP intentionally excludes arbitrary grant mutations, project-set mutations, policy apply, host deletion, backup restore, and interactive SSH. Host add/update, typed runbooks, and asynchronous commands are explicit, separately scoped operations. Runbooks and arbitrary command execution both remain disabled until configured and the job worker is enabled.

## Production Operations

The hardening features in this section are opt-in. Existing installations continue to use the local Redis connection, Flask development command, and per-session JSONL logs until the corresponding settings or units are enabled.

### Validate Configuration And Health

Validate the merged configuration without contacting external services:

```bash
sudo -u auth /opt/auth/shared/isolate.py config validate
```

Also validate runtime files such as the dashboard secret and audit signing key:

```bash
sudo -u auth /opt/auth/shared/isolate.py config validate --check-paths
```

Check Redis connectivity and log directory write access:

```bash
sudo -u auth /opt/auth/shared/isolate.py health
sudo -u auth /opt/auth/shared/isolate.py health --json
```

The dashboard exposes an unauthenticated, minimal `GET /health` endpoint for a load balancer or monitoring system. It returns `200` when configuration, Redis, and logging checks pass, otherwise `503`. It does not return credentials or tokens.

### Run Dashboard With Systemd And Gunicorn

Install the production Python dependencies and generate the Flask session secret:

```bash
python3 -m pip install -r /opt/auth/requirements.txt --break-system-packages
sudo install -d -o auth -g auth -m 0700 /opt/auth/keys
openssl rand -hex 32 | sudo tee /opt/auth/keys/dashboard_secret >/dev/null
sudo chown auth:auth /opt/auth/keys/dashboard_secret
sudo chmod 0600 /opt/auth/keys/dashboard_secret
```

Install the supplied systemd units and logrotate policy:

```bash
sudo install -o root -g root -m 0644 /opt/auth/deploy/systemd/isolate-dashboard.service /etc/systemd/system/
sudo install -o root -g root -m 0644 /opt/auth/deploy/systemd/isolate-dashboard.env /etc/default/isolate-dashboard
sudo install -o root -g root -m 0644 /opt/auth/deploy/systemd/isolate-log-retention.service /etc/systemd/system/
sudo install -o root -g root -m 0644 /opt/auth/deploy/systemd/isolate-log-retention.timer /etc/systemd/system/
sudo install -o root -g root -m 0644 /opt/auth/deploy/logrotate/isolate /etc/logrotate.d/isolate
sudo systemctl daemon-reload
sudo systemctl enable --now isolate-dashboard.service isolate-log-retention.timer
```

The service listens on `127.0.0.1:8080` by default. Change `ISOLATE_DASHBOARD_BIND` in `/etc/default/isolate-dashboard` when required. Put nginx or another trusted reverse proxy in front of Gunicorn; an example is available at `/opt/auth/deploy/nginx/isolate-dashboard.conf`.

Ansible keeps runtime unit installation disabled for existing deployments. Enable it explicitly:

```bash
ansible-playbook -i ansible/hosts.ini ansible/main.yml -e isolate_install_runtime_units=true
```

### Log Retention

`logging.retention_days` controls how long complete per-session directories are retained. Preview deletion first:

```bash
sudo -u auth python3 /opt/auth/scripts/prune-logs.py
```

Apply it manually:

```bash
sudo -u auth python3 /opt/auth/scripts/prune-logs.py --apply
```

The supplied systemd timer runs the apply mode daily. Legacy raw `.log/.meta` files and the central audit spool are rotated separately by logrotate.

### Service Backup And Recovery

Service backups are opt-in and do not change the existing `s`, `g`, login, dashboard, or Redis workflows. A backup contains:

- configured runtime paths such as `/opt/auth/configs`, `/opt/auth/keys`, and `/opt/auth/known_hosts`;
- optional `/home/auth/.ssh`, sudoers, dashboard environment, and systemd units when present;
- a logical Redis snapshot limited to the configured Isolate key patterns;
- `manifest.json` with source paths, modes, timestamps, file hashes, Redis metadata, and the current Git revision;
- an archive SHA-256 sidecar.

Session JSONL and raw terminal logs are excluded by default because they may be large and should normally have their own retention and off-host archival policy. Include them only when required:

```bash
sudo /opt/auth/shared/isolate.py backup create --include-logs
```

Create, list, and verify a normal service backup:

```bash
sudo /opt/auth/shared/isolate.py backup create
sudo /opt/auth/shared/isolate.py backup list
sudo /opt/auth/shared/isolate.py backup verify \
  --archive /opt/auth/backups/service/isolate-backup-20260902T021500000000Z.tar.gz
```

The default destination is `/opt/auth/backups/service`, retention is 14 archives, and files are normalized to mode `0600`. Configure both in `/opt/auth/configs/isolate.yml`:

```yaml
backup:
  base_path: /opt/auth/backups/service
  retention_count: 14
  include_logs: false
  redis_patterns:
    - server_*
    - grant_*
    - policy_*
    - project_set_*
    - access_request_*
    - active_session_*
    - job_*
    - dashboard_alert_state_*
    - ssh_config_*
    - complete_hosts_*
    - offset_*
    - projects_list
    - schema_version
  paths:
    - path: /opt/auth/configs
      required: true
    - path: /opt/auth/keys
      required: true
    - path: /opt/auth/known_hosts
      required: true
    - path: /home/auth/.ssh
      required: false
    - path: /etc/isolate
      required: false
```

Restore into a staging root first. The original absolute paths are recreated underneath that directory, so this command does not overwrite the running bastion:

```bash
sudo /opt/auth/shared/isolate.py backup restore \
  --archive /opt/auth/backups/service/isolate-backup-20260902T021500000000Z.tar.gz \
  --target-root /srv/isolate-restore-test \
  --restore-redis \
  --redis-conflict abort \
  --yes
```

Review the staged files and use a disposable Redis database or container for a recovery drill. Redis conflict modes are:

- `abort`: default; restore nothing when a target key already exists;
- `skip`: keep existing keys and restore only missing keys;
- `replace`: replace matching keys with backup values.

Live filesystem recovery is deliberately harder and should be performed during a maintenance window after stopping the dashboard and interactive access:

```bash
sudo systemctl stop isolate-dashboard.service
sudo /opt/auth/shared/isolate.py backup verify --archive /secure/path/isolate-backup.tar.gz
sudo /opt/auth/shared/isolate.py backup restore \
  --archive /secure/path/isolate-backup.tar.gz \
  --target-root / \
  --restore-redis \
  --redis-conflict replace \
  --preserve-owner \
  --live \
  --yes
sudo bash /opt/auth/scripts/fix-perms.sh
sudo systemctl start isolate-dashboard.service
```

The daily systemd timer is disabled for existing Ansible deployments. Enable it explicitly:

```bash
ansible-playbook -i ansible/hosts.ini ansible/main.yml -e isolate_enable_backup_timer=true
systemctl status isolate-backup.timer
journalctl -u isolate-backup.service
```

For a Redis ACL deployment, `backup.redis` can override only the backup job credentials while inheriting host, port, database, and TLS settings from `redis`:

```yaml
backup:
  redis:
    username: isolate-backup
    password: CHANGE_ME_BACKUP_PASSWORD
```

Creating a backup needs `KEYS`, `DUMP`, `PTTL`, and preferably `EVAL`; recovery additionally needs `EXISTS`, `RESTORE`, `MULTI`, and `EXEC`. Keep `RESTORE` out of the normal runtime ACL and grant it only to a controlled recovery credential when possible.

Backups contain secrets and private SSH keys. A local archive is not disaster recovery: ship successful, verified archives to encrypted off-host object storage with versioning/immutability, restrict access, and regularly perform a staged restore drill. SHA-256 checks detect corruption but do not protect against a malicious party replacing both an archive and its checksum.

Run the real-Redis recovery test from the repository root:

```bash
docker compose -f tests/integration/backup/docker-compose.yml up --build --abort-on-container-exit --exit-code-from backup-test
docker compose -f tests/integration/backup/docker-compose.yml down -v
```

### Redis ACL And TLS

Existing password-only Redis configuration remains compatible. For a hardened remote or shared Redis, configure an ACL user limited to Isolate key prefixes and commands, then set:

```yaml
redis:
  host: redis.internal.example.org
  port: 6380
  db: 0
  username: isolate
  password: CHANGE_ME_STRONG_PASSWORD
  ssl: true
  ssl_ca_certs: /etc/isolate/redis-ca.pem
  ssl_certfile: null
  ssl_keyfile: null
  ssl_check_hostname: true
  socket_timeout: 3
```

A representative Redis ACL is:

```text
user isolate on >CHANGE_ME_STRONG_PASSWORD ~server_* ~inventory_lock_* ~grant_* ~policy_* ~project_set_* ~access_request_* ~access_package_* ~active_session_* ~job_* ~dashboard_alert_state_* ~offset_* ~projects_list ~ssh_config_* +get +set +del +incr +expire +keys +ping +multi +exec +discard
```

Test ACL/TLS with `isolate health` before disabling the old Redis user. Client certificate fields are optional and are only needed for mutual TLS.

## Policy As Code

Policy bundles provide a reviewable YAML/JSON representation of `grant_*` and `project_set_*`. Legacy `policy_*` records remain readable by runtime compatibility code but are not modified by policy bundle apply.

Export the current production state before creating a Git-managed bundle:

```bash
sudo -u auth isolate policy export --output /opt/auth/configs/policy.yml
```

Example bundle:

```yaml
schema_version: 2
project_sets:
  - schema_version: 2
    name: production
    projects:
      - payments-prod
      - reporting-prod
    project_globs:
      - "poker-*-prod"
grants:
  - schema_version: 2
    subject: group
    name: Demo-Support
    project_set: production
    remote_user: support
    sudo_mode: none
    allowed_actions:
      - ssh
```

Validate selectors, project-set references, required remote users, duplicate IDs, and conflicting rules:

```bash
isolate policy validate --file /opt/auth/configs/policy.yml
```

Compare the file with Redis without changing anything:

```bash
isolate policy diff --file /opt/auth/configs/policy.yml
isolate policy apply --file /opt/auth/configs/policy.yml --dry-run
```

Apply reviewed additions and updates:

```bash
sudo -u auth isolate policy apply --file /opt/auth/configs/policy.yml --yes
```

Apply the file as the complete source of truth and remove Redis grants/project sets absent from it:

```bash
sudo -u auth isolate policy apply --file /opt/auth/configs/policy.yml --prune --yes
```

`--prune` is never implicit. Before a real change, Isolate writes a private backup to `/opt/auth/backups/policy-<timestamp>.yml`. Existing IDs are preserved when an exported bundle is edited, and a matching natural selector updates the existing rule instead of creating a duplicate.

### Optional Signed GitOps Mode

The existing Redis/CLI workflow remains the default. Enable GitOps only when the team is ready to make a protected Git repository the source of truth for static grants and project sets:

```yaml
policy_as_code:
  enabled: true
  enforce_git: true
  repository: ssh://git@git.example.org/platform/isolate-policy.git
  checkout_path: /opt/auth/cache/policy-repo
  branch: main
  git_bundle_path: policy.yml
  prune: true
  require_pr_approval: true
  approval_attestation_path: policy.approval.json
  approval_key_file: /opt/auth/keys/policy_approval_hmac.key
  minimum_approvals: 2
  backup_dir: /opt/auth/backups
  require_confirmation: true
```

When GitOps is enabled, PR approval attestation is mandatory and cannot be disabled. The attestation is signed by trusted CI and binds the target branch, exact SHA-256 of `policy.yml`, approver identities, and optional PR URL. It deliberately signs the policy content rather than the containing commit, avoiding an impossible self-referential commit hash.

Generate a 32-byte-or-longer shared HMAC key once and provision it independently to protected CI secrets and the bastion. Do not commit the key:

```bash
sudo openssl rand -hex 32 | sudo tee /opt/auth/keys/policy_approval_hmac.key >/dev/null
sudo chown auth:auth /opt/auth/keys/policy_approval_hmac.key
sudo chmod 0600 /opt/auth/keys/policy_approval_hmac.key
```

After CI has verified the required PR approvals, it can produce the repository attestation:

```bash
ISOLATE_CONFIG=/run/secrets/isolate-ci.yml isolate policy attest \
  --file policy.yml \
  --branch main \
  --approver demo.reviewer-one \
  --approver demo.reviewer-two \
  --pr-url https://git.example.org/platform/isolate-policy/merge_requests/42 \
  --output policy.approval.json
```

Commit the generated `policy.approval.json` to the reviewed branch. If CI appends it after the first review, configure branch protection to require approval of the final commit as well. A changed policy invalidates the old attestation even if the filename and approver list are copied.

Operator workflow:

```bash
# Local bundle checks
isolate policy validate --file policy.yml
isolate policy diff --file policy.yml --prune
isolate policy blast-radius --file policy.yml --prune

# Fetch the configured branch and verify CI approval; no writes
sudo -u auth isolate policy drift --git
sudo -u auth isolate policy sync --dry-run

# Snapshot Redis, then apply the signed revision
sudo -u auth isolate policy sync --yes

# Inspect and roll back snapshots
sudo -u auth isolate policy revisions
sudo -u auth isolate policy rollback --revision <revision-id> --yes
```

`blast-radius` reports gained, lost, and changed access for every known subject/action/host combination. Exit code `3` from `policy drift` means valid policy drift was found; exit code `2` means validation, Git, or approval verification failed. With `prune: true`, Git is authoritative for static policy, but active temporary break-glass grants are intentionally preserved. `enforce_git: true` blocks manual static grant/project-set mutations in CLI and dashboard; access-request approval continues to create expiring grants.

For periodic pull/apply, install the supplied units and enable the timer explicitly:

```bash
sudo install -o root -g root -m 0644 /opt/auth/deploy/systemd/isolate-policy-sync.service /etc/systemd/system/
sudo install -o root -g root -m 0644 /opt/auth/deploy/systemd/isolate-policy-sync.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now isolate-policy-sync.timer
```

The timer is never enabled by default. With Ansible, set `isolate_enable_policy_sync_timer: true`. A manual rollback creates another pre-rollback snapshot; pause the timer if the Git branch still points to the revision being rolled back.

## Central Audit Pipeline

Per-session `/opt/auth/logs/<user>/<session_id>/session.jsonl` remains the local source for dashboard history and replay metadata. For SIEM collection use the stable `/opt/auth/spool/events.jsonl` feed produced by `isolate-audit-export.service`. Do not configure the same shipper to collect the source files as well: runtime sinks and session logs may contain copies of the same event.

Install on a root-managed bastion with the runtime already present:

```bash
sudo bash /opt/auth/deploy/install-audit-export.sh
sudo systemctl status isolate-audit-export.service
```

The exporter reads session JSONL and, if enabled, the runtime `audit.jsonl` spool (including numbered and gzip rotations). It discovers new files every two seconds and starts each new source at the beginning. Persistent SQLite positions and a content digest index in `/var/lib/isolate/audit-export` prevent ordinary rereads and duplicate exports. Source offsets commit only after the output has been flushed with `fsync`. An output or database failure stops the service and systemd restarts it. A malformed/oversized source record blocks that source at its last checkpoint and produces a journal error; other sources continue. Monitor these errors and repair the source rather than silently dropping it.

New runtime events receive `event_id` before signing. The exporter preserves event contents and signatures, including legacy records. After a crash between output `fsync` and checkpoint commit, an event can be exported again with the same `event_id`; downstream deduplication, where needed, is separate. Keep the state directory across service restarts and upgrades. The digest index grows with exported events; include it in disk monitoring. Deleting it causes retained sources to be replayed.

Run the exporter as `auth`, with read access to session directories and exclusive write access to the output/state. Do not grant interactive users write access to the common feed or the signing key. Exporting an unsigned event does not verify or authenticate its origin. The exporter cannot recover files that were removed by retention before it read them; monitor service health, disk space, input retention and SIEM queues.

An optional low-latency runtime sink is an append-only local spool:

```yaml
logging:
  base_path: /opt/auth/logs
  fail_closed: false
  retention_days: 90
  sinks:
    - type: jsonl
      path: /opt/auth/spool/audit.jsonl
```

Runtime processes that can write the spool append their structured events there. Enable this sink for events without a session file, such as service/API audit. The exporter also reads session files from individual bastion users who cannot write the spool. Starter Vector and Filebeat configurations now collect only the exported `events.jsonl` feed.

### Wazuh 4.14

Create the stable feed by starting the exporter before starting/restarting the Wazuh agent. Add the following inside the agent's `<ossec_config>` (also provided in `deploy/wazuh/localfile.xml.example`):

```xml
<localfile>
  <location>/opt/auth/spool/events.jsonl</location>
  <log_format>json</log_format>
  <only-future-events max-size="1GB">no</only-future-events>
</localfile>
```

Wazuh documents wildcard rediscovery via `logcollector.vcheck_files` (64 seconds by default). `only-future-events` defaults to `yes`; setting `no` enables collection of content generated while the logcollector was stopped, within the configured catch-up size. A persistent feed avoids depending on rediscovery for every short-lived session. It does not guarantee delivery during arbitrary outages: the catch-up limit, queues, disk space and rotation still matter. The agent normally reads as root; verify access to the auth-only spool rather than making it world-readable.

The logrotate example uses rename/create for the JSONL spool instead of `copytruncate`; writers reopen the path for each append. Retain rotations longer than the expected outage, and recover archived output explicitly if the agent missed an entire rotation. Test restart, first enrollment, rotation and outages against the actual 4.14 agent/manager. Received events are distinct from alerts: configure manager rules for selected events, or `logall_json` and archives indexing if every event must be searchable. This repository does not enable manager-wide archives automatically. The `1GB` catch-up limit is finite and must be sized for the expected volume/outage.

Raw terminal logs contain a timestamp per PTY read chunk, which can be a single echoed character, plus output and terminal escape sequences. They are recordings, not a command stream. Do not ingest them as one command per line. Structured commands are `event: "command"` with `command`, `cwd`, `exit_code`/`exitcode`, `username`, `keycloak_sub`, `host_id` and `connection_id`. They come from the managed input mode or, with partial coverage, configured target hooks. Shell hooks quote callback arguments for OpenSSH's remote command string, preserving spaces, quotes, newlines and shell metacharacters as data. They remain optional, best effort and bypassable: the Bash DEBUG hook records the last simple command before the prompt, while zsh preexec records its command line. They do not cover every shell, pipeline, script, TUI, sudo transition or noninteractive execution. End-to-end SSH forwarding encrypts commands through the bastion; use target-side auditd/tlog or an equivalent audit agent for stronger target execution coverage and send that audit separately. The exporter does not infer commands from raw recordings.

The exporter preserves full records up to its 1 MiB input limit and journals a warning above 60 KiB. This is larger than Wazuh 4.14's roughly 64 KiB log message buffer; bound producer field lengths and monitor oversized records before relying on Wazuh ingestion. Do not truncate or rewrite signed events in the shipper to fit that buffer. Large records require a separate archival path. See the [4.14 buffer definitions](https://github.com/wazuh/wazuh/blob/v4.14.0/src/headers/defs.h) and [JSON file reader](https://github.com/wazuh/wazuh/blob/v4.14.0/src/logcollector/read_json.c).

References: [Wazuh localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html), [logcollector intervals](https://documentation.wazuh.com/current/user-manual/reference/internal-options.html), [manager event logging](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html).

Syslog is also supported:

```yaml
logging:
  sinks:
    - type: syslog
      address: /dev/log
      facility: authpriv
```

For tamper detection on events emitted by the auth-owned runtime, enable per-event HMAC signatures. Keep the key owner-only; interactive users must not be able to read it:

```bash
openssl rand -hex 32 | sudo tee /opt/auth/keys/audit_hmac.key >/dev/null
sudo chown auth:auth /opt/auth/keys/audit_hmac.key
sudo chmod 0600 /opt/auth/keys/audit_hmac.key
```

```yaml
logging:
  integrity:
    enabled: true
    key_file: /opt/auth/keys/audit_hmac.key
    key_id: isolate-audit-v1
```

Verify a signed JSONL file:

```bash
sudo -u auth isolate audit verify --path /opt/auth/spool/audit.jsonl
```

HMAC protects signed event contents but is not a substitute for immutable remote retention. Events written directly by individual Unix users cannot use an auth-owner-only signing key; ship per-session JSONL promptly to a write-once or access-controlled destination and treat the signed auth-owned spool as the higher-trust feed.

Keep `logging.fail_closed: false` for interactive SSH. A temporary syslog/spool failure then cannot block `s` or `g`; local session JSONL continues to be written. Alerting on VIP access, root/sudo, command events, unusual source IPs, and ticket-less break-glass requests should be configured in the downstream SIEM.

## Security Model

### Deny By Default

If no grant matches, access is denied.

### Exact Keycloak Group Names

Grant group names must match the Keycloak `groups` claim exactly.

If Keycloak sends:

```json
["Demo-DBA"]
```

Use:

```bash
isolate grant add --group Demo-DBA ...
```

If Keycloak sends:

```json
["/Demo-DBA"]
```

Use:

```bash
isolate grant add --group /Demo-DBA ...
```

### SSH Argument Hardening

Unknown SSH arguments are denied by default. Allowed extra args are configured:

```yaml
ssh:
  allowed_extra_args:
    - -v
    - -vv
    - -vvv
```

### Host Key Policy

The recommended default is:

```sshconfig
StrictHostKeyChecking accept-new
```

Avoid global `StrictHostKeyChecking no` in production.

### Config Permissions

Expected:

```text
/opt/auth/configs               auth:auth 0750
/opt/auth/configs/isolate.yml   auth:auth 0640
/opt/auth/configs/defaults.conf auth:auth 0640
```

### Log Permissions

Expected:

```text
/opt/auth/logs         auth:auth 2770
/opt/auth/logs/<user>  <user>:auth or auth:auth, mode 2770
log files              group auth, mode 0660
```

## Legacy OTP/PAM-OATH

Legacy OTP support is still possible but new deployments should prefer Keycloak.

Install packages:

```bash
apt install -y libpam-oath liboath0 liboath-dev oathtool qrencode
mkdir -p /etc/oath
touch /etc/oath/users.oath
chmod 0600 /etc/oath/users.oath
```

Generate a secret:

```bash
gen-oath-safe demo-user totp
```

Add the generated record to:

```text
/etc/oath/users.oath
```

PAM example:

```pam
auth required pam_oath.so usersfile=/etc/oath/users.oath window=20 digits=6
```

Modern OpenSSH option:

```sshconfig
KbdInteractiveAuthentication yes

Match Group auth
    AuthenticationMethods keyboard-interactive
```

Restart SSH after PAM changes.

## Quick End-To-End Demo

### 1. Login

```bash
isolate login
isolate whoami
```

### 2. Add Project Set

```bash
isolate project-set add prod-all --project-glob '*-prod'
isolate project-set show prod-all
```

### 3. Add Grant

```bash
isolate grant add \
  --group Demo-DBA \
  --project-set prod-all \
  --remote-user dba \
  --sudo-mode none
```

### 4. Search

```bash
s .
s payments-prod
```

### 5. Connect

```bash
g 10042
```

### 6. Show History

```bash
f
isolate history --host 10042
```

### 7. Request Temporary Access

```bash
isolate access request \
  --project payments-prod \
  --host 10042 \
  --remote-user dba \
  --sudo-mode none \
  --reason DEMO-INC-1001
```

### 8. Approve Temporary Access

```bash
isolate access list --status pending
isolate access approve --id 1 --ttl 2h
```

### 9. Start Dashboard

```bash
python3 /opt/auth/shared/isolate_web.py
```

Open:

```text
https://bastion.example.org
```

## Development Verification

Compile Python files:

```powershell
py -3 -m compileall shared wrappers tests
```

Run tests:

```powershell
py -3 -m unittest discover -s tests
```

Current focused tests cover:

- grant precedence;
- project-set and project-glob matching;
- grant list and update helpers;
- connection history parsing and ACL;
- break-glass access request approval flow;
- active session registry;
- dashboard admin group checks;
- trusted JWT identity verification;
- JWKS cache safety;
- identity cache roundtrip and expiry;
- safe SSH argv generation;
- SSH unknown argument rejection;
- Keycloak claim normalization.

## Troubleshooting

### `s` Or `g` Not Found

Check shell source:

```bash
grep isolate /etc/bash.bashrc
source /etc/bash.bashrc
type s
type g
type isolate
```

Check permissions:

```bash
id demo-user
namei -l /opt/auth/shared/bash.sh
sudo bash /opt/auth/scripts/fix-perms.sh
```

### `isolate login` Fails With Permission Denied

Check:

```bash
id demo-user
ls -l /opt/auth/shared/isolate.py
test -x /opt/auth/shared/isolate.py && echo OK
sudo bash /opt/auth/scripts/fix-perms.sh
```

Expected:

```text
/opt/auth/shared/isolate.py auth:auth 0750
```

### Config Permission Error

Check:

```bash
sudo -u auth test -r /opt/auth/configs/isolate.yml && echo OK
sudo -u auth test -r /opt/auth/configs/defaults.conf && echo OK
namei -l /opt/auth/configs/isolate.yml
```

Repair:

```bash
sudo bash /opt/auth/scripts/fix-perms.sh
```

### Log Permission Error

Check:

```bash
id demo-user
ls -ld /opt/auth /opt/auth/logs /opt/auth/logs/demo-user
namei -l /opt/auth/logs/demo-user/<failed-file>
```

Repair:

```bash
sudo bash /opt/auth/scripts/fix-perms.sh
```

### SSH Asks For Remote Password

Check whether the bastion public key exists in the remote user's `authorized_keys`.

From bastion:

```bash
sudo -u auth ssh -i /home/auth/.ssh/id_rsa dba@192.0.2.42
```

If this asks for a password, install `/home/auth/.ssh/id_rsa.pub` on the target remote user.

### SSH Asks For Sudo Password

If the prompt is:

```text
[sudo] password for dba:
```

SSH key login worked, but remote `sudo -i` needs a password.

Use grant no-sudo mode:

```bash
isolate grant update --id 7 --sudo-mode none
```

Or configure passwordless sudo for that remote user on the target host.

### Backspace, Delete, Arrows, Or History Do Not Work After `g`

Ensure TTY allocation is enabled:

```yaml
ssh:
  allocate_tty: true
```

The wrapper must pass `-tt` to OpenSSH for interactive remote shells.

### Policy Denied

Check identity:

```bash
isolate whoami
```

Check grants:

```bash
isolate grant list
isolate grant test --user demo.alex --group Demo-DBA --project payments-prod --host 10042
```

Check project sets:

```bash
isolate project-set list
isolate project-set show prod-all
```

Request temporary access:

```bash
isolate access request --project payments-prod --host 10042 --remote-user dba --sudo-mode none --reason DEMO-INC-1001
```

### Keycloak HTTP Error

Validate device endpoint:

```bash
ISSUER='https://keycloak.example.org/realms/demo-infra'
CLIENT_ID='isolate-bastion'
CLIENT_SECRET='CHANGE_ME_CLIENT_SECRET'

curl -i -X POST "$ISSUER/protocol/openid-connect/auth/device" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "scope=openid profile email groups"
```

The client sends:

```text
User-Agent: isolate-bastion/2.0
Accept: application/json
```

Keep `tls_verify: true` in production.

### Dashboard 403

For an administrative route, check Keycloak groups in the token:

```bash
isolate login
isolate whoami
```

Ensure one group matches:

```yaml
dashboard:
  admin_groups:
    - Demo-DevOps
    - Demo-Security
```

An ordinary signed-in user without a project management role should use `/me`;
administrative routes correctly return 403. A scoped operator should check the
role's permissions and project selectors in `dashboard.role_bindings` instead of
assuming full administrator access. If `/me` is denied too, check `dashboard.self_service_enabled` and any exact
`dashboard.self_service_groups` restriction. Do not add users to admin groups just
to let them request access or view their own activity.

### Redis Debug

Open Redis CLI:

```bash
redis-dev
```

Useful key patterns:

```bash
keys server_*
keys grant_*
keys project_set_*
keys access_request_*
keys active_session_*
```

## Running service discovery (opt-in)

For a fresh isolated contractor host, use the root-managed closed staging profile
and procedures in [deploy/CLOSED-BASTION.md](deploy/CLOSED-BASTION.md). The SSH
wrapper now verifies identity and policy itself; deploy the helper, callback,
authorization module and wrapper together. Review the documented migration steps
before upgrading existing installations. Incoming ProxyJump/ProxyCommand gateway
authorization remains a separate implementation step and is disabled in staging.

Merge `configs/service-discovery.example.yml` into the runtime config, select explicit
`host_ids`, and set `enabled: true`. Provision a dedicated `remote_user` with a bastion
SSH key and permission to list systemd units. It does not need sudo. Install trusted
host keys first; discovery always uses strict host key checking and batch mode.
For stronger restrictions, use a dedicated key with a forced command matching
`LC_ALL=C systemctl list-units --type=service --state=running --plain --no-legend --no-pager`
and disable PTY, forwarding and agent forwarding for that key.

Run one refresh as the bastion account before enabling the timer:

```bash
sudo -u auth python3 /opt/auth/scripts/isolate-service-discovery.py
sudo cp /opt/auth/deploy/systemd/isolate-service-discovery.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now isolate-service-discovery.timer
journalctl -u isolate-service-discovery.service
```

The timer scans hourly with jitter. Snapshots live in separate `host_services_*`
Redis records. CLI host tables and Dashboard Inventory combine manual descriptions
with discovered services, their UTC scan time, and the latest failure indicator.
A failed scan retains the last successful list; a successful empty scan clears it.
Discovery detects running systemd units, not every installed package, container,
application version, or service hidden inside another namespace. Container discovery
should use a separate restricted collector rather than granting Docker socket access.
Default backups include `host_services_*`; add this pattern to existing customized
backup configurations if the last scan snapshot must survive restore.

Successful scans also retain a bounded history of the latest 50 change records
inside each host's discovery snapshot. The first successful scan is a baseline,
with no claim that all detected services just appeared. Later records list added
and removed units. An unchanged successful scan refreshes the scan timestamp
without duplicating history; a failed scan preserves both the last successful
service list and the change timeline. A successful empty list records removals.

```bash
isolate host services-history 10004
isolate host services-history 10004 --limit 50 --json
```

Dashboard Inventory links to `/inventory/10004/services` for the same timeline and
UTC observation times. The timeline is a difference between scan observations,
not a continuous log of service starts and stops between scans. Because it remains
inside `host_services_*`, existing snapshot backup coverage includes the timeline.

## Dashboard identity and incident diagnosis

The sidebar shows the effective Dashboard role, exact groups granting Dashboard
access, all verified OIDC groups, and Keycloak realm roles. Group names come from
the verified login claims; configure the Keycloak groups mapper to include AD-derived
groups in the ID token. The panel cannot identify an AD group that Keycloak did not
include. All matching admin groups are shown because access can be granted by more
than one group.

Every response includes `X-Request-ID`. An unexpected 500 shows that ID to the user
and logs it with method/path beside Flask's traceback. Inspect the actual running
service's logs (systemd, container, or process supervisor) to determine the cause;
do not infer it from a successful unauthenticated `/health` check. After deployment,
check `/health`, `/login`, a real OIDC login, and the authenticated `/` route. Verify
that ordinary users without project roles reach `/me` and still receive 403 on
administrative routes such as `/inventory`, `/grants`, `/raw/...`, and
`/export/inventory`. Verify that scoped operators can enter permitted project
pages while other-project objects, exports, and policy management remain denied.
Monitoring should include the authenticated
page with a dedicated test identity and alert on HTTP 5xx rates; dependency health
alone does not exercise page rendering. This repository does not automatically
provision that monitor or its credentials.

Dashboard OIDC calls use `keycloak.http_connect_timeout: 2` and
`keycloak.http_read_timeout: 3` seconds for metadata, token exchange, and JWKS.
Network failures produce 503 with a retry hint and request ID; invalid OAuth state
or token validation produces 401. Signature verification remains required.
Probe every DNS address of the issuer from the Dashboard service environment:
one unreachable address combined with Requests' unlimited default timeout can
stall sign-in until Gunicorn kills its worker. IPv6 working in curl does not imply
Requests uses it: urllib3 tests IPv6 loopback availability. Correct outbound routing
to the issuer's addresses and monitor metadata/JWKS availability as well as page
rendering. Raising the Gunicorn timeout alone leaves the stalled connection intact.

Keep global Admin for configuration and policy mutations. The `/me` workspace
serves resource cards, personal sessions, history, and requests with server-side
ownership checks. Project-scoped management roles add delegated inventory,
approval, and audit operations with object and export scope enforcement. Assign
those roles explicitly in trusted configuration; a personal workspace does not
assign a project role or create an SSH grant.

The reported duplicate `raw_log_path` SSH traceback is already fixed in the local
wrapper: metadata holds the path once and both audit events use that metadata.
`tests/test_ssh_wrapper.py` guards this behavior. If production still shows the
duplicate keyword exception, compare the deployed wrapper to this version and
deploy the fix to the actual bastion; a Dashboard reload does not update a stale
SSH wrapper.

## Compatibility Notes

- Existing `server_*` host records are still read.
- Existing `auth-add-host`, `auth-dump-host`, `auth-del-host`, `s`, `g`, and `p` workflows remain available.
- New grants are stored as `grant_*`.
- Project sets are stored as `project_set_*`.
- Access requests are stored as `access_request_*`.
- Active sessions are stored as `active_session_*`.
- Existing `policy_*` rules are still read as compatibility grants.
- `StrictHostKeyChecking no` is no longer the recommended default.
- `UseRoaming` was removed because modern OpenSSH no longer supports it.

## Production Checklist

- Run `isolate config validate --check-paths` and `isolate health`.
- Configure Keycloak Device Authorization Grant for CLI.
- Configure Keycloak Authorization Code callback for dashboard.
- Ensure `groups` claim is present in tokens.
- Ensure `groups` claim is present in the signed `id_token`.
- Refresh trusted JWKS cache with `sudo -u auth /opt/auth/shared/isolate.py jwks refresh`.
- Define admin groups for access, history, and dashboard.
- Create project sets.
- Create grants.
- Verify `s .` only shows allowed hosts.
- Verify `g <host>` uses expected remote user.
- Verify deny-by-default behavior.
- Verify break-glass request and approval flow.
- Verify eligible non-admin access to `/me`, ownership isolation, and 403 on administrative dashboard routes.
- Verify each project role's permitted pages, cross-project denials, and filtered exports.
- If session approvals are enabled, verify quorum, self-approval denial, timeout, single-use consumption, and revocation on a real SSH connection.
- Run the dashboard through Gunicorn/systemd behind HTTPS, not Flask's development server.
- Keep Redis local or enable an ACL user and verified TLS before exposing it over the network.
- Export the current policy bundle, commit it for review, and test `policy diff`/`apply --dry-run`.
- Use `--prune` only after reviewing the complete policy bundle and automatic backup location.
- Configure session retention and verify the prune script in dry-run mode.
- Enable the local audit spool and asynchronous Vector/Filebeat shipping when central search is required.
- Store the audit HMAC key as `auth:auth 0600` and periodically verify shipped JSONL signatures.
- Enable the backup timer explicitly, copy verified archives off-host, and test staged recovery regularly.
- Keep MCP disabled until its dedicated Keycloak audience, scopes, HTTPS proxy, and Host allowlist are configured.
- Verify `/opt/auth/scripts/fix-perms.sh` after deploy.
- Verify `/home/auth/.ssh/id_rsa.pub` is installed for required remote users.
- Alert in the SIEM on VIP, sudo/root, break-glass, denied policy, and unusual source-IP events.
