# Isolate Bastion Platform v2

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
- Safer SSH argv construction through `subprocess` arguments.
- Permission repair workflow for Git deploys.
- Verifiable service backups for configuration, credentials, host keys, and Redis state.

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
sudo bash /opt/auth/scripts/fix-perms.sh
```

Also run it after:

```bash
git reset --hard origin/master
git checkout <branch>
```

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
  admin_groups:
    - Demo-DevOps
    - Demo-Security

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

VIP and privileged access fields are informational. They do not change grants by themselves. Use them to document that ordinary non-sudo SSH access stays in Isolate, while sudo/root access is handled by an external privileged access provider such as Warpgate, Teleport, PAM, or another bastion.

If a VIP host is denied by policy and privileged access metadata is configured, `g` prints a hint with the external provider and URL.

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
- safe HTML escaping with a minimal ANSI-friendly fallback.

Configure payload limits:

```yaml
replay:
  max_bytes: 10485760
  default_speed: 1
```

### Structured Command Audit

Structured command audit is opt-in and is intentionally separate from raw PTY replay. Isolate does not try to infer commands from terminal control sequences. Instead, target hosts can install shell hooks that submit completed commands back to the bastion.

Enable it:

```yaml
command_audit:
  enabled: true
  require_connection_id: true
  max_command_length: 4096
```

Append a command event:

```bash
isolate command-log append \
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

The templates expect deployment-specific context, usually environment variables such as `ISOLATE_CONNECTION_ID`, `ISOLATE_HOST_ID`, `ISOLATE_PROJECT`, and `ISOLATE_AUDIT_BASTION`. Install them only on hosts where command audit is required.

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
  admin_groups:
    - Demo-DevOps
    - Demo-Security
```

Keycloak redirect URI:

```text
https://bastion.example.org/auth/callback
```

Routes:

- `/`: summary.
- `/login`: Keycloak login.
- `/auth/callback`: OIDC callback.
- `/logout`: logout.
- `/sessions/active`: active SSH sessions.
- `/history`: connection history.
- `/session/<connection_id>`: session details and timeline.
- `/session/<connection_id>/events.json`: session JSONL events.
- `/inventory`: read-only host inventory with service/note search.
- `/access`: access requests with filters, comments, repeat, approve, and deny forms.
- `/grants`: grants and project sets.
- `/replay/<connection_id>`: raw transcript replay MVP.
- `/replay/<connection_id>.json`: parsed replay chunks.
- `/raw/<user>/<connection_id>`: raw transcript for admins.

The dashboard is admin-only. If a user is authenticated but does not belong to `dashboard.admin_groups`, the dashboard returns HTTP 403.

The `/`, `/sessions/active`, and `/access` pages auto-refresh when `dashboard.refresh_seconds` is greater than `0`. Set it to `0` to disable refresh.

Access approval from the dashboard supports:

- TTL, for example `30m`, `2h`, or `1d`;
- optional remote user override;
- optional sudo mode override;
- ticket/user/project filters;
- approve and deny comments;
- repeat request action;
- notification warnings;
- denial reason.

Dashboard POST actions use a per-session CSRF token.

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
user isolate on >CHANGE_ME_STRONG_PASSWORD ~server_* ~grant_* ~policy_* ~project_set_* ~access_request_* ~active_session_* ~offset_* ~projects_list ~ssh_config_* +get +set +del +incr +expire +keys +ping +multi +exec +discard
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

## Central Audit Pipeline

Per-session `/opt/auth/logs/<user>/<session_id>/session.jsonl` remains the local source for dashboard history and replay metadata. The safest complete feed is Vector/Filebeat tailing these files directly with read-only access. Central runtime sinks are an additional best-effort path and are disabled by default.

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

Runtime processes that can write the spool append their structured events there. Vector or Filebeat should also tail the per-session JSONL glob so events written by individual bastion users are not missed, then ship asynchronously to OpenSearch, ClickHouse, S3, or a SIEM. Starter configurations covering both paths are available in `/opt/auth/deploy/vector/isolate.toml.example` and `/opt/auth/deploy/filebeat/isolate.yml.example`.

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

Check Keycloak groups in token:

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
- Verify dashboard 403 for non-admin users.
- Run the dashboard through Gunicorn/systemd behind HTTPS, not Flask's development server.
- Keep Redis local or enable an ACL user and verified TLS before exposing it over the network.
- Export the current policy bundle, commit it for review, and test `policy diff`/`apply --dry-run`.
- Use `--prune` only after reviewing the complete policy bundle and automatic backup location.
- Configure session retention and verify the prune script in dry-run mode.
- Enable the local audit spool and asynchronous Vector/Filebeat shipping when central search is required.
- Store the audit HMAC key as `auth:auth 0600` and periodically verify shipped JSONL signatures.
- Enable the backup timer explicitly, copy verified archives off-host, and test staged recovery regularly.
- Verify `/opt/auth/scripts/fix-perms.sh` after deploy.
- Verify `/home/auth/.ssh/id_rsa.pub` is installed for required remote users.
- Alert in the SIEM on VIP, sudo/root, break-glass, denied policy, and unusual source-IP events.
