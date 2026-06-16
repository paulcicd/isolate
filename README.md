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
  password: CHANGE_ME_STRONG_PASSWORD

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

dashboard:
  enabled: true
  listen_host: 127.0.0.1
  listen_port: 8080
  public_url: https://bastion.example.org
  secret_key_file: /opt/auth/keys/dashboard_secret
  admin_groups:
    - Demo-DevOps
    - Demo-Security

policy:
  default_allowed_actions:
    - ssh
  fallback_remote_user: null
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
  --user support
```

Arguments:

- `--project`: project name.
- `--server-name`: friendly host name.
- `--ip`: target server IP address.
- `--port`: target SSH port.
- `--user`: default remote user from legacy config.
- `--nosudo`: legacy flag to avoid remote `sudo -i`.

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
  --reason DEMO-INC-1001
```

Arguments:

- `--project`: required project.
- `--host`: optional exact host.
- `--remote-user`: requested target Linux user.
- `--sudo-mode`: requested sudo mode.
- `--reason`: required business reason or incident id.

### Admin Lists Pending Requests

```bash
isolate access list --status pending
```

Other filters:

```bash
isolate access list --user demo.alex
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
isolate access approve --id 12 --ttl 2h
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
isolate access deny --id 12 --reason "Use staging environment first"
```

### Access Admins

Access admins are configured by Keycloak groups:

```yaml
access:
  admin_groups:
    - Demo-DevOps
    - Demo-Security
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

The dashboard can link to raw transcripts for admins.

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
- `/access`: access requests.
- `/grants`: grants and project sets.
- `/raw/<user>/<connection_id>`: raw transcript for admins.

The dashboard is admin-only. If a user is authenticated but does not belong to `dashboard.admin_groups`, the dashboard returns HTTP 403.

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
- Verify `/opt/auth/scripts/fix-perms.sh` after deploy.
- Verify `/home/auth/.ssh/id_rsa.pub` is installed for required remote users.
- Ship `/opt/auth/logs/*/session.jsonl` to the central logging stack if needed.
