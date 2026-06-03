# Isolate Bastion Platform

Isolate is an SSH bastion platform for managing access to large fleets of Linux servers. Users connect to the bastion first, search or select a target with the `s` and `g` helpers, and Isolate opens the SSH session while writing session metadata and logs.

This fork contains the v2 compatibility layer for modern bastion hosts:

- Ubuntu 24.04 LTS and Debian 12+ support
- Python 3 runtime
- Redis-backed host and policy storage
- Keycloak OIDC Device Authorization Grant helper
- Policy-based remote user selection
- JSONL session audit logs plus legacy raw SSH transcripts
- safer SSH command construction through `subprocess` argv

Legacy OTP/PAM-OATH setup is still documented below for compatibility, but new deployments should prefer the v2 identity and policy model.

## Requirements

### Bastion host

- Ubuntu 24.04 LTS is the primary target
- Debian 12+ should work with the same package set
- Python 3.12-era packages
- Redis
- OpenSSH server/client
- Ansible for remote deployment

Install local deployment dependencies:

```bash
apt update
apt install -y ansible git python3 python3-dev python3-pip python3-venv redis-tools
```

### Python dependencies

Runtime dependencies are listed in `requirements.txt`:

```bash
python3 -m pip install --break-system-packages -r requirements.txt
```

For development and tests on Windows, use:

```powershell
py -3 -m unittest discover -s tests
```

## Quick Deploy

### 1. Prepare inventory

Edit `ansible/hosts.ini`:

```ini
[main]
auth1.example.org ansible_ssh_host=203.0.113.10 ansible_ssh_port=22 ansible_ssh_user=root
```

### 2. Run Ansible

```bash
cd ansible
ansible-playbook main.yml -e redis_pass='CHANGE_ME_STRONG_PASSWORD'
```

The playbook creates the `auth` service user, installs Redis and system packages, deploys the repository to `/opt/auth`, installs Python dependencies with `pip3`, and applies file permissions.

Enable Git permission repair hooks on the bastion checkout:

```bash
cd /opt/auth
git config core.hooksPath .githooks
sudo bash /opt/auth/scripts/fix-perms.sh
```

Git does not preserve Unix owners/groups or the full permission model required
by the runtime. After any manual `git pull`, `git checkout`, or
`git reset --hard origin/master`, either let the hooks run or repair
permissions explicitly:

```bash
sudo bash /opt/auth/scripts/fix-perms.sh
```

### 3. Load shell helpers

Add this to `/etc/bash.bashrc` on Ubuntu/Debian:

```bash
if [ -f /opt/auth/shared/bash.sh ]; then
    source /opt/auth/shared/bash.sh
fi
```

Reload the shell:

```bash
source /etc/bash.bashrc
```

### 4. Configure sudo wrapper

Use `visudo` and add:

```sudoers
%auth ALL=(auth) NOPASSWD: /opt/auth/wrappers/ssh.py
```

### 5. Configure SSH daemon

Recommended baseline in `/etc/ssh/sshd_config`:

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

## Configuration

The v2 runtime reads configuration from:

1. `/etc/isolate/isolate.yml`
2. `/opt/auth/configs/isolate.yml`

Environment variables override file settings:

- `ISOLATE_CONFIG`
- `ISOLATE_DATA_ROOT`
- `ISOLATE_REDIS_HOST`
- `ISOLATE_REDIS_PORT`
- `ISOLATE_REDIS_DB`
- `ISOLATE_REDIS_PASS`
- `ISOLATE_KEYCLOAK_ISSUER`
- `ISOLATE_KEYCLOAK_CLIENT_ID`
- `ISOLATE_KEYCLOAK_CLIENT_SECRET`

Minimal v2 config:

```yaml
schema_version: 2
data_root: /opt/auth

redis:
  host: 127.0.0.1
  port: 6379
  db: 0
  password: CHANGE_ME_STRONG_PASSWORD

keycloak:
  issuer: https://keycloak.example.org/realms/infra
  client_id: isolate-bastion
  client_secret: null
  scopes:
    - openid
    - profile
    - email
  tls_verify: true

ssh:
  binary: /usr/bin/ssh
  config_path: /opt/auth/configs/defaults.conf
  allocate_tty: true
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

logging:
  base_path: /opt/auth/logs
  sink: local

policy:
  default_allowed_actions:
    - ssh
  fallback_remote_user: null
```

SSH client defaults live in `/opt/auth/configs/defaults.conf`:

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

## Quick Functional Test

These commands verify the main legacy flow and new v2 features on a freshly deployed bastion.

### 1. Load environment

```bash
source /etc/bash.bashrc
export ISOLATE_BACKEND=redis
export ISOLATE_REDIS_HOST=127.0.0.1
export ISOLATE_REDIS_PORT=6379
export ISOLATE_REDIS_DB=0
export ISOLATE_REDIS_PASS='CHANGE_ME_STRONG_PASSWORD'
```

### 2. Add a bastion user

```bash
auth-add-user alice
```

Log in as `alice` before testing user-facing commands.

### 3. Add a test target

Use a real SSH-reachable host:

```bash
auth-add-host --project prod --server-name test-ubuntu --ip 192.0.2.20 --port 22 --user support
```

Check it exists:

```bash
s prod
auth-dump-host 10001
```

### 4. Install the bastion key on the target

Print the helper:

```bash
add-support-user-helper
```

Run the printed commands on the target host as root. This creates the remote `support` user and installs `/home/auth/.ssh/id_rsa.pub`.

### 5. Test old workflow

Search:

```bash
s test-ubuntu
s prod
```

Connect:

```bash
g prod test-ubuntu --debug
```

Connect without remote `sudo -i`:

```bash
g prod test-ubuntu --nosudo
```

### 6. Test Keycloak device-flow login

Configure Keycloak:

```bash
export ISOLATE_KEYCLOAK_ISSUER='https://keycloak.example.org/realms/infra'
export ISOLATE_KEYCLOAK_CLIENT_ID='isolate-bastion'
```

Run:

```bash
isolate login
isolate whoami
```

Open the printed verification URL, enter the user code if required, and approve the login. The command saves normalized identity fields to `~/.isolate/identity.json`: `session_id`, `keycloak_sub`, `username`, `email`, `groups`, `roles`, and token expiration. User-facing `s` and `g` require this valid identity.

### 7. Test grant-based RBAC

Create a project set and allow a Keycloak group to access it:

```bash
isolate project-set add prod-all --project prod --project-glob '*-prod'
isolate grant add --group DevOps --project-set prod-all --remote-user support --sudo-mode none
```

Add a more specific user/host override:

```bash
isolate grant add --user alice --project prod --host 10001 --remote-user alice
```

Test resolution:

```bash
isolate grant test --user alice --group DevOps --project prod --host 10001
```

Expected result: `remote_user` is `alice`, because user+host grants have higher priority than group/project-set grants.

Now `alice` should only see hosts covered by matching grants:

```bash
s .
g prod test-ubuntu --debug
```

### 8. Test session audit logs

After running `g`, search JSONL audit events:

```bash
isolate session search --user alice --project prod
```

Logs are stored under:

```text
/opt/auth/logs/<user>/<session_id>/session.jsonl
```

Legacy raw SSH transcript and `.meta` files are still written for compatibility.

## User Commands

### Search

```bash
s <query>
s prod
s test-ubuntu
```

### Connect

```bash
g <project|host> [server_name|server_ip] [--user remote_user] [--port port] [--nosudo] [--debug]
```

Examples:

```bash
g prod test-ubuntu
g prod 192.0.2.20 --user support --port 22
g 192.0.2.20 --nosudo
```

### Projects

```bash
p
```

### Connection history

```bash
f
f kube
f 10004
f voskoboinikov
```

By default `f` shows the current user's last 10 connections. Users in
`history.admin_groups` can search other users, projects, hosts, and server ids.

## Admin Commands

### Hosts

```bash
auth-add-host --project prod --server-name web01 --ip 192.0.2.21 --port 22 --user support
auth-dump-host 10001
auth-del-host 10001
```

### Project defaults

```bash
auth-add-project-config prod --port 22 --user support
auth-dump-project-config prod
auth-del-project-config prod
```

### v2 grants and project sets

```bash
isolate project-set add prod-all --project prod --project-glob '*-prod'
isolate project-set add-pattern poker-all --project-glob 'poker*'
isolate project-set list
isolate project-set show prod-all
isolate project-set remove-project prod-all old-prod
isolate project-set remove-pattern prod-all '*-old'
isolate project-set remove prod-all

isolate grant add --group DevOps --project-set prod-all --remote-user support --sudo-mode none
isolate grant add --group OS-admin --project '*' --remote-user root --sudo-mode none
isolate grant add --group pokerteam --project-glob 'poker*' --remote-user poker-support --sudo-mode none
isolate grant add --user alice --project prod --host 10001 --remote-user alice
isolate grant list --group DevOps
isolate grant show --id 1
isolate grant update --id 1 --remote-user l2-support --sudo-mode none
isolate grant revoke --group pokerteam --project poker-old
isolate grant test --user alice --group DevOps --project prod --host 10001
```

Grant selectors are designed for large fleets:

- `--project prod` grants one exact project.
- `--project-glob '*-prod'` grants every matching project name.
- `--project-set prod-all` grants a named set containing exact projects and glob patterns.
- `--sudo-mode none` opens the remote user's normal shell. The default `sudo-i` runs `sudo -i` after SSH and therefore requires passwordless sudo on the target for that remote user.

Grant precedence:

1. user + host
2. user + project
3. group + host
4. group + project
5. project set
6. project glob

Access is denied by default. Without a valid `isolate login` identity and a matching grant, `s` hides the server and `g` refuses to connect before SSH starts.

### History admin config

Ordinary users can read only their own history. Users in configured admin groups
can query everyone:

```yaml
history:
  admin_groups:
    - DevOps
    - OS-admin
  default_limit: 10
  max_limit: 100
```

CLI equivalent:

```bash
isolate history
isolate history kube
isolate history --user voskoboinikov
isolate history --project kube --limit 20
isolate history --host 10004 --json
```

## Session Logging

v2 writes structured JSONL events:

- `helper_start`
- `policy_selected`
- `policy_denied`
- `ssh_start`
- `ssh_end`
- `ssh_argument_denied`

Each event includes session and identity fields where available:

- `session_id`
- `keycloak_sub`
- `username`
- `groups`
- `project`
- `host_id`
- `target_host`
- `remote_user`
- `source_ip`
- `exit_code`

The local JSONL sink is implemented first. It is intentionally easy to ship with Filebeat, Vector, syslog, OpenSearch, ClickHouse, S3, or another external collector.

## Keycloak Notes

Create a Keycloak client for the bastion:

- Client type: OpenID Connect
- Flow: Device Authorization Grant enabled
- Client authentication: public or confidential
- Scopes: `openid`, `profile`, `email`
- Group claim: include `groups` in the token if group-based policies are used

Set:

```bash
export ISOLATE_KEYCLOAK_ISSUER='https://keycloak.example.org/realms/infra'
export ISOLATE_KEYCLOAK_CLIENT_ID='isolate-bastion'
export ISOLATE_KEYCLOAK_CLIENT_SECRET='optional-secret'
```

Then:

```bash
isolate login
```

## Legacy OTP/PAM-OATH

For older deployments that still use OTP through PAM-OATH:

```bash
apt install -y libpam-oath liboath0 liboath-dev oathtool qrencode
mkdir -p /etc/oath
touch /etc/oath/users.oath
chmod 0600 /etc/oath/users.oath
```

Generate a user secret:

```bash
gen-oath-safe alice totp
```

Add the generated record to `/etc/oath/users.oath`.

Add to `/etc/pam.d/sshd` or your common auth stack:

```pam
auth required pam_oath.so usersfile=/etc/oath/users.oath window=20 digits=6
```

Modern OpenSSH uses `KbdInteractiveAuthentication` rather than old `ChallengeResponseAuthentication` naming:

```sshconfig
KbdInteractiveAuthentication yes

Match Group auth
    AuthenticationMethods keyboard-interactive
```

Restart SSH after PAM changes.

## Development Verification

Run syntax verification:

```powershell
py -3 -m compileall shared wrappers tests
```

Run tests:

```powershell
py -3 -m unittest discover -s tests
```

Current focused tests cover:

- grant precedence
- project-set and project-glob matching
- grant list/update helpers
- connection history parsing and ACL
- identity cache roundtrip and expiry
- deny when no remote user can be resolved
- safe SSH argv construction
- rejection of unknown SSH arguments
- Keycloak claim normalization

## Troubleshooting

Enable helper debug:

```bash
g prod test-ubuntu --debug
```

If interactive keys such as Backspace, Delete, arrows, or command history do not
work after `g`, make sure the v2 SSH config has remote TTY allocation enabled:

```yaml
ssh:
  allocate_tty: true
```

The wrapper must pass `-tt` to OpenSSH when it starts the remote `sudo -i`
session; otherwise the remote shell behaves like a non-interactive stdin script.

Open Redis with current password:

```bash
redis-dev
```

Check generated logs:

```bash
find /opt/auth/logs -type f -name 'session.jsonl' -o -name '*.meta' -o -name '*.log'
```

If a user gets `PermissionError` under `/opt/auth/logs`, verify group membership
and each directory on the path:

```bash
id <user>
ls -ld /opt/auth /opt/auth/logs /opt/auth/logs/<user>
namei -l /opt/auth/logs/<user>/<failed-file>
```

Expected log permissions:

```text
/opt/auth/logs         auth:auth 2770
/opt/auth/logs/<user>  <user>:auth or auth:auth, mode 2770
log files              group auth, mode 0660
```

Re-apply permissions after deploy:

```bash
bash /opt/auth/scripts/fix-perms.sh
```

If `g` fails with `PermissionError: /opt/auth/configs/isolate.yml`, verify that
the runtime user `auth` can read the config:

```bash
sudo -u auth test -r /opt/auth/configs/isolate.yml && echo OK
sudo -u auth test -r /opt/auth/configs/defaults.conf && echo OK
namei -l /opt/auth/configs/isolate.yml
```

Expected config permissions:

```text
/opt/auth/configs              auth:auth 0750
/opt/auth/configs/isolate.yml  auth:auth 0640
/opt/auth/configs/defaults.conf auth:auth 0640
```

Re-apply permissions:

```bash
bash /opt/auth/scripts/fix-perms.sh
```

If shell helpers disappear after a Git update, verify the whole path and repair
permissions as root:

```bash
id alice
namei -l /opt/auth/shared/bash.sh
namei -l /opt/auth/configs/isolate.yml
ls -ld /opt/auth /opt/auth/shared /opt/auth/configs /opt/auth/logs
sudo bash /opt/auth/scripts/fix-perms.sh
```

If `isolate login` fails with `Permission denied` for
`/opt/auth/shared/isolate.py`, verify that the user is in the `auth` group and
that the CLI file is executable by that group:

```bash
id <user>
ls -l /opt/auth/shared/isolate.py
test -x /opt/auth/shared/isolate.py && echo OK
```

Expected permission:

```text
/opt/auth/shared/isolate.py auth:auth 0750
```

If `isolate login` fails with a Keycloak HTTP error, the CLI prints the
response status and `error_description` when Keycloak returns JSON. Validate the
device endpoint directly:

```bash
ISSUER='https://keycloak.example.org/realms/infra'
CLIENT_ID='isolate-bastion'
CLIENT_SECRET='secret'

curl -i -X POST "$ISSUER/protocol/openid-connect/auth/device" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "scope=openid profile email"
```

The isolate client sends `User-Agent: isolate-bastion/2.0` and
`Accept: application/json` to avoid generic WAF blocks. Keep `tls_verify: true`
for production; set it to `false` only for temporary lab environments with
self-signed certificates.

Check SSH key and known hosts:

```bash
ls -la /home/auth/.ssh
ls -la /opt/auth/known_hosts
```

If policy resolution denies access, run:

```bash
isolate whoami
isolate grant test --user <username> --group <group> --project <project> --host <server_id>
```

If `isolate whoami` fails or shows an expired token, run `isolate login` again.

## Compatibility Notes

- Existing Redis `server_*` host records are still read by the helper.
- Existing `auth-add-host`, `auth-dump-host`, `auth-del-host`, `s`, `g`, and `p` workflows remain available.
- v2 grants are stored as Redis `grant_*` keys and project sets as `project_set_*` keys. Existing `policy_*` keys are still read as compatibility grants.
- The old global `StrictHostKeyChecking no` default was replaced with `accept-new` and `/opt/auth/known_hosts`.
- `UseRoaming` was removed because modern OpenSSH no longer supports it.
