# Contractor bastion staging

## Current host network override

At the owner's explicit request on 2026-10-19, host network filtering was removed:
`isolate-staging-firewall.service` and UFW are stopped and disabled, and the
nftables ruleset is empty. Outbound TCP 80/443 and an HTTPS request to the Ubuntu
repository were verified successfully. This host no longer has the closed
network posture described by the preparation defaults below. AWS security
groups, NACLs and routing were not modified or verified by this change. SSH
authentication/forwarding restrictions and Isolate authorization remain separate.
Backups are retained under `/etc/isolate/staging-backup/open-network-*`.

This is a prepared runtime, not an enabled contractor SSH gateway. Do not enable
ProxyJump or ProxyCommand by changing `AllowTcpForwarding` alone.

## Staging state

- Ubuntu EC2; root-owned application code and virtual environment under `/opt/auth`.
- Service account `auth` has `nologin`, no target SSH key, and no contractor members
  in its Unix group. `isolate-contractors` is a separate group.
- Redis listens on loopback, has ACL authentication, and rejects the default user.
- `/etc/isolate/isolate.yml` has no issuer, no grants or hosts, and
  `connection_authorization.connections_enabled: false`.
- Fresh preparation creates no contractor accounts or sudoers grants, Dashboard,
  MCP or job-worker listeners. On the current staging host, `apexdata-1` and
  `apexdata-2` have personal public keys. At the owner's explicit request on
  2026-10-19, they temporarily have ordinary `/bin/bash` SSH shell/exec and PTY
  access, with public-key-only authentication, no ForceCommand, no sudo and
  `DisableForwarding yes`. This login does not require Keycloak. Commands in
  these ordinary shells do not pass through the managed command audit boundary.
  `scripts/contractor-staging-console.py` remains an optional restricted entry,
  but is not the active SSH ForceCommand.
- `isolate-audit-export.service` maintains `/opt/auth/spool/events.jsonl` from
  per-session JSONL and the runtime spool, with persistent read positions.
  Wazuh/manager enrollment is separate; the exporter opens no network listener.
  Raw recordings stay available for replay. `command_audit.mode: managed` is
  selected for future wrapper sessions: submitted lines are durably audited
  before SSH exec, with a result event afterwards. There is no remote interactive
  stdin or persistent shell state. Contractor target connections remain disabled.
- Management SSH is public-key only, root login and all forwarding are disabled.
- Host nftables input permits SSH from the explicitly selected management CIDR.
  The current staging host uses `0.0.0.0/0` at the owner's request because its
  administrative client address is ephemeral. `ubuntu`, `apexdata-1` and
  `apexdata-2` public-key login is accepted. Target access and forwarding remain
  disabled.
  Output permits loopback, established responses, configured DNS, DHCP and EC2
  NTP. There is no new outbound SSH/HTTPS access, including to Keycloak or targets.
- AWS security groups, routes and NACLs are separate controls; the preparation
  scripts do not modify or attest them. Package updates also need an explicitly
  reviewed maintenance egress rule while this closed policy is active.

`health` validates runtime dependencies; it does not mean the realm or contractor
access is ready. The missing issuer warning is intentional during staging.

## Preparation

Run `deploy/prepare-closed-bastion.sh` as root on a fresh Ubuntu host from an
uploaded source tree. It refuses to overwrite existing Isolate installations.
Optional MCP dependencies are excluded; installed versions are captured in
`/opt/auth/requirements-installed.txt`.

Run `deploy/harden-closed-bastion.sh` as root with `ISOLATE_MANAGEMENT_IP` set to
the observed source address or explicitly approved management CIDR. It schedules a five
minute automatic rollback. Confirm a **new independent SSH connection**, inspect
the effective `sshd -T` policy and nft rules, then stop
`isolate-staging-rollback.timer`. Existing SSH is preserved during the change.
The firewall affects IPv4 and IPv6 and persists through systemd.

Never run the legacy `scripts/fix-perms.sh` on this deployment: it assumes shared
interactive access and service-owned code. The script refuses root-managed staging.
The initial administrative account is privileged and retained for management.

## Connection authorization changes

The classic helper/wrapper workflow now requires:

1. A trusted config at `/etc/isolate/isolate.yml` or `/opt/auth/configs/isolate.yml`.
   The privileged wrapper ignores caller environment config overrides and rejects
   unsafe path ownership, symlinks or group/other-writable configuration paths.
2. A signed, unexpired ID token with the exact configured issuer and audience.
   `azp` is not an audience substitute; token verification and TLS cannot be
   disabled for wrapper authorization.
3. Binding of the invoking sudo UID to the Keycloak identity. By default legacy
   installations require an exact username match. With `require_explicit_mapping`,
   every Unix account must map to its immutable Keycloak `sub` in `unix_users`.
4. A unique inventory host ID. IP, port, remote user, sudo mode, optional proxy
   and identity arguments are rechecked against inventory and current grants.
   Direct wrapper calls do not bypass policy. Proxy hosts are disabled by default;
   enabling them requires grants on both the target and the proxy.
5. Strict known-host checking, no agent forwarding or extra TCP forwards, and
   batch SSH authentication. Provision trusted host keys before enabling access.

The helper transfers only the signed ID token in a random caller-owned `/tmp`
file, readable through an ACL granted to the service UID. It is not exposed in
argv and does not require making the user's home readable. `setfacl` is required.
The callback removes the file after the connection; a timer removes crash leftovers.
Do not put contractors in the service group merely to make this handoff work.

Only diagnostic extra SSH flags are accepted by the helper. Overriding `--user`,
`--port`, identity metadata or proxy arguments after the policy decision is denied.
Changing the remote user requires an appropriate grant.

Active classic wrapper sessions recheck trusted config, signed token expiry,
inventory and current grants every five seconds by default. Revocation, expiry,
endpoint/policy change or verification/Redis failure terminates the child SSH
connection. The deadline is bounded by token expiry, grant expiry and maximum
session duration; extending a grant does not extend an already issued deadline.
Terminating SSH does not guarantee termination of detached processes on a target.

**Keycloak user blocking is not yet polled through introspection.** An otherwise
valid ID token can still be accepted until expiry. Immediate block handling needs
an online revocation mechanism when the realm and machine-access flow are designed.
Removing grants already affects the next policy check independently of Keycloak.

The administrative CLI now gates privileged command dispatch and policy mutation
on a platform administrator. Root can perform bootstrap maintenance; other users
must have an identity bound to their Unix account and an administrator group from
the trusted system config. Interactive config cannot define its own admin groups.
In addition, keep Redis credentials and runtime configs inaccessible to contractors.

## Compatibility / deployment

Deploy the new helper, bootstrap callback, authorization module and wrapper
together. Older helpers do not provide the token handoff and will be denied by
the new wrapper. Existing running SSH processes retain the code they loaded;
they are not retroactively secured by copying new files.

Legacy users whose Linux and Keycloak usernames differ need explicit `sub`
mappings before upgrade. Explicitly authorized nonstandard inventory SSH ports
remain possible with `allowed_target_ports: []`; the contractor profile limits
them to `[22]`. Existing proxy-host installations must opt in and grant both hops.

## Required before opening access

1. Realm issuer, client ID, exact audience and group mappings; personal accounts
   with mandatory MFA. Configure ID-token group claims and the correct audience.
2. Decide ProxyJump versus a forced ProxyCommand handler. Neither incoming gateway
   mode nor machine `client_credentials` to SSH-key binding is implemented here.
3. Provision controlled ingress for engineers/bots and egress only to reviewed
   targets on port 22 and the required identity/logging endpoints. Mirror it in AWS.
4. Implement a server-side restricted entry point and public/control-plane split.
   A plain `rbash`, shared config or unrestricted sudo access is not sufficient.
5. Populate inventory, expiring grants, per-target accounts and trusted host keys.
   Do not reuse the corporate bastion key or enable arbitrary remote sudo.
6. Exercise real login/MFA, key/identity binding, denied targets and ports,
   revocation of active channels, control-plane failure, audit and reconnects.
7. Only after those checks change `connections_enabled` and explicitly open the
   contractor SSH endpoint. Do not simply add contractors to `AllowUsers`.
