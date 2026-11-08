# SSH compatibility and the daily workspace (roadmap 5–7)

The API-backed employee workspace is `/workspace`; scoped administration is
`/workspace/admin`. After a verified Keycloak callback, API-enabled installations
open the new workspace by default (`dashboard.workspace_enabled`). Existing
console `s/g/p/f`, legacy portal routes, target Unix identities and management
permissions remain available.

The catalogue includes authorized SSH, HTTP API, Kubernetes API, PostgreSQL and
MySQL resources. Inventory permission permits visibility, not a connection.
Cards show availability, maintenance, required approval or fresh authentication;
each connection rechecks current policy. Search supports Ctrl/Command+K and arrow
keys/Enter. Favorites, recent successful connections and terminal preferences are
stored under the verified stable subject in the configured authoritative store.
They are filtered against current visibility before pagination. Resource metadata
never contains upstream credentials or private configuration.

## Standard SSH and browser sign-in

Enable browser sign-in only with a public HTTPS dashboard, verified Keycloak and
an enabled API/gateway. No target credentials or personal bastion Unix account
are supplied by the SSH client:

```yaml
gateway:
  browser_auth:
    enabled: true
    timeout_seconds: 120
  ssh_features:
    multiple_channels: true
    max_channels: 8
    sftp: true
    scp: true
    forwarding: true
    proxy_hops: true
    max_proxy_hops: 3
connection_authorization:
  allow_proxy: true
```

```bash
ssh -p 2222 -o PreferredAuthentications=keyboard-interactive 10001@bastion.example.org
sftp -P 2222 10001@bastion.example.org
scp -P 2222 report.txt 10001@bastion.example.org:/home/support/report.txt
```

The SSH username is an inventory ID. Verify the provisioned gateway host key
through your normal known-host distribution. The client displays a confirmation
URL/code. Sign in through Keycloak, verify the resource and SSH source address,
approve only a connection you initiated, then press Enter in the SSH client.
Keyboard-interactive/ASKPASS clients receive the URL in the prompt too. The public
code is not an SSH password: the waiting transport must also hold an independent
secret proof. Approval requires browser CSRF, and the result is consumed once.
Expired, revoked and pre-recovery confirmations fail closed. Existing opaque
API tickets continue to work as one-use native SSH passwords.

## Multiple channels, transfers and forwarding

Each authenticated transport has one prepared authorization/approval lifecycle
and one strictly verified upstream SSH connection. Shell/exec, SFTP/SCP and TCP
channels have bounded counts and individual authorization. File transfer needs
both the SSH login grant and the separate `sftp` action on the selected grant:

```yaml
subject: group
name: Developers
project: application-stage
remote_user: developer
sudo_mode: none
allowed_actions: [ssh, sftp, forward]
```

SFTP v3 operations run on the target using that policy-selected account. SCP
supports modern SFTP-based clients and legacy `scp -O`; legacy SCP is terminated
locally and uses audited upstream SFTP, not an unvalidated remote shell command.
Transfers cannot acquire `sudo-i` privileges. File operations and byte counts are
audited without storing file payloads in terminal recordings. Normal target
filesystem permissions apply; the gateway does not pretend to sandbox a Unix
account that already has broad server access.

TCP forwarding needs `forward` plus an exact deployment allowlist for the resource:

```yaml
gateway:
  forwarding_targets:
    '10001':
      - host: 127.0.0.1
        address: 127.0.0.1
        port: 31500
```

`host`/`port` match the client's requested destination exactly. `address` pins the
actual IP reached **from the target**, so caller DNS names cannot choose another
route. Local `-L` and dynamic `-D` forwarding use these direct TCP channels. Remote
`-R`, agent/X11 forwarding, Unix-socket tunnels and arbitrary destinations remain
denied. Enable only the destinations needed by a workflow.

VS Code Remote SSH and JetBrains SSH workflows can use the same OpenSSH entry,
multiple exec/SFTP channels and approved TCP endpoints. Configure the IDE's remote
server to a fixed permitted loopback port (for example 31500) rather than opening
all ephemeral ports. A dedicated OpenSSH Host alias can set HostName, Port,
User=10001 and PreferredAuthentications=keyboard-interactive. IDE releases and
plugins vary: the tests validate the protocol operations and real OpenSSH,
not every VS Code/JetBrains GUI version or every possible SSH extension.

## Inventory proxy hops

`proxy_id` chains are resolved only from inventory. Every hop needs its own
current SSH grant, maintenance/step-up checks, credentials and known-host
verification. Cycles and excessive depth are rejected. Each hop requiring human
approval gets a distinct approval bound to its host/identity; it is consumed
before upstream traffic and checked during the session. Revocation of any hop
or change of the chain closes the complete transport. OpenSSH ProxyCommand or
ProxyJump settings cannot override this route.

## Web SSH and replay

`/me/terminal` opens an empty workspace; `/me/terminal/10001` opens a resource.
Use up to eight tabs and four split panes per tab, search the terminal buffer,
adjust font/theme/scrollback, and reconnect or close individual panes. Every
pane obtains a fresh CSRF-protected ticket and has a separate recorded session.
Ctrl/Command+Shift+T opens a tab, Ctrl/Command+Shift+D splits, Ctrl/Command+Shift+F
finds text, and Alt+1…8 changes tabs. Ctrl+C remains a terminal command.

Multiline/large paste requires an explicit preview/confirmation before SSH sees
its bytes. Input is framed below the gateway message limit, including Unicode.
Closing a pane/tab/page closes its transport. Tokens, tickets and terminal data
are not stored in browser storage. Profile settings are allowlisted on the server.

Replay supports playback, seek, speed, search, readable text and personal
timestamp bookmarks. Owners can read their recordings by stable subject;
auditors require the recording's current project scope. Bookmark reads/writes
re-authorize the recording, are subject-owned, and mutations require CSRF for
browser sessions. Labels are rendered as text. Storage errors fail explicitly.

Native SSH multiplex recordings share the transport's terminal transcript; channel
start/end events identify individual channels. Web panes have independent
transcripts. SFTP payloads and forwarded binary streams are not terminal output.
Transport closure does not undo commands or kill deliberately detached processes.

All new SSH capabilities are disabled by default. Stage the config/grants, test
allowed and denied cases, Keycloak group removal/logout, each hop's approvals,
and client compatibility before production activation. See the gateway and UI
integration READMEs for repeatable synthetic checks. Roadmap item 11 and later
protocol-deepening blocks are separate from this implementation.

## Verification

Local full suites: **509 tests on Linux** with no skips/failures, and **509 tests
on Windows** with 9 Unix-only skips and no failures. Those skips were exercised
by the Linux run. Node tests cover the shared UI helpers, Unicode framing,
paste guard, search and replay math. The real HTTPS Keycloak/PostgreSQL/Redis
suite covers standard OpenSSH browser sign-in, concurrent channels, SFTP, job
lifecycle and backchannel logout. The Playwright/Edge suite covers real local
WebSocket-to-SSH exchanges and desktop/mobile screenshots, not mocked socket
responses. See `tests/integration/ui/README.md` to repeat it.

The GitHub workflow includes the new browser test and screenshot artifact. It
was checked locally; no remote workflow, production migration or service
activation is performed by this change. These checks establish the tested
behaviors, not universal IDE compatibility or an infrastructure availability SLA.

The native suite also checks that an authenticated but idle transport expires
before any channel is opened, so a ControlMaster connection cannot keep an old
authorization indefinitely.
