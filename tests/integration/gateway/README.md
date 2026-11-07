# Isolated gateway integration test

This test uses a separate Compose project and Docker network. It publishes no
host ports and does not touch the running `isolate-v2-demo` containers. All users,
passwords, TLS/SSH keys, Redis records and PostgreSQL data are synthetic fixtures.
The image builds on the existing demo bastion image; build that image first if
it is unavailable.

From the repository's `isolate` directory:

```powershell
docker compose -f tests/integration/gateway/docker-compose.yml run --build --use-aliases --rm runner
docker compose -f tests/integration/gateway/docker-compose.yml down --volumes --remove-orphans
```

The second command cleans up only this test's containers/network/fixture volume.
Run it before re-running after changing fixture certificates or the realm.

Coverage uses **real Keycloak HTTPS authorization-code login through the browser
form and the production Authlib callback**, including state/nonce, signed
subject/groups and a negative invalid-state check. User password grants are
disabled. A generated local CA is trusted explicitly by the test client,
application and Keycloak; verification is never disabled.

The resulting token authenticates the production API and produces one-use
tickets for native SSH and Web SSH. The test checks policy-selected target
identity, strict SSH known-host validation, ticket replay rejection, browser
CSRF, WebSocket input/output/resize, and real Keycloak-signed backchannel logout
over HTTPS. Logout closes an active SSH session and denies subsequent use of the
old token. Events are written to a real PostgreSQL audit index and checked for
search, replay idempotency and exclusion of bearer tokens.

The target is an ephemeral loopback AsyncSSH server that accepts only the test
gateway's generated key as `observer`. No personal bastion Linux account is
created or needed. Protocol adapter TLS and spoofing checks are also covered by
`tests/test_protocols.py`; this suite does not claim a deployed Kubernetes cluster
or real MySQL/PostgreSQL query auditing.
