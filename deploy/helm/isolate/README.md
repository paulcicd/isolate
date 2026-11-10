# Isolate Helm chart

Build `Dockerfile.prod` from reviewed source, push it to your registry and set
`image.repository` plus `image.digest`. No production registry or cluster is
modified by the source build/tests. The chart consumes external PostgreSQL,
Redis, IdP and optional S3; it does not bundle single-pod databases.

Provision a private shared RWX runtime PVC and an existing Secret containing
`isolate.yml` and referenced secret files. Use absolute runtime paths under
`/var/lib/isolate` and private files under `/run/isolate/secrets`. Match dashboard
8080, gateway SSH 2222 and gateway HTTPS 8092 to the config. Known-hosts, gateway
TLS/SSH keys, SQL DSN, IdP client secret and signing keys must be provided by the
operator. Store persistent signing keys outside image/releases and retain them
across upgrades. Do not generate a different host/signing key per replica.

```sh
helm lint deploy/helm/isolate --strict
helm template access deploy/helm/isolate -f /secure/isolate-values.yml
helm upgrade --install access deploy/helm/isolate \
  -f /secure/isolate-values.yml --atomic --wait --timeout 10m
```

The default chart starts only API/dashboard. Enable `gateway.enabled`,
`jobs.enabled`, `recordings.enabled` only together with their application config
and external dependencies. Resources and replicas are configurable. `ingress`
requires a TLS Secret and the right controller annotations. HTTP `/` routes to
the API; exact `/ssh` and prefix `/protocols` route to the **HTTPS** gateway when
enabled. `/ssh/authorize` remains an API/browser page. Configure upstream TLS
verification and WebSocket support in the actual ingress controller; the default
NGINX backend-protocol annotation selects HTTPS but does not configure your CA.

Browser applications use separate exact-host Ingress resources when
`webApplications.enabled=true`, with `gateway.enabled=true` and matching runtime
`web_apps` configuration. Set `webApplications.hosts` entries with `host` and
`tlsSecret`; no wildcard or automatic public DNS is provisioned. Default NGINX
annotations select HTTPS backend and cookie affinity. Configure controller TLS
verification/SNI, WebSocket timeouts and sticky routing for the app session owner.
See [WEB-APPLICATIONS.md](../../WEB-APPLICATIONS.md) for DNS isolation and lifecycle.

App containers run as UID/GID 2000, drop all capabilities, disable privilege
escalation and service-account token mounts, and use read-only root filesystems.
Private credentials must be owner-only: native projected Secrets otherwise have
root ownership, while `fsGroup` sharing would violate the application's checks.
By default a limited root init container copies the mounted Secret to memory
with UID2000/mode0600 and prepares known runtime directories mode0700. It has
only CHOWN/FOWNER/DAC_OVERRIDE capabilities, a read-only root filesystem and no
Kubernetes API token. **This init container needs an exception to Restricted Pod
Security.** The app containers remain nonroot. The chart does not weaken secret
or recording-path validation.

For an environment requiring every container to meet Restricted Pod Security,
set `init.enabled=false` and `runtime.privateSecretsClaim` to a preprovisioned
CSI/private volume with UID2000 files mode0600, directory0700. Prepare the runtime
PVC with the same ownership/mode before installation. Do not replace owner-only
permissions with group-readable secrets or group-writable capture ancestors.

Readiness checks the control store; startup checks config/dependencies. A rolling
replacement has a 60-second termination grace period, which can close long SSH
streams. Drain/schedule replacement around active sessions as described in
[RELEASES.md](../../RELEASES.md). More replicas do not enable transparent SSH
stream migration. A shared RWX filesystem is a deployment prerequisite, not an
S3 replacement for the durable private recording outbox.

Schema operations are off by default and have no Helm lifecycle hooks. Creating
a manual migration Job requires both `migration.enabled=true`, the exact
`I_HAVE_VERIFIED_BACKUP_AND_SCHEMA_PLAN` acknowledgement, and an explicit reviewed
`migration.command` array. It uses `backoffLimit: 0`; review a failed/uncertain
operation before retrying. Helm rollback only rolls chart/code; follow SQL
recovery procedures separately. The chart is linted/rendered locally; a real
cluster's storage, ingress and policy admission still require staging validation.
