# Isolate Terraform provider

This is an executable [Terraform Plugin Framework](https://developer.hashicorp.com/terraform/plugin/framework) provider, with `isolate_host` and `isolate_grant` resources. It calls the versioned administration API. It does not manage access requests, ephemeral approvals, connection tickets, target passwords, SSH private keys, or remote commands.

The source address is `isolate/isolate`; the provider is included in this repository and is **not published to the Terraform Registry**. Build and install it locally or distribute a reviewed binary through your organization's provider filesystem mirror.

## Build and local verification

Use Go 1.25 or later and Terraform 1.9 or later:

```sh
go test ./...
go build -o .build/terraform-provider-isolate .
```

On Windows add `.exe` to the binary name. For local development create a Terraform CLI configuration outside the module:

```hcl
provider_installation {
  dev_overrides {
    "isolate/isolate" = "/absolute/path/to/terraform-provider-isolate/.build"
  }
  direct {}
}
```

Set `TF_CLI_CONFIG_FILE` to that file. With the development override, run `terraform providers schema -json`, `terraform validate`, and `terraform plan` directly in `examples/`. Do not run `terraform init` to download this unpublished provider. For deployment use a versioned, checksummed [provider filesystem mirror](https://developer.hashicorp.com/terraform/cli/config/config-file#implied-local-mirror-directories); `dev_overrides` is intended for local development.

## Authentication and authorization

Set `ISOLATE_ENDPOINT` to the trusted **HTTPS** control API origin. Provider configuration optionally accepts `endpoint`, `token_file`, and `ca_file` (additional trusted CA PEM bundle). System trust and hostname verification always apply. Redirects are refused; there is no TLS verification bypass.

Supply a short-lived OIDC **access token** using either:

- `ISOLATE_TOKEN_FILE`, or provider `token_file`, pointing to an existing private regular file; its contents are reloaded before every HTTP request, so a CI credential broker can rotate tokens during an apply. Unix permissions must be `0600` or stricter; on Windows restrict its ACL to the executing identity. Symbolic links are refused.
- `ISOLATE_TOKEN` in the Terraform process environment. Environment credentials remain fixed for that process; use a rotating file for longer runs.

There is deliberately no token configuration attribute. Token material does not enter Terraform resource state, outputs, plans, or provider diagnostics. File paths and inventory/policy attributes can enter configuration/state: keep credentials out of notes, tags and other resource fields, secure the Terraform backend, and do not commit token files. Merely marking an attribute `sensitive` would not remove its contents from state.

Prefer a dedicated workload client, explicitly enabled in `identity_security.workloads.clients.<client_id>` with `allowed_actions: [inventory.write, policy.write]`, `admin_projects: [stage]`, and matching access-token scopes `isolate.inventory.write isolate.policy.write`. Use the exact client identity and subject binding required by the configured workload policy. Human platform administrators can also use those explicit scopes. Workloads do not inherit human groups or roles. A scoped workload can only read/mutate its administrative projects; moving records requires both old and new projects to be allowed. Wildcard/glob/project-set grants require explicit `admin_projects: ['*']`; prefer exact project selectors. Do not broaden a client to global administration just to fix a plan.

The provider does not obtain client secrets or implement an IdP-specific login. Use the product's OIDC login or the organization's workload-token broker, which keeps Keycloak and other configured OIDC providers usable without putting credentials in HCL.

## Desired state and import

See [`examples/main.tf`](examples/main.tf) for both resources. Inventory field names match the API: `project_name`, `server_name`, `server_ip`, `server_user`, `server_port`, `server_nosudo`, `server_note`, `server_services`, `proxy_id`, `resource_owner`, `environment`, `tags`. The host IP is pinned; a jump host is an existing numeric inventory `proxy_id`, not a URL. The provider does not create target Unix users or SSH credentials.

Grants accept `subject` (`user`, `group`, `role`, `service`), `name`, `project`, `remote_user`, `sudo_mode` (`none` or `sudo-i`), `allowed_actions`, optional `host` selector, and optional `subject_id` stable user binding (API compatibility field `keycloak_sub`). IDs and opaque revisions are computed.

```sh
terraform import isolate_host.api 17
terraform import isolate_grant.support 42
terraform plan
```

Import and refresh read the actual object and its current revision. Reconcile configuration with imported values before applying. An empty `proxy_id` removes a jump host. Omitted owner/environment are computed from server defaults/tags; set explicit values to manage them. Managed/GitOps-owned grants are protected by the API rather than silently taken over.

Every create carries a fresh `Idempotency-Key` for that create intent and `confirm=true`; updates/deletions carry the last read `If-Match` revision and explicit confirmation. A concurrent edit fails with `409` and requires a new refresh/plan. Missing revisions fail closed. A missing object is removed from state on refresh; DELETE returns `204` and a missing object is considered deleted. There are no blind writes or automatic mutation retries.

**Uncertain create outcomes require reconciliation.** If the network fails after the server may have committed a create, inspect the inventory/grants and import the created numeric ID before applying again. The provider intentionally does not retry unknown outcomes, and a later fresh apply is a new create intent. The API rejects an uncertain replay rather than risking a duplicate mutation. Terraform destroy is a real confirmed deletion; review its plan and use Terraform `prevent_destroy` where policy requires it.

## Validation

`go test ./...` exercises real TLS HTTP fixtures for both framework resource lifecycles (create/read/update/conflict/delete/404/import), bearer and mutation guards, token-file rotation, certificate verification, refused redirects, and error redaction. The protocol schema test runs the actual framework gRPC schema handler. Server-side authorization, selector validation, managed ownership and Redis concurrency are independently covered by the Python API tests.
