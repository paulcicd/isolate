# Kubernetes interactive access

The optional streaming adapter extends Kubernetes API access with exec, attach,
logs/follow, watch and port-forward. It keeps verified HTTPS, inventory IP
pinning and upstream impersonation of the verified OIDC identity. Kubernetes
RBAC remains authoritative for each object and action.

```yaml
protocols:
  enabled: true
  targets:
    '10043':
      protocol: kubernetes
      project: payments-prod
      upstream: https://kube.internal.example:6443
      ca_file: /etc/isolate/ca/kubernetes.pem
      bearer_token_file: /etc/isolate/credentials/kubernetes-sa-token
      impersonation: true
      impersonation_user_prefix: 'isolate:'
      impersonation_group_prefix: 'isolate:'
      allowed_methods: [GET, HEAD, POST]
      allowed_paths:
        - /api
        - /api/*
        - /apis
        - /apis/*
        - /version
        - /openapi/*
      kubernetes:
        enabled: true
        allowed_namespaces: [payments]
        allowed_operations: [exec, attach, logs, watch, portforward]
        allowed_ports: [8080, 9090]
        record_output: true
        record_logs: false
        max_channels: 16
        max_frame_bytes: 1048576
        max_stream_bytes: 1073741824
        stream_timeout_seconds: 3600
```

Use narrower `allowed_paths` for a restricted resource set. Namespaced requests
must match `allowed_namespaces`; cluster-scoped object access requires an
explicit `['*']` namespace scope. Discovery GET/HEAD paths have a separate narrow
exception. API proxy subresources remain denied. Port-forward requires an exact
port allowlist. Settings do not give the upstream service account object-admin
rights: grant only required impersonation privileges and bind the resulting
prefixed subjects/groups to appropriate Kubernetes Roles.

## Grants and clients

The **selected grant** must contain `kubernetes` plus each permitted operation:

```yaml
allowed_actions:
  - kubernetes
  - kubernetes-exec
  - kubernetes-attach
  - kubernetes-logs
  - kubernetes-watch
  - kubernetes-portforward
```

Omit actions to deny channels. Existing grant precedence still applies: actions
from separate equal-priority rules are not combined. Each operation must retain
the same policy identity and sudo mode as the base authorization. Both gateway
settings and the effective grant must permit it. Changing an operation grant
closes its existing stream even if base API access remains allowed.

Use a kubeconfig cluster server of
`https://gateway.example.com/protocols/kubernetes/10043`, with its gateway CA.
Use the existing `isolate login` cache through the exec plugin:

```yaml
users:
  - name: isolate
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: python3
        args:
          - /opt/isolate/scripts/isolate-protocol-proxy.py
          - credential
          - --config
          - /home/alice/.config/isolate/config.yml
        interactiveMode: Never
```

The helper selects the configured OIDC ID/access token kind and prints only an
ExecCredential; it needs no Redis access. An expired login requires signing in
again. Use a modern kubectl with WebSocket streaming; for the verified 1.31.3
client set `KUBECTL_REMOTE_COMMAND_WEBSOCKETS=true` and
`KUBECTL_PORT_FORWARD_WEBSOCKETS=true` in its environment. Native HTTP/SPDY
upgrades are deliberately rejected rather than forwarded as opaque tunnels.

```bash
kubectl -n payments exec -it deployment/api -- sh
kubectl -n payments attach -it pod/api
kubectl -n payments logs -f pod/api
kubectl -n payments get pods --watch
kubectl -n payments port-forward pod/api 18080:8080
```

Exec/attach negotiate `v4.channel.k8s.io` or `v5.channel.k8s.io`, validate stream
directions, TTY resize and v5 half-close. Port-forward uses kubectl's
`SPDY/3.1+portforward.k8s.io` WebSocket tunnel, inspecting decompressed SPDY stream
headers and every requested port before forwarding. Closed/unknown streams,
forged channel direction and channel/frame/total-byte limits fail closed.
The dictionary's BSD license is retained in
`shared/third_party/SPDYSTREAM-LICENSE.txt`.

## Recording and lifecycle

Audit captures namespace/pod, operation, bounded channel metadata, byte counts
and a digest of exec arguments. Arguments, stdin and port-forward payloads are
excluded. With `record_output: true`, stdout/stderr use the runtime's private
recording/archive path; `record_logs: true` similarly opts into log payloads.
Output/logs may contain application secrets, so apply existing recording
permissions and retention policy.

Identity/IdP rechecks, approvals, lease ownership, policy revision, epoch,
administrator termination and operation expiry remain active throughout streams.
Permissions are checked before upgrades and forwarding channel data. Interactive
sessions are not migrated between nodes after a restart.

`tests/test_kubernetes_streams.py` exercises real TLS and an unmodified kubectl
against a deterministic Kubernetes API fixture, including all five operations
and revocation. It does not provision a real Kubernetes cluster. Validate the
chosen API-server/client versions, RBAC, ingress upgrades and network policy in
staging before activation. API impersonation details are in the
[official Kubernetes reference](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation).
