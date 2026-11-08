# Shared session recordings

The optional S3 archive publishes protected session JSONL and raw terminal files
from gateway sessions and the legacy SSH wrapper. SQL authority is required.
The local capture, outbox and cache directories belong to the service user,
mode 0700; files use 0600. Unlike legacy human-writable log directories, these
paths must have no group/world-writable ancestors. Provision them before rollout.

```yaml
recordings:
  enabled: true
  backend: s3
  bucket: company-isolate-evidence
  prefix: isolate
  endpoint_url: https://s3.example.org
  region: us-east-1
  ca_bundle: /opt/auth/keys/storage_ca.pem
  capture_path: /opt/auth/spool/evidence
  outbox_path: /opt/auth/spool/recordings
  cache_path: /opt/auth/cache/recordings
  signing_key_file: /opt/auth/keys/recordings_hmac.key
  chunk_bytes: 262144
  upload_interval_seconds: 2
  max_outbox_age_seconds: 300
```

For AWS S3 omit the custom endpoint/CA as appropriate. Use the standard AWS
credential chain, preferably an instance/workload role. Do not put credentials
in URLs or application YAML. HTTPS certificate verification is mandatory.
Grant access only to the intended bucket/prefix. Provision server-side storage
encryption and retention/Object Lock according to your deployment's evidence
policy; the application does not configure those bucket features.

Generate a private signing key of at least 32 random bytes. All publishing and
reading nodes need the same active key. To rotate, set `signing_key_id` for new
manifests and retain old `verification_key_files: {old-id: /protected/old-key}`
on readers until every retained recording using that key has expired.

Install `deploy/systemd/isolate-recording-worker.service` on each capturing node
with that node's config. It retries the durable outbox and does not delete
evidence. A manual single pass is:

```bash
python3 /opt/auth/scripts/isolate-recording-worker.py --config /opt/auth/configs/isolate.yml --once
```

Capture fsyncs locally before publication. The worker uploads content-addressed
immutable chunks and signed revision manifests with conditional writes, then
commits the authoritative revision/digest in SQL. A failed upload keeps the
outbox for retry; a process crash can repair a missing queue descriptor from
its durable capture state. Live snapshots are coalesced and finalization
publishes the complete prefix. SQL rejects rollback of the published head.

History, replay and live tails can read the latest published revision from any
node. Authorize signed session metadata before fetching terminal chunks; verify
their digests even when cached. Missing/tampered objects fail explicitly, without
falling back to a same-ID legacy log. Legacy logs remain readable only when no
published recording exists. Cross-node live tails have publication lag; they
do not resume an SSH stream or provide an owning-node streaming router.

Monitor `isolate health --json`: the recording check reports local pending count
and oldest queue age; it becomes unhealthy beyond `max_outbox_age_seconds`.
This local check does not contact S3. Alert on worker publication failures,
spool disk capacity and oldest pending age. An S3 outage permits capture while
protected local storage is healthy; failed local capture follows the configured
audit failure behavior. Losing a node's disk before publication loses its
unpublished tail. Do not promise zero evidence RPO without durable node storage.

Back up SQL recording heads and signing keys together with S3 evidence. SQL
heads, manifests and chunks form one retention unit; bucket lifecycle policies
must not delete referenced chunks. This version deliberately has no automatic
evidence/chunk garbage collector. Reconcile pending outboxes before deleting
capture files. The real HTTPS MinIO/PostgreSQL interoperability test is documented
in `tests/integration/recordings/README.md`.
