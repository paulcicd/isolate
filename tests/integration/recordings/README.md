# Shared recording interoperability test

This isolated Compose project publishes no ports and never uses an external S3
account. It runs a real MinIO server over HTTPS with a generated test CA, plus
PostgreSQL 17 for the authoritative publication pointer. All credentials and
evidence are synthetic. It builds on the repository's local
`isolate-gateway-tests:local` image (see the gateway integration Dockerfile).

MinIO Community releases are source-only. The test builds the fixed upstream
security release commit `9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a` rather than
using an older published binary image. This is an interoperability fixture,
not a recommendation to deploy a particular production S3 service.

From `isolate/`:

```powershell
docker compose -f tests/integration/recordings/docker-compose.yml run --build --rm runner
docker compose -f tests/integration/recordings/docker-compose.yml down --volumes --remove-orphans
```

The checks cover real conditional/checksummed S3 PUTs, verified TLS, immutable
chunks, progressive publication, SQL authority, outbox outage/restart/idempotency,
replay after the originating files/spool disappear, missing-object detection,
and rejection of an untrusted S3 certificate. `tests/test_recordings.py` covers
additional tampering, truncation, rollback, permission and key-rotation cases.
