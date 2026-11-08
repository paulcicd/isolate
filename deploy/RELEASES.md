# Verified releases and rollback

Use a trusted source checkout or verify a release artifact's checksum and
publisher provenance before staging it. A self-generated SHA-256 checks content,
not who published it. The manual `release-integrity.yml` workflow produces a
source checksum and GitHub provenance attestation; it is not a frozen runtime
dependency lock. This change does not publish an image/provider or deploy a host.

The installer copies only application source, requirements and license files.
It excludes config, keys, logs and authoritative state, refuses symlinks and
inline credentials in deployment config, creates a release-local virtual
environment, and hashes the installed dependency tree and freeze inventory.
Version directories are immutable from the installer's perspective; a changed
file, added module or changed dependency fails verification. Protect the
installation root from service-user writes; run staging as the deployment owner.

```sh
python scripts/isolate-install.py --root /opt/isolate plan \
  --source /srv/reviewed-isolate --version 2.2.0 --config /etc/isolate/isolate.yml
python scripts/isolate-install.py --root /opt/isolate stage \
  --source /srv/reviewed-isolate --version 2.2.0 --config /etc/isolate/isolate.yml \
  --expected-source-sha256 REVIEWED_SOURCE_DIGEST
python scripts/isolate-install.py --root /opt/isolate verify \
  --version 2.2.0 --expected-release-sha256 STAGED_RELEASE_DIGEST
python scripts/isolate-install.py --root /opt/isolate activate \
  --version 2.2.0 --config /etc/isolate/isolate.yml --service-user auth \
  --expected-release-sha256 STAGED_RELEASE_DIGEST --yes
```

`plan` writes nothing. `stage` does not select code or start services. `activate`
uses the candidate interpreter as the intended service user to check config,
OIDC/JWKS, private files and backing-service health, compatible SQL schema, and
authority/identity/key continuity against the currently selected interpreter.
On Linux selection metadata and code links change behind one atomic `current`
pointer. Windows metadata selection exists for development/testing; production
Gunicorn/systemd services target Linux. `status --root ...` is expressed as
`isolate-install.py --root /opt/isolate status`.

For systemd, resolve the release **before** exec rather than running a virtual
environment through a mutable `current/.venv` path:

```ini
[Service]
User=auth
Group=auth
ExecStart=/usr/bin/python3 -I -B /opt/isolate/current/scripts/isolate-run.py --root /opt/isolate dashboard --config /etc/isolate/isolate.yml
Restart=on-failure
NoNewPrivileges=true
```

`isolate-run.py` resolves the selected version once and execs its immutable
interpreter and entry point. A later code selection cannot change import paths
inside an already running worker. Keep config/secrets/runtime paths outside
release directories. Provision the service's own SSH credentials separately.

Activation does not restart live services. Remove/drain old ingress, check new
readiness and then restart/replace processes according to the deployment's
session policy. Existing SSH streams cannot transparently move between nodes;
forcing a pod/process termination closes those streams. Schedule replacement
after sessions finish, or explicitly accept the configured termination deadline.
The chart's rolling deployment and readiness checks do not promise uninterrupted
SSH during forced termination.

To select a previously verified compatible release:

```sh
python scripts/isolate-install.py --root /opt/isolate rollback \
  --version 2.1.0 --config /etc/isolate/isolate.yml --service-user auth \
  --expected-release-sha256 PREVIOUS_RELEASE_DIGEST --yes
```

Rollback repeats the same verification/preflight. It never restores a database,
signing key, revoked permission, consumed ticket or recording head. A release
whose schema range does not contain the live SQL schema is rejected. Back up
and migrate schemas explicitly using [STATE-RECOVERY.md](STATE-RECOVERY.md);
code rollback does not make an incompatible schema downgrade safe. Change IdP
and persistent keys as separate, reviewed operations, not part of code rollout.
