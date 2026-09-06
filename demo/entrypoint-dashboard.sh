#!/usr/bin/env bash
set -euo pipefail

bash --norc /opt/auth/scripts/fix-perms.sh

for attempt in $(seq 1 60); do
  if python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:18080/realms/isolate-demo/.well-known/openid-configuration', timeout=2)" >/dev/null 2>&1; then
    break
  fi
  if [[ "$attempt" -eq 60 ]]; then
    echo "Keycloak discovery was not ready after 120 seconds" >&2
    exit 1
  fi
  sleep 2
done

exec runuser -u auth -- /usr/local/bin/gunicorn \
  --chdir /opt/auth/shared \
  --workers 2 \
  --threads 4 \
  --timeout 30 \
  --bind 0.0.0.0:18081 \
  --access-logfile - \
  --error-logfile - \
  'isolate_web:create_app()'
