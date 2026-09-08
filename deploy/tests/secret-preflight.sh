#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/okoscope-secret-test.XXXXXX)
trap 'rm -rf "$work"' EXIT

cat >"$work/kubectl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
key=${*: -1}
if [[ $key != jsonpath=* ]]; then
  exit 0
fi
key=${key#jsonpath=\{.data.}
key=${key%\}}
case "$key" in
  database-url) value=${TEST_DATABASE_URL-} ;;
  postgres-password) value=${TEST_POSTGRES_PASSWORD-} ;;
  admin-credential) value=${TEST_ADMIN_CREDENTIAL-} ;;
  webhook-encryption-key) value=${TEST_WEBHOOK_KEY-} ;;
  *) value= ;;
esac
if [[ -n $value ]]; then
  printf %s "$value" | base64
fi
exit 0
MOCK
chmod +x "$work/kubectl"
export PATH="$work:$PATH"
export TEST_DATABASE_URL='postgres://user:password@postgres:5432/okoscope'
export TEST_POSTGRES_PASSWORD='password'
export TEST_ADMIN_CREDENTIAL='admin-credential-with-at-least-32-bytes'
export TEST_WEBHOOK_KEY='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'

deploy_log="$work/output"
cd "$root"
deploy/scripts/preflight-secret.sh okoscope okoscope-secrets >"$deploy_log" 2>&1
grep -q 'values redacted' "$deploy_log"
export TEST_WEBHOOK_KEY='0000000000000000000000000000000000000000000000000000000000000000'
if deploy/scripts/preflight-secret.sh okoscope okoscope-secrets >"$deploy_log" 2>&1; then
  echo "development key unexpectedly passed" >&2
  exit 1
fi

! grep -R -q '^kind: Secret$' deploy/kubernetes/server deploy/kubernetes/agent deploy/kubernetes/frontend deploy/kubernetes/common
echo "secret preflight tests passed"
