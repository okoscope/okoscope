#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/okoscope-workflow-test.XXXXXX)
trap 'rm -rf "$work"' EXIT
commit=3333333333333333333333333333333333333333
previous=1111111111111111111111111111111111111111
web=ghcr.io/okoscope/okoscope-web:2222222222222222222222222222222222222222

cd "$root"
deploy/scripts/render-release.sh "$work/release" "$commit" "$commit" "$web" disabled
grep -q 'name: OKOSCOPE_REGISTRATION_ENABLED' "$work/release/03-upgrade.yaml"
grep -q 'value: "false"' "$work/release/03-upgrade.yaml"
grep -q 'name: OKOSCOPE_SESSION_LIFETIME_SECONDS' "$work/release/03-upgrade.yaml"
! grep -q 'OKOSCOPE_API_CREDENTIAL\|api-credential' "$work/release/03-upgrade.yaml"
mkdir "$work/bin"
cat >"$work/bin/kubectx" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1-} == aliens ]]
MOCK
cat >"$work/bin/kubectl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
echo "$*" >>"$TEST_COMMAND_LOG"
if [[ ${1-} == get && ${2-} == secret && "$*" == *jsonpath* ]]; then
  query=${*: -1}
  case "$query" in
    *database-url*) value='postgres://user:password@postgres:5432/okoscope' ;;
    *postgres-password*) value='password' ;;
    *admin-credential*) value='admin-credential-with-at-least-32-bytes' ;;
    *webhook-encryption-key*) value='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' ;;
  esac
  printf %s "$value" | base64
fi
if [[ ${1-} == wait && "$*" == *okoscope-migrate-* && ${TEST_MIGRATION_FAIL:-false} == true ]]; then
  exit 1
fi
if [[ ${1-} == wait && "$*" == *okoscope-notification-check-* && ${TEST_CHECK_FAIL:-false} == true ]]; then
  exit 1
fi
MOCK
chmod +x "$work/bin/kubectx" "$work/bin/kubectl"
export PATH="$work/bin:$PATH"
export TEST_COMMAND_LOG="$work/commands"
real_path=${PATH#"$work/bin:"}

deploy/scripts/deploy-release.sh "$work/release"
deploy/scripts/deploy-release.sh "$work/release"
[[ $(grep -c 'apply -f .*02-migrate-' "$TEST_COMMAND_LOG") -eq 2 ]]
[[ $(grep -c 'apply -f .*02-notification-check-' "$TEST_COMMAND_LOG") -eq 2 ]]
[[ $(grep -c 'apply -f .*03-upgrade.yaml' "$TEST_COMMAND_LOG") -eq 2 ]]
! grep -q '01-install-bundled-postgres' "$TEST_COMMAND_LOG"

: >"$TEST_COMMAND_LOG"
export TEST_MIGRATION_FAIL=true
if deploy/scripts/deploy-release.sh "$work/release" >/dev/null 2>&1; then
  echo "failed migration unexpectedly advanced" >&2
  exit 1
fi
! grep -q '03-upgrade.yaml' "$TEST_COMMAND_LOG"
unset TEST_MIGRATION_FAIL

: >"$TEST_COMMAND_LOG"
export TEST_CHECK_FAIL=true
if deploy/scripts/deploy-release.sh "$work/release" >/dev/null 2>&1; then
  echo "failed notification preflight unexpectedly advanced" >&2
  exit 1
fi
! grep -q '03-upgrade.yaml' "$TEST_COMMAND_LOG"
unset TEST_CHECK_FAIL

export PATH="$real_path"
deploy/scripts/render-release.sh "$work/rollback" "$previous" "$previous" "$web" disabled
grep -Fq "ghcr.io/okoscope/okoscope-server:$previous" "$work/rollback/03-upgrade.yaml"
grep -Fq "ghcr.io/okoscope/okoscope-agent:$previous" "$work/rollback/03-upgrade.yaml"
! grep -Eq '^kind: (Secret|StatefulSet)$' "$work/rollback/03-upgrade.yaml"

echo "deployment workflow tests passed"
