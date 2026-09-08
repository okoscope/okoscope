#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
docs=("$root/README.md" "$root/docs/installation.md" "$root/docs/self-hosted-deployment.md")

for expected in \
  'oci://ghcr.io/okoscope/charts/okoscope-agent' \
  'oci://ghcr.io/okoscope/charts/okoscope' \
  'database-url' \
  'credentialSecret' \
  'database.existingSecret' \
  'OKOSCOPE_API_UPSTREAM'; do
  grep -q "$expected" "${docs[@]}"
done

if grep -Ei 'new bundled installation|okoscope chart.*(installs|bundles).*postgres|postgresql.enabled' "${docs[@]}"; then
  echo 'public installation docs contain prohibited bundled-PostgreSQL guidance' >&2
  exit 1
fi

helm show values "$root/deploy/helm/okoscope" | grep -q '^database:'
helm show values "$root/deploy/helm/okoscope-agent" | grep -q '^workloads:'

required_migration=$(sed -n 's/^pub const REQUIRED_MIGRATION: i64 = \([0-9][0-9]*\);/\1/p' "$root/crates/server/src/database.rs")
grep -q "requiredDatabaseMigration: $required_migration" "$root/deploy/helm/release-metadata.yaml"
grep -q "okoscope.io/required-migration: \"$required_migration\"" "$root/deploy/helm/okoscope/templates/migration.yaml"
