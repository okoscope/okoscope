#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
metadata="$root/deploy/helm/release-metadata.yaml"
values="$root/deploy/helm/okoscope/values.yaml"
agent_schema="$root/deploy/helm/okoscope-agent/values.schema.json"
openapi="$root/openapi/okoscope-v1.yaml"
release_workflow="$root/.github/workflows/release-charts.yml"

chart_version=$(sed -n 's/^  okoscope-agent: //p' "$metadata")
agent_version=$(sed -n 's/^  agent: //p' "$metadata")
grep -q "chartVersion: \"$chart_version\"" "$values"
grep -q "recommendedAgentVersion: \"$agent_version\"" "$values"
for key in endpoint developmentPlaintext caSecret; do grep -q "\"$key\"" "$agent_schema"; done
for key in chart_reference chart_version grpc_endpoint tls_mode credential_secret_name credential_secret_key configuration_schema_version; do grep -q "$key" "$openapi"; done
grep -q 'ca_secret_name' "$openapi"
grep -q 'ca_secret_key' "$openapi"
grep -Fq 'helm push "dist/okoscope-agent-$VERSION.tgz"' "$release_workflow"
grep -Fq 'helm push "dist/okoscope-$VERSION.tgz"' "$release_workflow"
if grep -Eq 'helm push +dist/okoscope-\*\.tgz' "$release_workflow"; then
  echo 'server chart publication must not use a glob that also matches the agent chart' >&2
  exit 1
fi

rendered=$(mktemp)
trap 'rm -f "$rendered"' EXIT
helm template onboarding "$root/deploy/helm/okoscope-agent" -f "$root/deploy/helm/fixtures/agent-hosted.yaml" > "$rendered"
grep -q 'kind: DaemonSet' "$rendered"
grep -q 'credentialSecret' "$agent_schema"
