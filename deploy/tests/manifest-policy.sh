#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/okoscope-manifest-test.XXXXXX)
trap 'rm -rf "$work"' EXIT
overlay=deploy/kubernetes/common
next_tag=1111111111111111111111111111111111111111

cd "$root"
if command -v kustomize >/dev/null 2>&1; then
  build=(kustomize build)
else
  build=(kubectl kustomize)
fi

"${build[@]}" "$overlay" >"$work/production.yaml"
test -s "$work/production.yaml"
! grep -Eq '__[A-Z0-9_]+__|:0{40}([[:space:]]|$)' "$work/production.yaml"
! grep -q '^kind: Secret$' "$work/production.yaml"
! grep -q '^kind: StatefulSet$' "$work/production.yaml"
[[ $(grep -Ec 'image: ghcr.io/okoscope/okoscope-server:[0-9a-f]{40}$' "$work/production.yaml") -eq 1 ]]
[[ $(grep -Ec 'image: ghcr.io/okoscope/okoscope-agent:[0-9a-f]{40}$' "$work/production.yaml") -eq 1 ]]
[[ $(grep -Ec 'image: ghcr.io/okoscope/okoscope-web:[0-9a-f]{40}$' "$work/production.yaml") -eq 1 ]]
grep -q 'OKOSCOPE_MIGRATE: "false"' "$work/production.yaml"
grep -q 'OKOSCOPE_NOTIFICATION_DELIVERY_ENABLED: "false"' "$work/production.yaml"
grep -Eq 'okoscope.io/notification-config: [0-9a-f]{12}' "$work/production.yaml"

cp -R deploy/kubernetes "$work/kubernetes"
candidate="$work/kubernetes/common/kustomization.yaml"
sed -i.bak "/name: ghcr.io\/okoscope\/okoscope-server/{n;s/newTag:.*/newTag: \"$next_tag\"/;}" "$candidate"
rm "$candidate.bak"
diff_output=$(diff -u "$overlay/kustomization.yaml" "$candidate" || true)
[[ $(printf '%s\n' "$diff_output" | grep -Ec '^[+-]    newTag: "[0-9a-f]{40}"$') -eq 2 ]]
[[ $(printf '%s\n' "$diff_output" | grep -Ev '^(---|\+\+\+|@@|[-+]    newTag: "[0-9a-f]{40}"$|[[:space:]])' | wc -l | tr -d ' ') -eq 0 ]]
"${build[@]}" "$work/kubernetes/common" >"$work/promoted.yaml"
grep -q "image: ghcr.io/okoscope/okoscope-server:$next_tag" "$work/promoted.yaml"

echo "GitOps manifest policy tests passed"
