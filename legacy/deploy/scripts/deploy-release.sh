#!/usr/bin/env bash
set -euo pipefail

bundle=${1:?bundle directory is required}
namespace=${OKOSCOPE_NAMESPACE:-okoscope}
install=${OKOSCOPE_INSTALL_BUNDLED_POSTGRES:-false}

kubectx aliens >/dev/null
if [[ $install == true ]]; then
  kubectl apply -f "$bundle/01-install-bundled-postgres.yaml"
fi
deploy/scripts/preflight-secret.sh "$namespace" okoscope-secrets
migration_manifest=$(find "$bundle" -maxdepth 1 -name '02-migrate-*.yaml' -print -quit)
[[ -n $migration_manifest ]] || { echo "migration artifact is missing" >&2; exit 1; }
migration_job=$(awk '$1 == "name:" && $2 ~ /^okoscope-migrate-/ {print $2; exit}' "$migration_manifest")
kubectl apply -f "$migration_manifest"
kubectl wait --for=condition=complete --timeout=5m "job/$migration_job" -n "$namespace"
check_manifest=$(find "$bundle" -maxdepth 1 -name '02-notification-check-*.yaml' -print -quit)
[[ -n $check_manifest ]] || { echo "notification check artifact is missing" >&2; exit 1; }
check_job=$(awk '$1 == "name:" && $2 ~ /^okoscope-notification-check-/ {print $2; exit}' "$check_manifest")
kubectl apply -f "$check_manifest"
kubectl wait --for=condition=complete --timeout=2m "job/$check_job" -n "$namespace"
kubectl apply -f "$bundle/03-upgrade.yaml"
[[ ! -f $bundle/04-routing.yaml ]] || kubectl apply -f "$bundle/04-routing.yaml"
kubectl rollout status deployment/okoscope-server -n "$namespace" --timeout=5m
kubectl rollout status deployment/okoscope-web -n "$namespace" --timeout=5m
kubectl rollout status daemonset/okoscope-agent -n "$namespace" --timeout=5m
kubectl get --raw "/api/v1/namespaces/$namespace/services/http:okoscope-server:8080/proxy/readyz" >/dev/null
echo "release rollout and readiness verification passed"
