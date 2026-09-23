#!/usr/bin/env bash
set -euo pipefail

: "${OKOSCOPE_SERVER_TAG:?set immutable server commit tag}"
: "${OKOSCOPE_WEB_TAG:?set immutable Web commit tag}"

pg_namespace=${OKOSCOPE_TEST_PG_NAMESPACE:-okoscope-install-pg-test}
app_namespace=${OKOSCOPE_TEST_NAMESPACE:-okoscope-install-test}
release=${OKOSCOPE_TEST_RELEASE:-okoscope}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
password=$(openssl rand -hex 24)

kubectx aliens
kubectl create namespace "$pg_namespace"
kubectl create namespace "$app_namespace"
kubectl -n "$pg_namespace" create secret generic postgres-auth \
  --from-literal=POSTGRES_USER=okoscope \
  --from-literal=POSTGRES_PASSWORD="$password" \
  --from-literal=POSTGRES_DB=okoscope
kubectl -n "$pg_namespace" create deployment postgres --image=postgres:17.6
kubectl -n "$pg_namespace" set env deployment/postgres --from=secret/postgres-auth
kubectl -n "$pg_namespace" expose deployment postgres --port=5432 --target-port=5432
kubectl -n "$pg_namespace" rollout status deployment/postgres --timeout=5m

database_url="postgresql://okoscope:${password}@postgres.${pg_namespace}.svc:5432/okoscope"
kubectl -n "$app_namespace" create secret generic okoscope-database \
  --from-literal=database-url="$database_url"
unset database_url password

helm dependency build "$root/deploy/helm/okoscope" --skip-refresh
helm upgrade --install "$release" "$root/deploy/helm/okoscope" \
  --namespace "$app_namespace" \
  --set server.image.tag="$OKOSCOPE_SERVER_TAG" \
  --set web.image.tag="$OKOSCOPE_WEB_TAG" \
  --wait --timeout 10m
helm test "$release" --namespace "$app_namespace" --logs

internal_secret_uid=$(kubectl -n "$app_namespace" get secret "$release-internal" -o jsonpath='{.metadata.uid}')
helm upgrade "$release" "$root/deploy/helm/okoscope" \
  --namespace "$app_namespace" \
  --set server.image.tag="$OKOSCOPE_SERVER_TAG" \
  --set web.image.tag="$OKOSCOPE_WEB_TAG" \
  --wait --timeout 10m
test "$internal_secret_uid" = "$(kubectl -n "$app_namespace" get secret "$release-internal" -o jsonpath='{.metadata.uid}')"

kubectl -n "$app_namespace" create secret generic okoscope-database-unreachable \
  --from-literal=database-url='postgresql://invalid:invalid@invalid.invalid.svc:5432/invalid'
if helm upgrade "$release" "$root/deploy/helm/okoscope" \
  --namespace "$app_namespace" --reuse-values \
  --set database.existingSecret=okoscope-database-unreachable \
  --set migration.backoffLimit=0 \
  --set migration.activeDeadlineSeconds=30 \
  --wait --timeout 2m; then
  echo 'expected migration gate failure' >&2
  exit 1
fi
test "$(kubectl -n "$app_namespace" get deployment "$release-server" -o jsonpath='{.status.readyReplicas}')" = 1
kubectl -n "$app_namespace" delete secret okoscope-database-unreachable

if kubectl -n "$app_namespace" get statefulset,service,pvc -l app.kubernetes.io/instance="$release" -o name | grep -q postgres; then
  echo 'Okoscope release unexpectedly owns PostgreSQL resources' >&2
  exit 1
fi

helm rollback "$release" 1 --namespace "$app_namespace" --wait --timeout 10m
helm uninstall "$release" --namespace "$app_namespace"
kubectl -n "$pg_namespace" get deployment/postgres service/postgres >/dev/null
kubectl -n "$app_namespace" get secret/okoscope-database >/dev/null

echo "Cluster lifecycle verification passed. Test namespaces remain for inspection: $pg_namespace $app_namespace"
