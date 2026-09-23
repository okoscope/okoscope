#!/usr/bin/env bash
set -euo pipefail

context="${KUBE_CONTEXT:-aliens}"
okoscope_namespace="${OKOSCOPE_NAMESPACE:-okoscope}"
workload_namespace="${WORKLOAD_NAMESPACE:-okoscope-demo}"
selected_deployment="${SELECTED_DEPLOYMENT:-payment-api}"
selected_container="${SELECTED_CONTAINER:-file-activity}"
control_deployment="${CONTROL_DEPLOYMENT:-control-api}"
postgres_pod="${POSTGRES_POD:-postgres-0}"
postgres_user="${POSTGRES_USER:-okoscope}"
postgres_database="${POSTGRES_DB:-okoscope}"
expected_release="${E2E_RELEASE_VERSION:?set E2E_RELEASE_VERSION to the selected workload release}"
baseline_release_id="${E2E_BASELINE_RELEASE_ID:?set E2E_BASELINE_RELEASE_ID for release diff assertions}"
run_id="${E2E_RUN_ID:-$(date +%s)}"

if [[ ! "$run_id" =~ ^[a-zA-Z0-9-]+$ ]]; then
  echo "E2E_RUN_ID must contain only letters, digits, and hyphens" >&2
  exit 1
fi
if [[ ! "$expected_release" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo "E2E_RELEASE_VERSION contains unsupported characters" >&2
  exit 1
fi
if [[ ! "$baseline_release_id" =~ ^[0-9a-fA-F-]{36}$ ]]; then
  echo "E2E_BASELINE_RELEASE_ID must be a UUID" >&2
  exit 1
fi

for command in kubectx kubectl; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

kubectx "$context" >/dev/null

psql_scalar() {
  kubectl -n "$okoscope_namespace" exec "$postgres_pod" -- \
    psql -X -U "$postgres_user" -d "$postgres_database" -Atc "$1" | tr -d '[:space:]'
}

assert_sql_eq() {
  local expected="$1"
  local description="$2"
  local query="$3"
  local actual
  actual="$(psql_scalar "$query")"
  if [[ "$actual" != "$expected" ]]; then
    echo "$description: expected $expected, got $actual" >&2
    exit 1
  fi
}

config="$(kubectl -n "$okoscope_namespace" get configmap okoscope-agent -o jsonpath='{.data.agent\.yaml}')"
grep -q 'enabled: true' <<<"$config" || {
  echo "observation.files must be enabled" >&2
  exit 1
}
grep -q "release: $expected_release" <<<"$config" || {
  echo "selected workload must declare release: $expected_release" >&2
  exit 1
}

desired="$(kubectl -n "$okoscope_namespace" get daemonset okoscope-agent -o jsonpath='{.status.desiredNumberScheduled}')"
ready="$(kubectl -n "$okoscope_namespace" get daemonset okoscope-agent -o jsonpath='{.status.numberReady}')"
[[ "$desired" == "$ready" ]] || {
  echo "agent DaemonSet is not ready: $ready/$desired" >&2
  exit 1
}

assert_sql_eq "$desired" "file capability registration" \
  "SELECT count(*) FROM agents WHERE last_seen_at > now()-interval '1 minute' AND capabilities ? 'file.activity.syscall-path/v1'"

path="/tmp/okoscope-files/e2e-$run_id"
renamed_path="$path.renamed"
excluded_path="/tmp/okoscope-files/excluded/e2e-$run_id"
control_path="/tmp/okoscope-files/control-e2e-$run_id"

kubectl -n "$workload_namespace" exec "deployment/$selected_deployment" -c "$selected_container" -- \
  sh -ceu "rm -f '$path' '$renamed_path'; set -C; : > '$path'; set +C; printf changed > '$path'; mv '$path' '$renamed_path'; rm '$renamed_path'; : > '$excluded_path'; rm '$excluded_path'"
kubectl -n "$workload_namespace" exec "deployment/$control_deployment" -- \
  sh -ceu "rm -f '$control_path'; set -C; : > '$control_path'; set +C; rm '$control_path'"

for _ in $(seq 1 30); do
  event_count="$(psql_scalar "SELECT count(*) FROM runtime_events WHERE payload::text LIKE '%e2e-$run_id%'")"
  [[ "$event_count" == "4" ]] && break
  sleep 2
done

scope="e.payload::text LIKE '%e2e-$run_id%'"
assert_sql_eq 4 "durable raw file events" \
  "SELECT count(*) FROM runtime_events e WHERE $scope"
assert_sql_eq 4 "create/modify/delete/rename coverage" \
  "SELECT count(DISTINCT event_kind) FROM runtime_events e WHERE $scope AND event_kind IN ('file.create','file.modify','file.delete','file.rename')"
assert_sql_eq 0 "excluded and unselected isolation" \
  "SELECT count(*) FROM runtime_events WHERE payload::text LIKE '%$excluded_path%' OR payload::text LIKE '%$control_path%'"
assert_sql_eq 4 "group occurrence memberships" \
  "SELECT count(*) FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE $scope"
assert_sql_eq 4 "deterministic runtime groups" \
  "SELECT count(DISTINCT m.group_id) FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE $scope"
assert_sql_eq 4 "first-seen outbox work" \
  "SELECT count(DISTINCT o.aggregate_id) FROM outbox_messages o JOIN runtime_event_group_memberships m ON m.group_id=o.aggregate_id JOIN runtime_events e ON e.id=m.event_id WHERE o.topic='runtime_group.first_seen' AND $scope"
assert_sql_eq 4 "inventory event memberships" \
  "SELECT count(*) FROM runtime_inventory_event_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE $scope"
assert_sql_eq 4 "inventory identities" \
  "SELECT count(DISTINCT m.item_id) FROM runtime_inventory_event_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE $scope"
assert_sql_eq 4 "inventory-to-group navigation" \
  "SELECT count(DISTINCT l.item_id) FROM runtime_inventory_group_links l JOIN runtime_inventory_event_memberships m ON m.item_id=l.item_id JOIN runtime_events e ON e.id=m.event_id WHERE $scope"
assert_sql_eq 4 "inventory occurrence sightings" \
  "SELECT count(DISTINCT s.item_id) FROM runtime_inventory_sightings s JOIN runtime_inventory_event_memberships m ON m.item_id=s.item_id JOIN runtime_events e ON e.id=m.event_id WHERE $scope"
assert_sql_eq 4 "raw release attribution" \
  "SELECT count(*) FROM runtime_events e JOIN releases r ON r.id=e.release_id WHERE $scope AND r.version='$expected_release'"
assert_sql_eq 4 "release-scoped group summaries" \
  "SELECT count(DISTINCT gr.group_id) FROM runtime_event_group_releases gr JOIN runtime_event_group_memberships m ON m.group_id=gr.group_id JOIN runtime_events e ON e.id=m.event_id JOIN releases r ON r.id=gr.release_id WHERE $scope AND r.version='$expected_release'"
assert_sql_eq 4 "release-scoped inventory summaries" \
  "SELECT count(DISTINCT ir.item_id) FROM runtime_inventory_releases ir JOIN runtime_inventory_event_memberships m ON m.item_id=ir.item_id JOIN runtime_events e ON e.id=m.event_id JOIN releases r ON r.id=ir.release_id WHERE $scope AND r.version='$expected_release'"
assert_sql_eq 4 "release diff new classification" \
  "WITH target AS (SELECT DISTINCT gr.group_id FROM runtime_event_group_releases gr JOIN releases r ON r.id=gr.release_id JOIN runtime_event_group_memberships m ON m.group_id=gr.group_id JOIN runtime_events e ON e.id=m.event_id WHERE r.version='$expected_release' AND $scope), baseline AS (SELECT group_id FROM runtime_event_group_releases WHERE release_id='$baseline_release_id') SELECT count(*) FROM target t LEFT JOIN baseline b USING(group_id) WHERE b.group_id IS NULL"

echo "file activity E2E passed for run $run_id"
