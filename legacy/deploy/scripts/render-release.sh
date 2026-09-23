#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <output-dir> <server-tag> <agent-tag> <web-image> [routing]" >&2
  exit 2
}

[[ $# -ge 4 && $# -le 5 ]] || usage
output_dir=$1
server_tag=$2
agent_tag=$3
web_image=$4
routing=${5:-disabled}
required_migration=$(sed -nE 's/^pub const REQUIRED_MIGRATION: i64 = ([0-9]+);$/\1/p' crates/server/src/database.rs)
notification_enabled=${OKOSCOPE_NOTIFICATION_DELIVERY_ENABLED:-false}
notification_poll_ms=${OKOSCOPE_NOTIFICATION_POLL_MS:-1000}
notification_claim_size=${OKOSCOPE_NOTIFICATION_CLAIM_SIZE:-50}
notification_concurrency=${OKOSCOPE_NOTIFICATION_CONCURRENCY:-8}
notification_lease_seconds=${OKOSCOPE_NOTIFICATION_LEASE_SECONDS:-30}
webhook_timeout_seconds=${OKOSCOPE_WEBHOOK_TIMEOUT_SECONDS:-10}
webhook_max_attempts=${OKOSCOPE_WEBHOOK_MAX_ATTEMPTS:-8}
webhook_backoff_min_seconds=${OKOSCOPE_WEBHOOK_BACKOFF_MIN_SECONDS:-5}
webhook_backoff_max_seconds=${OKOSCOPE_WEBHOOK_BACKOFF_MAX_SECONDS:-3600}
webhook_max_response_bytes=${OKOSCOPE_WEBHOOK_MAX_RESPONSE_BYTES:-4096}
notification_drain_seconds=${OKOSCOPE_NOTIFICATION_DRAIN_SECONDS:-15}
retention_enabled=${OKOSCOPE_NOTIFICATION_RETENTION_ENABLED:-false}
terminal_retention_days=${OKOSCOPE_NOTIFICATION_TERMINAL_RETENTION_DAYS:-90}
recovery_retention_days=${OKOSCOPE_NOTIFICATION_RECOVERY_RETENTION_DAYS:-365}
retention_batch_size=${OKOSCOPE_NOTIFICATION_RETENTION_BATCH_SIZE:-1000}
retention_poll_seconds=${OKOSCOPE_NOTIFICATION_RETENTION_POLL_SECONDS:-3600}

require_range() {
  local name=$1 value=$2 minimum=$3 maximum=$4
  [[ $value =~ ^[0-9]+$ && $value -ge $minimum && $value -le $maximum ]] || {
    echo "$name must be an integer in range $minimum..$maximum" >&2
    exit 2
  }
}

notification_substitutions() {
  sed -e "s/__NOTIFICATION_CONFIG_FINGERPRINT__/\"$activation_fingerprint\"/g" \
      -e "s/__NOTIFICATION_ENABLED__/\"$notification_enabled\"/g" \
      -e "s/__NOTIFICATION_POLL_MS__/\"$notification_poll_ms\"/g" \
      -e "s/__NOTIFICATION_CLAIM_SIZE__/\"$notification_claim_size\"/g" \
      -e "s/__NOTIFICATION_CONCURRENCY__/\"$notification_concurrency\"/g" \
      -e "s/__NOTIFICATION_LEASE_SECONDS__/\"$notification_lease_seconds\"/g" \
      -e "s/__WEBHOOK_TIMEOUT_SECONDS__/\"$webhook_timeout_seconds\"/g" \
      -e "s/__WEBHOOK_MAX_ATTEMPTS__/\"$webhook_max_attempts\"/g" \
      -e "s/__WEBHOOK_BACKOFF_MIN_SECONDS__/\"$webhook_backoff_min_seconds\"/g" \
      -e "s/__WEBHOOK_BACKOFF_MAX_SECONDS__/\"$webhook_backoff_max_seconds\"/g" \
      -e "s/__WEBHOOK_MAX_RESPONSE_BYTES__/\"$webhook_max_response_bytes\"/g" \
      -e "s/__NOTIFICATION_DRAIN_SECONDS__/\"$notification_drain_seconds\"/g" \
      -e "s/__RETENTION_ENABLED__/\"$retention_enabled\"/g" \
      -e "s/__TERMINAL_RETENTION_DAYS__/\"$terminal_retention_days\"/g" \
      -e "s/__RECOVERY_RETENTION_DAYS__/\"$recovery_retention_days\"/g" \
      -e "s/__RETENTION_BATCH_SIZE__/\"$retention_batch_size\"/g" \
      -e "s/__RETENTION_POLL_SECONDS__/\"$retention_poll_seconds\"/g"
}

[[ $server_tag =~ ^[0-9a-f]{40}$ ]] || { echo "server tag must be a 40-character commit SHA" >&2; exit 2; }
[[ $agent_tag =~ ^[0-9a-f]{40}$ ]] || { echo "agent tag must be a 40-character commit SHA" >&2; exit 2; }
[[ $web_image =~ ^[^[:space:]]+(@sha256:[0-9a-f]{64}|:[0-9a-f]{40})$ ]] || {
  echo "web image must use a commit tag or sha256 digest" >&2
  exit 2
}
[[ $routing == enabled || $routing == disabled ]] || usage
[[ $required_migration =~ ^[1-9][0-9]*$ ]] || {
  echo "cannot read REQUIRED_MIGRATION from crates/server/src/database.rs" >&2
  exit 1
}
[[ $notification_enabled == true || $notification_enabled == false ]] || {
  echo "OKOSCOPE_NOTIFICATION_DELIVERY_ENABLED must be true or false" >&2
  exit 2
}
[[ $retention_enabled == true || $retention_enabled == false ]] || {
  echo "OKOSCOPE_NOTIFICATION_RETENTION_ENABLED must be true or false" >&2
  exit 2
}
require_range notification_poll_ms "$notification_poll_ms" 50 60000
require_range notification_claim_size "$notification_claim_size" 1 1000
require_range notification_concurrency "$notification_concurrency" 1 256
require_range notification_lease_seconds "$notification_lease_seconds" 5 3600
require_range webhook_timeout_seconds "$webhook_timeout_seconds" 1 120
require_range webhook_max_attempts "$webhook_max_attempts" 1 100
require_range webhook_backoff_min_seconds "$webhook_backoff_min_seconds" 1 86400
require_range webhook_backoff_max_seconds "$webhook_backoff_max_seconds" 1 604800
require_range webhook_max_response_bytes "$webhook_max_response_bytes" 128 65536
require_range notification_drain_seconds "$notification_drain_seconds" 1 300
require_range terminal_retention_days "$terminal_retention_days" 1 3650
require_range recovery_retention_days "$recovery_retention_days" 1 3650
require_range retention_batch_size "$retention_batch_size" 1 10000
require_range retention_poll_seconds "$retention_poll_seconds" 60 86400
[[ $webhook_backoff_min_seconds -le $webhook_backoff_max_seconds ]] || {
  echo "minimum webhook backoff must not exceed maximum backoff" >&2
  exit 2
}
activation_fingerprint=$(printf '%s\n' \
  "$notification_enabled" "$notification_poll_ms" "$notification_claim_size" \
  "$notification_concurrency" "$notification_lease_seconds" "$webhook_timeout_seconds" \
  "$webhook_max_attempts" "$webhook_backoff_min_seconds" "$webhook_backoff_max_seconds" \
  "$webhook_max_response_bytes" "$notification_drain_seconds" "$retention_enabled" \
  "$terminal_retention_days" "$recovery_retention_days" "$retention_batch_size" "$retention_poll_seconds" \
  | shasum -a 256 | cut -c1-12)

mkdir -p "$output_dir"
kubectl kustomize deploy/kubernetes/install/bundled-postgres >"$output_dir/01-install-bundled-postgres.yaml"
kubectl kustomize deploy/kubernetes/migrate \
  | sed -e "s/0000000000000000000000000000000000000000/$server_tag/g" \
        -e "s/okoscope-migrate-000000000000/okoscope-migrate-${server_tag:0:12}/g" \
        -e "s/__REQUIRED_MIGRATION__/\"$required_migration\"/g" \
  >"$output_dir/02-migrate-${server_tag:0:12}.yaml"
kubectl kustomize deploy/kubernetes/check \
  | sed -e "s/0000000000000000000000000000000000000000/$server_tag/g" \
        -e "s/okoscope-notification-check-000000000000/okoscope-notification-check-${server_tag:0:8}-$activation_fingerprint/g" \
        -e "s/__REQUIRED_MIGRATION__/\"$required_migration\"/g" \
  | notification_substitutions \
  >"$output_dir/02-notification-check-${server_tag:0:12}.yaml"
# The legacy bundle renderer starts from the neutral base. The tracked
# production overlay is the GitOps source of truth and owns its image tags.
kubectl kustomize deploy/kubernetes/base \
  | sed -e "s#ghcr.io/okoscope/okoscope-server:0000000000000000000000000000000000000000#ghcr.io/okoscope/okoscope-server:$server_tag#g" \
        -e "s#ghcr.io/okoscope/okoscope-agent:0000000000000000000000000000000000000000#ghcr.io/okoscope/okoscope-agent:$agent_tag#g" \
        -e "s#ghcr.io/okoscope/okoscope-web:0000000000000000000000000000000000000000#$web_image#g" \
  | notification_substitutions \
  >"$output_dir/03-upgrade.yaml"

if [[ $routing == enabled ]]; then
  : "${OKOSCOPE_DOMAIN:?OKOSCOPE_DOMAIN is required}"
  : "${OKOSCOPE_CERTIFICATE_NAME:?OKOSCOPE_CERTIFICATE_NAME is required}"
  : "${OKOSCOPE_CERT_ISSUER:?OKOSCOPE_CERT_ISSUER is required}"
  : "${OKOSCOPE_TLS_SECRET:?OKOSCOPE_TLS_SECRET is required}"
  : "${OKOSCOPE_HTTP_ENTRYPOINT:?OKOSCOPE_HTTP_ENTRYPOINT is required}"
  : "${OKOSCOPE_HTTPS_ENTRYPOINT:?OKOSCOPE_HTTPS_ENTRYPOINT is required}"
  : "${OKOSCOPE_SERVER_SERVICE:?OKOSCOPE_SERVER_SERVICE is required}"
  : "${OKOSCOPE_WEB_SERVICE:?OKOSCOPE_WEB_SERVICE is required}"
  [[ $OKOSCOPE_DOMAIN =~ ^[A-Za-z0-9.-]+$ ]] || { echo "invalid domain" >&2; exit 2; }
  for value in "$OKOSCOPE_CERTIFICATE_NAME" "$OKOSCOPE_CERT_ISSUER" "$OKOSCOPE_TLS_SECRET" "$OKOSCOPE_HTTP_ENTRYPOINT" "$OKOSCOPE_HTTPS_ENTRYPOINT" "$OKOSCOPE_SERVER_SERVICE" "$OKOSCOPE_WEB_SERVICE"; do
    [[ $value =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || { echo "invalid Kubernetes routing input" >&2; exit 2; }
  done
  kubectl kustomize deploy/kubernetes/routing \
    | sed -e "s/__DOMAIN__/$OKOSCOPE_DOMAIN/g" \
          -e "s/__CERTIFICATE_NAME__/$OKOSCOPE_CERTIFICATE_NAME/g" \
          -e "s/__CERT_ISSUER__/$OKOSCOPE_CERT_ISSUER/g" \
          -e "s/__TLS_SECRET__/$OKOSCOPE_TLS_SECRET/g" \
          -e "s/__HTTP_ENTRYPOINT__/$OKOSCOPE_HTTP_ENTRYPOINT/g" \
          -e "s/__HTTPS_ENTRYPOINT__/$OKOSCOPE_HTTPS_ENTRYPOINT/g" \
          -e "s/__SERVER_SERVICE__/$OKOSCOPE_SERVER_SERVICE/g" \
          -e "s/__WEB_SERVICE__/$OKOSCOPE_WEB_SERVICE/g" \
    >"$output_dir/04-routing.yaml"
fi

cat >"$output_dir/PROVENANCE.txt" <<EOF
server_image=ghcr.io/okoscope/okoscope-server:$server_tag
agent_image=ghcr.io/okoscope/okoscope-agent:$agent_tag
web_image=$web_image
required_migration=$required_migration
routing=$routing
notification_delivery_enabled=$notification_enabled
notification_poll_ms=$notification_poll_ms
notification_claim_size=$notification_claim_size
notification_concurrency=$notification_concurrency
notification_lease_seconds=$notification_lease_seconds
webhook_timeout_seconds=$webhook_timeout_seconds
webhook_max_attempts=$webhook_max_attempts
webhook_backoff_min_seconds=$webhook_backoff_min_seconds
webhook_backoff_max_seconds=$webhook_backoff_max_seconds
webhook_max_response_bytes=$webhook_max_response_bytes
notification_drain_seconds=$notification_drain_seconds
notification_retention_enabled=$retention_enabled
notification_terminal_retention_days=$terminal_retention_days
notification_recovery_retention_days=$recovery_retention_days
notification_retention_batch_size=$retention_batch_size
notification_retention_poll_seconds=$retention_poll_seconds
EOF
