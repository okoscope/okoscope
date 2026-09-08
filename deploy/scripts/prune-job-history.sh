#!/usr/bin/env bash
set -euo pipefail

namespace=${1:?usage: prune-job-history.sh NAMESPACE APP_NAME...}
shift
(( $# > 0 )) || { echo "at least one application name is required" >&2; exit 2; }

command -v jq >/dev/null 2>&1 || { echo "jq is required to prune Job history" >&2; exit 1; }

for app_name in "$@"; do
  kubectl get jobs -n "$namespace" -l "app.kubernetes.io/name=$app_name" -o json \
    | jq -r '
        [.items[]
          | . as $job
          | (.status.conditions // [])[]
          | select(.status == "True" and (.type == "Complete" or .type == "Failed"))
          | [.type, (.lastTransitionTime // $job.metadata.creationTimestamp), $job.metadata.name]
        ]
        | sort_by(.[0], .[1])
        | group_by(.[0])[]
        | .[0:-1][]
        | .[2]
      ' \
    | while IFS= read -r job_name; do
        [[ -n "$job_name" ]] || continue
        kubectl delete job "$job_name" -n "$namespace" --wait=false
      done
done
