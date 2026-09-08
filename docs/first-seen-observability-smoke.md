# First-seen observability smoke test

This runbook verifies one selected Application from workload execution through raw storage, grouping, first-seen notification state, and the versioned Web API. Use a disposable command whose semantic fingerprint has not previously appeared in the Application.

## Prerequisites

- Select the `aliens` Kubernetes context before every cluster operation.
- Export `OKOSCOPE_API_CREDENTIAL`, `PROJECT_ID`, and `APPLICATION_ID` in the local shell. Do not commit credentials.
- Run the commands from a workstation that can reach `https://okoscope.com`.

## Produce new and repeated behavior

```sh
kubectx aliens
kubectl -n okoscope-demo exec deploy/payment-api -- /bin/sh -c '/usr/bin/id'
kubectx aliens
kubectl -n okoscope-demo exec deploy/payment-api -- /bin/sh -c '/usr/bin/id'
```

Wait for the agent batch to be acknowledged, then list the selected Application's groups:

```sh
curl -fsS \
  -H "Authorization: Bearer ${OKOSCOPE_API_CREDENTIAL}" \
  "https://okoscope.com/api/v1/runtime-groups?project_id=${PROJECT_ID}&application_id=${APPLICATION_ID}&event_kind=process.exec&limit=50"
```

Record the matching `id` as `GROUP_ID`. The group must expose `first_seen_event_id`, `occurrence_count` of at least two, status `open`, and a first-seen notification state. Repeating the command must update occurrences without creating another group or first-seen outbox item.

## Investigate the group

```sh
curl -fsS \
  -H "Authorization: Bearer ${OKOSCOPE_API_CREDENTIAL}" \
  "https://okoscope.com/api/v1/runtime-groups/${GROUP_ID}"

curl -fsS \
  -H "Authorization: Bearer ${OKOSCOPE_API_CREDENTIAL}" \
  "https://okoscope.com/api/v1/runtime-groups/${GROUP_ID}/occurrences?limit=50"
```

The representative event remains stable. Occurrences are ordered by `(observed_at, id)` descending and retain Pod, container, Kubernetes namespace, payload, and optional release attribution.

## Verify lifecycle

```sh
curl -fsS -X POST -H "Authorization: Bearer ${OKOSCOPE_API_CREDENTIAL}" \
  "https://okoscope.com/api/v1/runtime-groups/${GROUP_ID}/acknowledge"
curl -fsS -X POST -H "Authorization: Bearer ${OKOSCOPE_API_CREDENTIAL}" \
  "https://okoscope.com/api/v1/runtime-groups/${GROUP_ID}/resolve"
curl -fsS -X POST -H "Authorization: Bearer ${OKOSCOPE_API_CREDENTIAL}" \
  "https://okoscope.com/api/v1/runtime-groups/${GROUP_ID}/reopen"
```

Each response must contain the target status plus `status_changed_at` and `status_changed_by`. Retrying the same command is idempotent. Lifecycle changes must not alter `first_seen_at`, `first_seen_event_id`, representative event, occurrence count, or notification delivery count.

## Verify PostgreSQL

Port-forward PostgreSQL after selecting `aliens`, then run `ops/queries/runtime-groups.sql`. For the selected group verify exactly one membership per stored event and exactly one `runtime_group.first_seen` outbox row:

```sql
SELECT count(*) FROM runtime_event_group_memberships WHERE group_id = '<group-id>';
SELECT count(*) FROM outbox_messages
WHERE aggregate_id = '<group-id>' AND topic = 'runtime_group.first_seen';
```

The second query must return `1`. Stop port-forwards after verification. Do not run destructive cleanup against the shared cluster database.
