# First-seen observability smoke test

This runbook verifies one selected Application from workload execution through raw storage, grouping, first-seen notification state, and the versioned Web API. Use a disposable command whose semantic fingerprint has not previously appeared in the Application.

## Prerequisites

- Select the installation's Kubernetes context before every cluster operation; the commands below use `<context>`.
- Export `OKOSCOPE_URL` (the server's public origin, for example `https://okoscope.example.com`), `PROJECT_ID`, and `APPLICATION_ID` in the local shell.
- Sign in as a user with access to the Project and keep the session cookie in a private file. Do not commit it:

```sh
curl -fsS -c okoscope.cookies -H 'Content-Type: application/json' \
  -d '{"email":"<email>","password":"<password>"}' \
  "${OKOSCOPE_URL}/api/v1/auth/login"
```

## Produce new and repeated behavior

```sh
kubectx <context>
kubectl -n okoscope-demo exec deploy/payment-api -- /bin/sh -c '/usr/bin/id'
kubectx <context>
kubectl -n okoscope-demo exec deploy/payment-api -- /bin/sh -c '/usr/bin/id'
```

Wait for the agent batch to be acknowledged, then list the selected Application's groups:

```sh
curl -fsS \
  -b okoscope.cookies \
  "${OKOSCOPE_URL}/api/v1/runtime-groups?project_id=${PROJECT_ID}&application_id=${APPLICATION_ID}&event_kind=process.exec&limit=50"
```

Record the matching `id` as `GROUP_ID`. The group must expose `first_seen_event_id`, `occurrence_count` of at least two, status `open`, and a first-seen notification state. Repeating the command must update occurrences without creating another group or first-seen outbox item.

## Investigate the group

```sh
curl -fsS \
  -b okoscope.cookies \
  "${OKOSCOPE_URL}/api/v1/runtime-groups/${GROUP_ID}"

curl -fsS \
  -b okoscope.cookies \
  "${OKOSCOPE_URL}/api/v1/runtime-groups/${GROUP_ID}/occurrences?limit=50"
```

The representative event remains stable. Occurrences are ordered by `(observed_at, id)` descending and retain Pod, container, Kubernetes namespace, payload, and optional release attribution.

## Verify lifecycle

```sh
curl -fsS -X POST -b okoscope.cookies -H "Origin: ${OKOSCOPE_URL}" \
  "${OKOSCOPE_URL}/api/v1/runtime-groups/${GROUP_ID}/acknowledge"
curl -fsS -X POST -b okoscope.cookies -H "Origin: ${OKOSCOPE_URL}" \
  "${OKOSCOPE_URL}/api/v1/runtime-groups/${GROUP_ID}/resolve"
curl -fsS -X POST -b okoscope.cookies -H "Origin: ${OKOSCOPE_URL}" \
  "${OKOSCOPE_URL}/api/v1/runtime-groups/${GROUP_ID}/reopen"
```

State-changing requests send `Origin` with the server's own origin; without it a session request is rejected with `403 untrusted_origin`. Each response must contain the target status plus `status_changed_at` and `status_changed_by`. Retrying the same command is idempotent. Lifecycle changes must not alter `first_seen_at`, `first_seen_event_id`, representative event, occurrence count, or notification delivery count.

## Verify PostgreSQL

Port-forward PostgreSQL after selecting `<context>`, then run `ops/queries/runtime-groups.sql`. For the selected group verify exactly one membership per stored event and exactly one `runtime_group.first_seen` outbox row:

```sql
SELECT count(*) FROM runtime_event_group_memberships WHERE group_id = '<group-id>';
SELECT count(*) FROM outbox_messages
WHERE aggregate_id = '<group-id>' AND topic = 'runtime_group.first_seen';
```

The second query must return `1`. Stop port-forwards after verification, then sign out and delete the cookie file:

```sh
curl -fsS -X POST -b okoscope.cookies -H "Origin: ${OKOSCOPE_URL}" "${OKOSCOPE_URL}/api/v1/auth/logout"
rm okoscope.cookies
```

Do not run destructive cleanup against the shared cluster database.
