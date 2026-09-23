# Runtime inventory operations

Application runtime inventory is an additive projection of accepted runtime events. Version 2 groups outbound destinations, DNS behavior, syscalls, and file activity by canonical Application behavior rather than Linux thread command. Raw events and process-aware Runtime Groups continue to retain the command for investigation.

Authorized Project users can assign one user label to any stable Application
inventory identity, including processes, lifecycle events, inbound and outbound
network activity, DNS queries, syscalls, and file activity. Labels are trimmed,
limited to 120 Unicode characters, and kept separate from the canonical
technical `semantic_summary`; they never change grouping, counts, policy
evaluation, or collected evidence. Duplicate label text is allowed.

## Logical DNS presentation groups

The additive `.../runtime-inventory/dns-groups` API presents DNS observations as
logical destinations without changing the stored `domain` inventory items.
Questions for A and AAAA records share a logical group when their canonical
name and observed process match. A name ending in the default Kubernetes search
suffix (`<namespace>.svc.cluster.local`, `svc.cluster.local`, or
`cluster.local`) is folded into the base name when that exact base name is also
present, or when at least two different exact questions produce the same base
through different recognized suffixes. Corroboration is limited to one process,
cluster, namespace, Pod, and container in the complete effective filter scope.
Unknown cluster domains, ambiguous suffixes, and evidence left without this
corroboration remain separate groups.

List and distribution aggregation starts from retained event membership after
tenant, release, Kubernetes, observation-window, policy, suppression, and
evaluation-state filters. Search matches the logical display name or any exact
question in the group. The group observation total counts matching retained
events once; distribution entries plus `other` reconcile with the complete
logical-group and observation totals.

`.../dns-groups/{group_token}/variants` returns a bounded list of the exact
name/type identities contributing to a group. Its `item_id` continues to address
the existing inventory detail, release, sighting, Runtime Group, and occurrence
history routes. Logical groups therefore describe resolver presentation only;
they do not prove a connection, change policy identity, or replace raw evidence.

The item-scoped `PUT .../runtime-inventory/{item_id}/user-label` and `DELETE`
operations resolve the stable kind, identity version, and digest on the server.
Clients cannot supply identity material. The optional `expected_updated_at`
precondition detects concurrent edits. Inventory and linked runtime-group and
attention reads expose current labels, while a notification snapshots at most
20 deterministic labels when its delivery is materialized so retries remain
unchanged after later edits.

## Staged rollout

1. Apply database migration 8 and confirm `/ready` reports the required schema.
2. Deploy the server with live ingestion projection enabled. New events update inventory in the same transaction as raw storage and grouping.
3. Backfill one Project, or one Application for a smaller canary, in bounded batches:

   ```sh
   okoscope-server --database-url "$OKOSCOPE_DATABASE_URL" inventory-backfill \
     --organization-id ORGANIZATION_UUID \
     --project-id PROJECT_UUID \
     --application-id APPLICATION_UUID \
     --identity-version 2 \
     --batch-size 500 \
     --throttle-ms 25
   ```

4. Run reconciliation for every backfilled Application:

   ```sh
   okoscope-server --database-url "$OKOSCOPE_DATABASE_URL" inventory-reconcile \
     --organization-id ORGANIZATION_UUID \
     --project-id PROJECT_UUID \
     --application-id APPLICATION_UUID \
     --identity-version 2
   ```

5. Enable inventory API and UI traffic only after reconciliation exits successfully.

The backfill snapshots an upper event identifier, processes bounded ordered batches, and skips existing versioned event memberships. Repeating or resuming the command is safe. It creates no runtime-group first-seen outbox work and therefore cannot deliver historical first-seen notifications.

## Readiness and monitoring

Monitor the following metrics:

- `okoscope_inventory_projection_events_total` and `okoscope_inventory_projection_skips_total`;
- `okoscope_inventory_items_created_total`;
- `okoscope_inventory_projection_duration_microseconds_total`;
- `okoscope_inventory_backfill_scanned`, `projected`, and `skipped`;
- `okoscope_inventory_projection_freshness_seconds`;
- `okoscope_inventory_reconciliation_mismatches_total`;
- inventory query request and duration totals.
- `okoscope_inventory_summary_requests_total`, `okoscope_inventory_summary_duration_microseconds_total`, and `okoscope_inventory_summary_results_total`;
- `okoscope_inventory_facet_requests_total`, `okoscope_inventory_facet_duration_microseconds_total`, and `okoscope_inventory_facet_results_total`;
- `okoscope_inventory_scope_validation_failures_total` and `okoscope_inventory_cursor_rejections_total`.

Summary and facet structured logs contain only the closed operation/facet name, elapsed time, result size, and closed validation class. They must never include semantic search, facet search, namespace, workload, container, or any other observed value. During rollout, compare request growth with total duration and result totals; investigate cursor-rejection spikes separately from ordinary invalid scope filters.

Initial cardinality assumptions per Application are 100 clusters, 1,000 namespaces, 10 workload kinds, 10,000 workload names, and 10,000 container names. Before enabling broad UI traffic, run the PostgreSQL benchmark with representative cardinalities, retain `EXPLAIN (ANALYZE, BUFFERS)` output for scoped summary and all facets, and confirm every page remains at or below 200 options.

Use [`ops/queries/runtime-inventory.sql`](../ops/queries/runtime-inventory.sql) to inspect per-Application projection totals, missing memberships, and kind cardinality without selecting event payloads.

## Rollback and rebuild

An older server image can run against migration 8 because the schema change is additive. To roll back the feature, stop inventory API traffic and deploy the older server; do not drop projection tables during an incident.

The hardening routes are additive. If summary/facet latency regresses during rollout, disable the UI calls or deploy the prior server image; existing unfiltered inventory list/detail behavior and stored projections remain usable. Do not add or remove indexes during incident response without a captured plan and the normal migration verification suite.

To rebuild one controlled tenant scope:

1. Stop inventory reads and live ingestion for the selected Application.
2. Export counts for diagnosis.
3. Delete the selected Application rows from `runtime_inventory_items`; cascading foreign keys remove its projection memberships, links, releases, and sightings without deleting source evidence.
4. Run `inventory-backfill` and `inventory-reconcile` for that Application.
5. Resume ingestion and inventory reads after reconciliation succeeds.

Never delete `runtime_events`, `runtime_event_groups`, their memberships, or release summaries as part of an ordinary inventory rebuild. The version-2 cutover for an explicitly selected Application is a separate destructive reset: pause ingestion and reads, take a database backup, verify Organization/Project/Application identifiers and preflight counts, remove all Application runtime evidence and user-authored runtime state in one reviewed transaction, verify zero residual rows and preserved Application/release/deployment/credential/agent/resource records, deploy compatible server and Web releases, then resume and reconcile. Rollback requires restoring the backup before ingestion resumes.

For that one-time cutover, first record the three trusted identifiers from the
database and take a restorable PostgreSQL backup. Pause the selected
Application's agent and block its inventory UI/API access. Review
[`ops/queries/reset-application-runtime.sql`](../ops/queries/reset-application-runtime.sql),
then run it with explicit psql variables:

```sh
psql "$OKOSCOPE_DATABASE_URL" \
  --set=organization_id=ORGANIZATION_UUID \
  --set=project_id=PROJECT_UUID \
  --set=application_id=APPLICATION_UUID \
  --file=ops/queries/reset-application-runtime.sql
```

The transaction aborts unless the identifiers resolve to exactly one
Application, prints preflight counts, verifies targeted state is absent, and
compares preserved-row counts before committing. Do not resume ingestion if it
fails. After deploying compatible releases, resume the selected agent, run
`inventory-reconcile` with identity version 2, and inspect fresh occurrences.
To roll back, keep ingestion paused, restore the captured database backup,
deploy the previous server and Web releases, and only then resume traffic.

User labels are durable configuration stored independently from disposable
inventory projection rows and raw evidence. A rebuild therefore preserves a
label and exposes it again when the same Application-scoped kind, identity
version, and digest is reconstructed. Labels never transfer to another
Application or identity version, and deleting the owning Application removes
them by cascade. Label text must not be copied into metric dimensions or
routine structured logs.
