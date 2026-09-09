# Runtime inventory operations

Application runtime inventory is an additive projection of accepted runtime events. Raw events, runtime groups, release summaries, and notifications remain the source evidence and continue working when inventory reads are disabled.

## Staged rollout

1. Apply database migration 8 and confirm `/ready` reports the required schema.
2. Deploy the server with live ingestion projection enabled. New events update inventory in the same transaction as raw storage and grouping.
3. Backfill one Project, or one Application for a smaller canary, in bounded batches:

   ```sh
   okoscope-server --database-url "$OKOSCOPE_DATABASE_URL" inventory-backfill \
     --organization-id ORGANIZATION_UUID \
     --project-id PROJECT_UUID \
     --application-id APPLICATION_UUID \
     --identity-version 1 \
     --batch-size 500 \
     --throttle-ms 25
   ```

4. Run reconciliation for every backfilled Application:

   ```sh
   okoscope-server --database-url "$OKOSCOPE_DATABASE_URL" inventory-reconcile \
     --organization-id ORGANIZATION_UUID \
     --project-id PROJECT_UUID \
     --application-id APPLICATION_UUID \
     --identity-version 1
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

Never delete `runtime_events`, `runtime_event_groups`, their memberships, or release summaries as part of an inventory rebuild.
