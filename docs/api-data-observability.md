# API data observability contract and handoff

The Web UI consumes the authoritative backend contract from `openapi/okoscope-v1.yaml`. The contract defines `identity_token`, Runtime Inventory Distribution, Runtime Diff Summary, their concrete response schemas, `limit` bounds, standard responses, and explicit identity-token error codes.

## Application agent health

`GET /api/v1/projects/{project_id}/applications/{application_id}/agent-health`
returns agents that authenticated for the Application, including agents that
have not produced a runtime event. The collection is tenant-scoped, uses an
opaque cursor, and accepts at most 20 agents per page. Supported history shapes
are fixed at `1h`/one minute, `6h`/five minutes, and `24h`/15 minutes.

The response keeps three facts separate: a recent Application-stream heartbeat,
advertised capabilities, and accepted Application runtime-event evidence. A
recent heartbeat is reported as `reporting`, not as proof that the transport is
currently connected. The server freshness bound is 300 seconds.

Timeline points distinguish received signals, missing signals inside known
history, and unavailable time before collection or retention coverage. Health
source buckets are retained for at least 25 hours. Diagnostic deltas are recent
increments from monotonic counters; they are node-wide, can therefore appear on
multiple Application cards served by one agent, and must not be attributed to a
specific workload. Counter decreases produce reset markers and no negative or
cross-reset delta. Older agents without counters remain visible with diagnostics
unavailable.

Deploy migration 28 and the compatible server before enabling the stage 2 Web
surface. A Web rollback can return to the workers-only view independently. A
server rollback leaves the additive health tables unused; do not reverse the
migration or delete health buckets, runtime evidence, agent identities,
credentials, or installation state. Older compatible agents remain supported
and continue to contribute stream freshness even when counters are unavailable.

## Runtime Inventory Distribution example

```json
{
  "identity_version": 1,
  "kind": "syscall",
  "total_item_count": 25,
  "total_occurrence_count": 18420,
  "entries": [
    {
      "identity_token": "<opaque-token>",
      "semantic_summary": {"process_command": "payments", "syscall": "epoll_wait"},
      "item_count": 1,
      "occurrence_count": 8842
    }
  ],
  "other": {"item_count": 24, "occurrence_count": 9578}
}
```

## Runtime Diff Summary example

```json
{
  "baseline": {"id": "018f4f9c-3f9a-7de1-8000-000000000010", "project_id": "018f4f9c-3f9a-7de1-8000-000000000001", "application_id": "018f4f9c-3f9a-7de1-8000-000000000002", "version": "1.0.0", "description": null, "deployed_at": "2026-08-19T10:00:00Z", "created_at": "2026-08-19T10:00:00Z"},
  "target": {"id": "018f4f9c-3f9a-7de1-8000-000000000011", "project_id": "018f4f9c-3f9a-7de1-8000-000000000001", "application_id": "018f4f9c-3f9a-7de1-8000-000000000002", "version": "1.1.0", "description": null, "deployed_at": "2026-08-20T10:00:00Z", "created_at": "2026-08-20T10:00:00Z"},
  "total_item_count": 42,
  "classifications": [
    {"classification": "new", "item_count": 12},
    {"classification": "disappeared", "item_count": 4},
    {"classification": "unchanged", "item_count": 26}
  ],
  "largest_changes": [
    {"group_id": "018f4f9c-3f9a-7de1-8000-000000000012", "classification": "new", "event_kind": "exec", "semantic_summary": {"executable": "/app/new-worker"}, "baseline_occurrence_count": 0, "target_occurrence_count": 340, "occurrence_delta": 340}
  ]
}
```

## Identity-token failures

All failures are HTTP 400 using the standard correlated error envelope:

- `invalid_identity_token`: malformed, oversized, incorrectly signed, tampered, or unresolvable token.
- `expired_identity_token`: authenticated token whose validity period elapsed.
- `identity_token_scope_mismatch`: authenticated token incompatible with the authorized tenant, Project, Application, requested kind, or identity version.

Tokens are navigation capabilities only. Clients treat them as opaque, reset the list cursor when identity changes, and do not persist them beyond their short validity period.

Deployments set `OKOSCOPE_IDENTITY_TOKEN_KEY` to at least 32 random bytes. A configured undersized key fails during API router initialization. When the variable is absent, a random process-lifetime key is generated; this is suitable for tests and local development but makes tokens invalid after restart. Rotation across replicas currently requires a coordinated key update and invalidates tokens issued with the previous key.

## Performance acceptance

Both aggregate routes cap top-N at 10. Inventory Distribution uses a materialized filtered relation with window totals and returns at most ten rows to the application. Runtime Diff Summary performs classification and largest-delta aggregation in one repeatable-read snapshot and returns at most three classification rows plus ten changes. Existing indexes used by these shapes are `runtime_inventory_items_kind_recent_idx`, `runtime_inventory_releases_release_idx`, `runtime_inventory_sightings_filter_idx`, the `runtime_event_group_releases` primary key, and release/group scope indexes.

## Recorded development baseline

On 2026-08-20 the ignored acceptance benchmark ran against an isolated local PostgreSQL 17 cluster with 10,000 events, 1,000 process identities, 200 Pods, two namespaces, two releases, a roughly seven-day observation range, 1,000 diff groups, and 30 measured requests per aggregate endpoint.

| Measurement | Result |
|---|---:|
| Projection | 22,007 ms |
| Inventory Distribution p50 / p95 / p99 | 2 / 3 / 5 ms |
| Runtime Diff Summary p50 / p95 / p99 | 3 / 4 / 6 ms |
| Maximum serialized response | 10,615 bytes |
| Top-N maximum | 10 |

Migration 9 adds `runtime_inventory_items_distribution_idx` for ordered distribution retrieval and `runtime_event_group_releases_release_group_idx` for selective release-side comparison lookup. After `ANALYZE`, the process distribution plan used an index-only scan on the new ordered index. The 50/50 two-release benchmark made sequential scans cheaper for diff; the full hash outer comparison and absolute-delta sort necessarily inspect the complete comparison in PostgreSQL while returning only bounded rows to application memory.

Limitations: these debug-profile numbers are a developer regression baseline, not a production SLO; diff tail latency is sensitive to full-comparison cardinality; only process identities were used in the high-cardinality run, while correctness integration tests cover all four inventory kinds. Production acceptance must repeat `EXPLAIN (ANALYZE, BUFFERS)` and latency sampling using deployment-scale cardinality, retention, concurrent ingestion, and representative filters.

## Expanded aggregate verification (2026-09-03)

See [high-cardinality verification](data-visualizations-high-cardinality.md) for 40,000 identities, real HTTP p99 samples, full aggregate query plans, and the confirmed default 5 / maximum 10 entry limits. The historical index-only distribution plan above explains a simplified lookup, not the full materialized-scope/window aggregate. The new oversized-label probe also demonstrates that bounded entry count does not enforce a fixed response-byte maximum; frontend task 5.4 remains open for that contract decision.
