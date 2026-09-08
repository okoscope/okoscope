# Runtime event retention

Runtime retention has two observation-age horizons. Details remain for `raw_days`; numerical history remains until total age `history_days`. A null historical horizon means “keep forever”. It does not retain raw event payloads forever.

Organization owners manage the default policy. A Project either inherits the complete Organization policy or overrides it completely. An explicit disabled override pauses that Project's cleanup. Members can read effective settings but cannot change them. Initial settings are disabled with 30 days of details and 365 days of numerical history. Notification retention is independent.

## Policy API

| Route | Methods |
| --- | --- |
| `/api/v1/organizations/{organization_id}/runtime-retention` | GET, PUT |
| `/api/v1/projects/{project_id}/runtime-retention` | GET, PUT, DELETE |

PUT supplies the complete `enabled`, `raw_days`, `history_days` policy. `raw_days` is an integer from 1 to 3650. Finite `history_days` must be at least `raw_days` and no greater than 3650. Project DELETE restores inheritance. Project reads show the override, inherited policy, effective policy and its source. Writes use the existing user-session and trusted-Origin requirements. Cross-tenant reads do not disclose resource existence.

Policy and snapshot response examples are in [runtime-retention.json](fixtures/runtime-retention.json). The authoritative schema remains [OpenAPI](../openapi/okoscope-v1.yaml).

## What a snapshot preserves

One fixed-size row summarizes one group, optional release and UTC day within its trusted Project and Application. It contains numerical occurrence counts and first/last observation times. A million equivalent events in that bucket occupy one snapshot row, even when maintenance processes them in many batches. Different groups, releases and days produce different rows.

Snapshots contain no payload archives, lists of event identifiers or Pod-level evidence. Derived restart findings retain their defined logical occurrence counts; adding totals of overlapping groups is not a unique raw-event count. A snapshot cannot restore individual events or rebuild old history under a new grouping algorithm.

Maintenance operates on complete UTC days. A day becomes eligible when its end is no later than the configured age cutoff. This can keep data for less than one extra day. Both horizons use the original observation time, so 30/365 means details for approximately 30 days followed by summaries until total age approximately 365 days, not another 365 days after compaction.

## Reads after cleanup

Group history combines retained raw contributions and snapshots exactly once. Compaction does not increase existing group totals. Snapshot expiry removes its contribution from retained statistics. Raw representative and first-seen event references can become unavailable; the UI must distinguish missing details from zero observed events.

Release comparisons use snapshot-backed positive evidence. Where history required to infer absence has expired, comparison results are unknown. Detailed inventory, deployment sightings, facets and distributions describe retained raw evidence; group snapshots are separate historical evidence and cannot answer Pod/container-level questions. Historical daily counts do not imply exact sub-day results.

After the final evidence expires, a group or inventory identity referenced by a runtime policy can remain as a minimal configuration reference with no retained historical counts. Retention does not delete the referencing policy or active notification work. Notification delivery history remains governed by its independent retention settings.

## Database dependencies

| Data | Retention behavior |
| --- | --- |
| Group/inventory event memberships | Removed with their raw event after its numerical contribution is saved. |
| Correlations and restart event memberships | Raw links cascade; surviving correlation evidence is marked incomplete. Active-window evidence has a bounded grace interval. |
| Group/release representative and first-seen event references | Cleared when the raw event disappears; readers accept unavailable details. |
| Group and release summaries | Count retained raw contributions plus snapshots; expiration removes historical contributions. |
| Inventory releases, sightings, group links and evidence flags | Recomputed for affected identities from surviving raw evidence. |
| Runtime policy references | Preserve necessary zero-history identity shells; policies are not cascaded away. |
| First-seen outbox | Pending or delivery-referenced work survives independently; processed unreferenced work can be removed with empty history. |
| Backfill and reconciliation | Coordinate with cleanup locks and report retained raw coverage rather than claiming full reconstruction. |

## Late arrivals and retries

Each Project has a persisted observation-time boundary for closed history. Before compacting old days, maintenance closes them against new ingestion. Events arriving behind that boundary, including retries of removed events, do not add new raw rows, counters or notification work. The ingestion protocol must consume these as non-retryable expired outcomes while preserving delivery of eligible events in mixed batches.

Late events arriving before a day closes still follow normal validation and deduplication. Increasing a duration, choosing forever or disabling cleanup cannot reopen a closed period or restore deleted information. Clients expose actual retained coverage separately from configured horizons.

## Automatic processing

Processing runs on the server's schedule in bounded transactions. There is no run-now button, API or CLI command. A batch saves exactly its selected events' snapshot contributions, updates dependent projections/references and removes those events atomically. A failed batch rolls back and can be retried without doubling counts. A newer policy applies to batches beginning after its write commits; a running batch may finish with its prior policy.

`OKOSCOPE_RUNTIME_RETENTION_PAUSED=true` (or `1`) pauses maintenance without modifying tenant settings. `OKOSCOPE_RUNTIME_RETENTION_POLL_SECONDS` selects the interval (default 60 seconds, bounded to 1–3600). Each tick visits up to 32 Projects and each Project processes up to 500 raw events and 500 expired snapshots; Project traversal resumes on the next tick. These operational values are independent of Organization/Project policy. Monitor `okoscope_runtime_retention_compacted_events_total`, `expired_snapshots_total`, `errors_total`, `last_success_timestamp_seconds`, `duration_microseconds_total`, `paused`, and `expired_arrivals_total` (all with the `okoscope_runtime_retention_` prefix). `okoscope_runtime_retention_raw_backlog_projects_last_scan` counts Projects with remaining raw backlog among the last sampled tick of up to 32 Projects, including protected active-window evidence; it is not a global remaining-event count. Keep metrics free of payloads and unbounded tenant labels. “Forever” still permits growth in the number of group/release/day buckets; it does not make total storage constant.

Legacy raw rows without group membership are retained rather than deleted without a numerical contribution. Use the existing grouping backfill to project such legacy evidence; it preserves release attribution and coordinates with retention locks. This does not introduce a manual retention trigger.

## Coordinated upgrade and rollback

1. Apply the runtime retention schema with automatic maintenance paused and Organization policies disabled.
2. Deploy all ingestion writers and API readers that understand nullable evidence and closed history before enabling any cleanup. Do not mix old ingestion writers with active closure enforcement.
3. Deploy the frontend synchronized with the authoritative OpenAPI. Verify settings inheritance, forever, coverage and missing-detail states.
4. Validate PostgreSQL migration failure/repair, concurrent replay, transaction rollback, real foreign keys and scheduled processing on an isolated test stack.
5. Enable desired policies and resume automatic scheduling. The worker drains accumulated history in bounded batches; no manual immediate action is necessary.
6. To roll back, pause maintenance first and retain the additive schema and closed-history enforcement. Never restart writers that can accept already closed history. Snapshots cannot recover removed details, and increasing retention cannot recover expired snapshots.

## Local performance check

On 2026-09-03, the ignored `measured_single_group_retention_workload` PostgreSQL test processed 20,004 events on local PostgreSQL 14. Most events shared one group, inventory identity and observation day. It produced four daily group/release snapshot rows in 41 batches limited to 500 events. Measured batch latency was p50 122 ms, p95 184 ms, maximum 227 ms; summed batch processing time was 5,177 ms. The candidate query used `runtime_events_retention_idx` through an index-only scan and returned 500 rows in 0.349 ms.

These are local test measurements, not a production capacity guarantee. Updating affected group/inventory projections can scan surviving evidence for those identities, so batch size bounds selected event rows but does not impose a constant bound on transaction time. Benchmark larger groups and concurrent ingestion before selecting operational limits for a large installation. Partitioning remains a separate possible optimization.

Reproduce against an isolated PostgreSQL database with `DATABASE_URL` set:

```sh
cargo test -p server --test runtime_retention_reads measured_single_group_retention_workload -- --ignored --nocapture
```

Correlation/restart processing can temporarily retain the ten-minute evidence interval immediately preceding the closed boundary. This protects active window calculations when newer events arrive; the evidence becomes eligible as the boundary advances.

## Verification

The implementation passed strict workspace Clippy, server library/OpenAPI checks, PostgreSQL migration initialization/idempotency/failure/repair checks, retention concurrency and rollback regressions, and the scheduler failure-isolation regression. Frontend verification passed 183 unit tests and the full 41-test Playwright suite.

An independent browser run against a real local backend and PostgreSQL passed 11 checks, including owner/member/tenant isolation, settings persistence, keyboard submission, CSRF, snapshot pagination, Russian mobile accessibility, and actual scheduled compaction followed by snapshot expiry. Five events seeded through normal ingestion became one retained fresh event and no expired snapshot rows; retained group and inventory counts agreed. No manual maintenance entry point was used.

The guarded `cargo run -p server --example retention_e2e_fixture` helper creates reproducible ingestion fixtures only when `DATABASE_URL` targets localhost and database `okoscope_retention_browser`. Use a separate local test database and server; never point this fixture at an existing installation. The local services and container used for verification were removed after the run.
