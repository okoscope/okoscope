# Runtime inventory performance acceptance

The executable acceptance benchmark is `crates/server/tests/inventory_benchmark.rs`. It projects 10,000 accepted events into 1,000 application-level process items across 200 Pods, two namespaces, two releases, and roughly seven days, then measures bounded list, item-evidence, scoped summary, the five Runtime Inventory facets, Runtime Inventory Distribution, and Runtime Diff Summary queries.

Run it against an isolated PostgreSQL database:

```sh
DATABASE_URL=postgres://localhost/okoscope_inventory_benchmark \
  cargo test -p server --test inventory_benchmark -- --ignored --nocapture
```

Initial acceptance limits for a development PostgreSQL instance are:

| Operation | Cardinality | Limit |
|---|---:|---:|
| Transactional projection | 10,000 events, 1,000 items, 200 Pods | 60 seconds |
| Bounded inventory list | maximum 200 returned items | 2 seconds |
| Item evidence count | 10 memberships for one item | 2 seconds |
| Scoped summary | 1,000 items, 200 Pods, release and deployment filters | 2 seconds |
| One facet page | up to 1,000 distinct values, maximum 200 returned options | 2 seconds |

These are regression ceilings, not production SLOs. Production sizing must additionally test expected retention, concurrent agents, release cardinality, distinct Pods, filters, and pagination using sanitized synthetic data. API pages remain capped at 200 regardless of database size.

The benchmark prints measured projection, list, and detail durations. Record results with the server revision, PostgreSQL version, machine resources, and database settings when changing projection tables or indexes.

Facet acceptance data must include all five dimensions and record item, release, Pod, and distinct-value cardinalities. The first development profile assumes at most 100 clusters, 1,000 namespaces, 10 workload kinds, 10,000 workload names, and 10,000 container names per Application. These are test-shaping assumptions rather than API limits; every returned page remains capped at 200. Capture `EXPLAIN (ANALYZE, BUFFERS)` for scoped summary and each facet, including the first and cursor-bearing pages, before adding an index. Retain the plan output with the benchmark date and revision.

No new facet index is justified until this PostgreSQL-backed plan capture is complete. If a plan exceeds the two-second development ceiling, prefer a tenant/Application-leading projection index demonstrated by the slow plan and rerun migration idempotency and repair tests.

## Recorded baseline

On 2026-08-20, the expanded benchmark passed locally with PostgreSQL 17 using the repository debug test profile:

- transactional projection: 22,007 ms;
- bounded inventory list: 9 ms;
- item evidence count: less than 1 ms.
- distribution p50/p95/p99: 2/3/5 ms;
- diff summary p50/p95/p99: 3/4/6 ms;
- maximum aggregate response: 10,615 bytes.

The distribution plan used an index-only scan on `runtime_inventory_items_distribution_idx`. The isolated database used default PostgreSQL settings. These measurements establish a developer regression baseline only and do not replace deployment-specific load testing; diff tail latency remains the primary observed limitation.

Scoped-summary and facet measurements are intentionally not claimed in this historical baseline. They must be recorded by the hardening acceptance run against an isolated PostgreSQL database.

## Hardening baseline

On 2026-09-02, the hardening benchmark passed on PostgreSQL 17 at backend revision `c6bddcb5878e1da41ae31f7e8fcaa04ddd6946ee` plus the reviewed working-tree changes. The dataset contained 10,000 events, 1,000 items, 200 Pods, two namespaces, two releases, one cluster, one workload kind/name, and one container name:

- projection: 46,669 ms;
- scoped summary HTTP request: 9.94 ms; measured plan execution: 2.58 ms;
- cluster facet: 6.89 ms; measured plan execution: 2.31 ms;
- namespace facet: 5.19 ms; measured plan execution: 1.77 ms;
- workload-kind facet: 5.27 ms; measured plan execution: 1.81 ms;
- workload-name facet: 5.17 ms; measured plan execution: 1.75 ms;
- container-name facet: 5.06 ms; measured plan execution: 1.71 ms.

All plans were captured with `EXPLAIN (ANALYZE, BUFFERS)`. Summary used the sightings primary-key bitmap scan plus item/release indexes; facets used release filtering, item primary-key lookup, and `runtime_inventory_sightings_item_recent_idx`. All requests were far below the two-second development ceiling, so the measurement did not justify a new projection index or migration. Higher distinct-value production profiles remain a deployment sizing check, not a blocker for the bounded API contract.

## Expanded aggregate verification (2026-09-03)

See [high-cardinality verification](data-visualizations-high-cardinality.md) for 40,000 identities, real HTTP p99 samples, full aggregate query plans, and the confirmed default 5 / maximum 10 entry limits. The historical index-only distribution plan above explains a simplified lookup, not the full materialized-scope/window aggregate. The new oversized-label probe also demonstrates that bounded entry count does not enforce a fixed response-byte maximum; frontend task 5.4 remains open for that contract decision.
