# Aggregate high-cardinality verification — 2026-09-03

This report records high-cardinality verification for the data visualization API. The executable harness is [benchmark_visualizations.py](../tools/benchmark_visualizations.py). It requires an empty, migrated, isolated local PostgreSQL database, `psql`, Python 3, and a current `target/debug/server` built with `cargo build -p server --bin server`.

```sh
python3 tools/benchmark_visualizations.py \
  postgres://okoscope@127.0.0.1:55439/viz_benchmark \
  /tmp/okoscope-viz-results.json
```

The harness inserts synthetic projection rows directly to isolate aggregate read cost from ingestion cost. It starts the actual backend on loopback, authenticates an owner session, measures complete HTTP bodies, validates default/maximum limits and full-scope totals, and extracts the actual SQL from the backend source for `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)`. It terminates its backend process after measurement; the caller owns database lifecycle. Never use a shared database.

## Profile and interpretation

Backend revision: `810660cef5a0fe73cc9be2cd297459a87833e71c`, debug build. Host: Apple M2 Pro, 12 logical CPUs, 16 GiB RAM. PostgreSQL 17, isolated local cluster. No production data or Kubernetes resources are involved.

The synthetic profile contains 40,000 inventory identities and diff groups, 10,000 identities per original visualization kind, 40,000 event rows and sightings, 2,000 Pods, 20 namespaces, 100 workloads, one application/cluster and two releases. Release overlap produces new, disappeared and unchanged groups. Counts vary from 1 through 100; timestamps span seven days. These are directly seeded read-model fixtures, not a projection correctness or ingestion-throughput test. They do not establish expected production cardinalities or a production SLO.

Each endpoint/limit configuration uses ten warmup requests followed by 300 sequential HTTP requests with a persistent connection. Durations include authentication, database queries, JSON serialization and full response reading over loopback. Percentiles use nearest rank; p99 is sample 297 of 300. Requests are not concurrent. Plan timings are separate, uninstrumented HTTP samples determine reported latency. Response sizes are uncompressed JSON bytes excluding HTTP headers.

## Response bound caveat

Top-N is a row-count bound, not an enforced aggregate byte budget. `ProcessExec.executable` is a `String`; inventory identity normalization checks nonempty strings but imposes no maximum length. Both aggregate handlers return stored `semantic_summary` values. Consequently, a measured maximum for ordinary labels is not a contract-wide maximum response size. A separate oversized-label probe tests this distinction; it is not included in latency percentiles.

Do not mark frontend task 5.4 complete on the basis of a small observed payload alone. A guaranteed byte budget requires an explicit backend contract for bounded identity fields or a defined bounded aggregate representation, plus enforcement and regression coverage. Silently truncating identity fields can alter identity semantics and is not an acceptable incidental benchmark change.

## Results

PostgreSQL 17.4; `shared_buffers=128 MiB`, `work_mem=4 MiB`, `max_connections=100`, `random_page_cost=4`. Raw samples and full plans: [benchmark results](data-visualizations-benchmark-results.json). Host was a shared developer laptop; background OS workloads were not disabled.

| Endpoint | Limit | p50 ms | p95 ms | p99 ms | Max ms | Max JSON bytes |
|---|---:|---:|---:|---:|---:|---:|
| process | 5 | 5.86 | 9.30 | 11.55 | 13.73 | 5,436 |
| process | 10 | 6.40 | 6.94 | 9.56 | 14.40 | 10,710 |
| destination | 5 | 6.02 | 6.50 | 10.01 | 15.94 | 5,958 |
| destination | 10 | 6.73 | 7.36 | 9.39 | 46.02 | 11,752 |
| domain | 5 | 5.89 | 6.44 | 11.56 | 17.65 | 5,669 |
| domain | 10 | 6.45 | 7.03 | 9.65 | 13.40 | 11,175 |
| syscall | 5 | 6.15 | 6.78 | 7.14 | 13.37 | 5,506 |
| syscall | 10 | 6.82 | 7.62 | 9.98 | 15.90 | 10,848 |
| scoped_process | 5 | 18.72 | 23.37 | 34.08 | 63.01 | 5,433 |
| scoped_process | 10 | 19.19 | 23.34 | 36.33 | 58.86 | 10,704 |
| diff | 5 | 37.62 | 39.48 | 40.75 | 70.10 | 2,413 |
| diff | 10 | 37.93 | 40.50 | 47.50 | 87.15 | 3,672 |

All 3,600 measured requests succeeded. The scoped process query selects baseline release, namespace `ns-0`, and workload kind `Deployment`, matching 1,333 identities. Every ordinary distribution matches 10,000 identities; top entries plus `other` account for all item and occurrence totals. Diff classifications account for all 40,000 groups. HTTP checks confirmed omitted limit returns five entries, explicit limits 1 and 10 return those counts, and 0/11 return HTTP 400 for every tested route.

The default 5 / maximum 10 bounds remain suitable for this synthetic development profile: every measured request is below the existing two-second development regression ceiling. Reducing top-N does not eliminate full-scope aggregation work. This is evidence for retaining the entry-count limits, not approval of unrestricted production scopes or a fixed byte budget.

## Query-plan review

These are the actual aggregate SQL statements extracted from the current handler source, explained with literal parameter values after `ANALYZE`. They are not the simplified ordered-index lookup used by the historical benchmark. They also do not claim to capture every SQLx prepared/generic plan; the HTTP latency measurements exercise the backend's real connection pool and prepared statements.

- Unfiltered distributions scan 40,000 inventory rows, select 10,000 matching rows, materialize the scope, compute complete window totals and use in-memory top-N heapsort. Plan execution is 9.89–10.35 ms. A sequential scan is reasonable for this one-application fixture; the aggregate does not become an index-only top-ten lookup because totals require the full scope.
- Scoped process uses `runtime_inventory_items_kind_recent_idx` and hashed scope subplans over releases/sightings, then window totals and top-N heapsort for 1,333 rows. Plan execution is 24.77 ms.
- Diff classifications compare the full release union through hash joins and aggregate three classifications (30.83 ms). Largest changes use a parallel hash full join, in-memory sort / gather merge, and group primary-key lookups (22.43 ms).
- All captured plan nodes report zero temporary read/write blocks; no observed spill requires an index or `work_mem` change for this profile. Data cardinality, label width, release selectivity, generic plans and concurrent ingestion can change that conclusion.

## Remaining acceptance issue

The separate oversized-label probe stores 131,072-byte process labels and requests ten entries. The real HTTP endpoint returns **200 with 1,321,222 JSON bytes**. This directly disproves treating the normal-fixture maximum of 11,752 bytes, or the old benchmark's 1 MiB body-read limit, as a guaranteed API response cap. This probe seeds stored summaries directly; it demonstrates response behavior, not acceptance through every agent/transport ingestion path. Event-model and projection code independently show no process executable length constraint.

A contract-wide response-byte bound remains open (along with deployment representativeness if production acceptance is required). Backend follow-up must select and document a byte/identity-field budget, enforce it consistently without changing opaque identity selection semantics or silently losing evidence, cover existing oversized stored values, and rerun the oversized-label and high-cardinality checks. Frontend workarounds are unnecessary.
