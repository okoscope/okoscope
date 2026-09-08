# Resource utilization canary — 2026-09-07

This report records the first production canary of the opt-in cgroup v2 resource
profile on the `aliens` cluster. Collection was limited to the existing
`okoscope-quickstart/quickstart-demo` Application. Raw phase samples and deployed
configuration are in `resource-canary-2026-09-07.json`.

## Deployed versions

- Server: `ghcr.io/okoscope/okoscope-server@sha256:e429ed8ff5a05ceb4b69ec6a39c986748afcd0725b599c68bcb55fe3797ea159`
- Web: `ghcr.io/okoscope/okoscope-web@sha256:45465ee3cfd86d059911809c2c11f6c2deb615ad98137121860ac306eaab348c`
- Agent after the canary fix: `ghcr.io/okoscope/okoscope-agent@sha256:05128c2390dfbd516029174064afe788ccaa2997884c87d3f3724e1836a7364b`
- Server schema migration: 25
- Resource configuration: 15-second sampling, one-minute aggregation, 4,096
  cgroup states, 1,024 open aggregates, queue capacity 256, batch size 64.

The server schema and API were deployed first, Web second, and agents last. The
agents were initially deployed with collection disabled and then enabled only for
the selected Application.

## Load profile

The profile repeated the earlier agent benchmark phases: 90 seconds background,
120 seconds paced HTTP, 120 seconds four-worker HTTP burst, 120 seconds
four-worker process burst, and 90 seconds recovery. The demo retained its 100m
CPU limit, so the burst rate remained generator-limited.

| Phase | Achieved load | Agent mean CPU | Agent p95/max CPU | Working set mean/max | RSS mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| Background | No synthetic load | 39.79m | 40.28m / 40.28m | 55.69 / 55.71 MiB | 23.13 MiB |
| Paced HTTP | 1,039 successes, 0 failures | 63.97m | 80.79m / 80.79m | 55.69 / 55.71 MiB | 23.13 MiB |
| HTTP burst | 2,668 successes, 0 failures | 59.73m | 63.33m / 63.33m | 55.71 / 55.73 MiB | 23.14 MiB |
| Process burst | 4,664 successes, 0 failures | 67.53m | 79.05m / 79.05m | 55.71 / 55.73 MiB | 23.14 MiB |
| Recovery | No synthetic load | 47.79m | 55.01m / 55.01m | 55.70 / 55.72 MiB | 23.14 MiB |

Against the earlier current-profile run, mean CPU changed by -1.15m at
background, +9.45m for paced HTTP, +1.18m for HTTP burst, +3.17m for process
burst, and -1.27m during recovery. Working set was about 0.8 MiB lower. These
separate runs are useful envelope checks but are not an identical simultaneous
A/B, so they do not close the CPU, memory, throughput, or application-latency
release gates. Achieved throughput changed by -2.3%, -7.0%, and +1.8% in the
three load phases. The HTTP burst difference exceeds the 3% budget, but the
generator was CPU-limited and no request latency was recorded; causality cannot
be assigned to resource collection.

## Collection correctness

The initial canary exposed `unavailable_sources=64` for the PID source. The
collector requested `pids.events.local`, while cgroup v2 exposes `pids.events`.
The source path and regression fixture were corrected, the agent was rebuilt,
and the enabled DaemonSet was rolled forward.

After the fix, ten observed one-minute contributions had
`unavailable_sources=0`. Full buckets contained four samples and approximately
59.999 seconds of covered time. All 24 v1 metrics were present, including CPU
usage and throttling, CPU/memory/I/O PSI, memory values and events, I/O rates,
and PID values and events. Every contribution was attributed to the selected
Application and its Release. The first post-restart bucket was partial by design;
subsequent complete buckets reached effectively 100% coverage.

The controlled load produced visible CPU contention signals: across the clean
post-fix window, CPU throttled-period ratio averaged 13.3% and reached 98.5% in a
minute, while CPU PSI `some` averaged 12.8% and reached 90.5%. Memory headroom
averaged 96.3%; memory, I/O, OOM, and PID-limit event counters stayed at zero.

## Storage, queries, and delivery

During the measured query snapshot, 15 contributions and 379 rollup points used 112 KiB for the
contribution table and 272 KiB for the rollup table, including indexes and table
overhead. This startup-sized sample cannot be extrapolated reliably to the
250 MiB/Application/day budget.

A representative warm 24-hour minute query for `cpu_usage_cores` returned 15
points in 0.203 ms execution time. The current sample is too small to validate
the 24-hour p95, 30-day hourly, or release-comparison latency gates.

The resource queue is independent from runtime-event delivery and acknowledged
aggregates continued to produce idempotent contributions and rollups across
reconnects. No negative counter deltas appeared after the fixed-agent restart.
Agent logs still show recurring gRPC HTTP/2 `INTERNAL_ERROR` resets followed by
immediate reconnection. This behavior existed before resource collection and is
a confounder for a backend-outage/recovery gate. Resource health counters are
carried in Hello and heartbeat messages, but this run did not capture every
counter at phase boundaries, so the loss-counter reconciliation gate remains
open.

## Gate decision

The one-Application canary validates deployment order, cgroup source parsing,
aggregation, persistence, Release attribution, clean full-bucket coverage, and a
small warm query. It also found and corrected a real PID-source portability bug.

After independent live verification, collection was rolled back with
`observation.resources.enabled=false` in agent Helm revision 5. All three agents
became Ready with zero restarts. PostgreSQL still contained all 24 contributions,
including 19 clean post-fix contributions and Release attribution on every row;
after another aggregation window the count and latest interval remained unchanged
at `2026-09-07 15:03:00Z`. This confirms that rollback stops new sampling and
retains existing history.

It does not enable the profile by default. The full release benchmark still
needs identical agent-off/current/resource-on runs, application p95 latency,
many-container cardinality, explicit pressure and malformed-source cases,
short-lived containers, controlled agent restart and backend outage, transport
byte accounting, database growth at scale, cleanup failure/retry, and long-range
API latency. Keep broader rollout gated until those measurements pass the
documented budgets.
