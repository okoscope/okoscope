# Resource utilization observation

Okoscope can sample Linux cgroup v2 resource counters for selected Kubernetes
workloads. Collection is disabled by default. When enabled, each node agent reads
only cgroup accounting files, aggregates measurements into fixed one-minute UTC
windows, and sends bounded, retryable batches through the existing authenticated
Application stream.

## Enable collection

Add the resource profile to the agent values file:

```yaml
observation:
  resources:
    enabled: true
    sampleIntervalSeconds: 15
    aggregationIntervalSeconds: 60
    maxCgroupStates: 4096
    maxOpenAggregates: 1024
    queueCapacity: 256
    batchSize: 64
```

The sampling interval accepts 10–60 seconds. Aggregation is fixed at 60 seconds.
The chart and agent reject state, queue, and batch sizes outside their bounded
ranges. Disable the profile to stop cgroup scans and capability advertisement;
stored history remains subject to retention.

Collection requires cgroup v2 and the existing read-only `/sys/fs/cgroup` host
mount. The agent advertises the resource capability only when the profile is
enabled and `/sys/fs/cgroup/cgroup.controllers` exists. Unsupported or missing
files produce availability metadata and gaps rather than invented zero values.

### cgroup v2 source contract

The collector treats a directory containing the validated 64-hex container ID
as the container leaf and keys its counter baseline by both directory inode and
container ID. A reused inode or changed container ID starts a fresh lifetime.
It does not derive a container measurement from a Pod-level cgroup. A container's
namespaced `/proc/self/cgroup` may report only `0::/`; host leaf discovery and
inode/container mapping remain authoritative. This is the file contract used by
the Linux 6.1 build/verifier profile; 5.15 and 6.8 kernels are accepted through
feature detection rather than a kernel version check.

| File | Required keys and meaning | Feature detection |
| --- | --- | --- |
| `cpu.stat` | `usage_usec`, `nr_periods`, `nr_throttled`, `throttled_usec` are cumulative | Missing file or keys make CPU values unavailable |
| `cpu.max` | quota and period in microseconds; `max` means no finite quota | Missing or malformed values omit quota-derived ratios |
| `memory.current` / `memory.max` | charged bytes; `max` means no finite limit | Each value is detected independently |
| `memory.stat` | `anon` and `file` charged bytes | Unknown keys are ignored; missing keys remain unavailable |
| `memory.events.local` | cumulative `high`, `max`, `oom`, `oom_kill` events for the leaf | Local events avoid ancestor double counting |
| CPU, memory and I/O `pressure` | cumulative `total` stall microseconds for `some` and `full` | `some` and `full` remain independently optional |
| `io.stat` | cumulative `rbytes`, `wbytes`, `rios`, `wios`, summed across devices | Added device keys are ignored; arithmetic overflow rejects the sample |
| `pids.current`, `pids.max`, `pids.events` | current tasks, finite/`max` limit, cumulative `max` events | Missing PID files affect only PID metrics |

The parser accepts added keys and arbitrary key order. Empty, malformed, or
overflowing unsigned values are unavailable. A cumulative counter decrease is a
reset: the interval is discarded and the current sample becomes the next
baseline. Bounded fixtures cover these semantics.

The 2026-09-07 `aliens` inventory checked cgroup v2 nodes running
5.15.0-138/139 and 6.8.0-137. Both exposed `cpuset`, `cpu`, `io`, `memory`,
`hugetlb`, `pids`, `rdma`, and `misc` controllers and every file in the table.
The 5.15 `cpu.stat` omitted newer `core_sched`, `nr_bursts`, and burst keys; the
6.8 source added them, which confirms that unknown-key handling is required.
Both exposed unlimited CPU as `max 100000`, finite CPU as `10000 100000`, and
unlimited PIDs as `max`. The 6.8 `io.stat` also exposed `dbytes` and `dios`, which
are intentionally ignored. This source-level check confirms feature detection;
the controlled workload and overhead canary remains a separate release gate.

## Metrics and formulas

The agent reads `cpu.stat`, `cpu.max`, `memory.current`, `memory.max`,
`memory.stat`, `memory.events.local`, CPU/memory/I/O `pressure`, `io.stat`,
`pids.current`, `pids.max`, and `pids.events`. Unknown keys are ignored so newer
kernels remain compatible. Counter decreases start a new baseline and are never
reported as negative usage.

The server exposes these derived series:

| Family | Metrics | Calculation |
| --- | --- | --- |
| CPU | usage cores, quota ratio | CPU microseconds / covered microseconds; usage cores / quota cores |
| Throttling | throttled period ratio, throttled seconds | throttled periods / periods; throttled microseconds / 1,000,000 |
| Memory | current, anonymous, file, headroom | sampled gauge average; `(limit - current) / limit` when a finite limit exists |
| Memory events | high, max, OOM, OOM kill | counter delta in the aggregation window |
| Pressure | CPU, memory, and I/O `some`/`full` ratios | PSI stalled microseconds / covered microseconds |
| I/O | read/write bytes and operations per second | counter delta / covered seconds |
| Processes | current, limit ratio, max events | sampled gauge average, current / limit, event delta |

Every point includes covered and expected seconds, samples, contributors,
observed and ready replicas, and a coverage ratio. Coverage below 0.8 is returned
as insufficient with a null value. `mode=per_ready_replica` reports the weighted
per-replica value; the default `total` scales it by effective covered replicas.

## APIs and release interpretation

Application history is available from:

`GET /api/v1/projects/{project_id}/applications/{application_id}/resources`

The required query parameters are `metric`, `from`, `to`, and `step`; optional
filters are `release_id`, `container`, and `mode`. Minute history is bounded to 31
days and hourly history to 366 days.

Release comparison is available from:

`GET /api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/resource-comparison`

An optional `baseline_id` selects an explicit baseline. Otherwise the server uses
deployment transition evidence and reports the baseline selection source. It
excludes a 10-minute warm-up and compares 30-minute windows. A comparison needs
at least 80% coverage and 24 minute buckets. Findings use rule version 1 and can
surface OOM events, reduced memory headroom, increased CPU throttling, increased
CPU/memory/I/O pressure, and utilization growth in Application and Organization
Attention. Non-OOM findings require three adjacent covered buckets. An active
finding closes after two consecutive clean background evaluations, which avoids
flapping on a single recovered interval.

These findings describe timing and measured changes. They do not assert that a
release caused a resource change. Scaling, traffic, noisy neighbors, and platform
changes may overlap the same window.

## Retention and operating cost

Raw node contributions and minute rollups default to 7 days. Hourly rollups
default to 90 days. Organization defaults are stored in PostgreSQL; a Project may
override both within 1–31 days for detail and up to 366 days for rollups. Cleanup
is bounded and runs with the existing runtime retention worker.

Sampling cost grows with selected container cgroups and sampling frequency.
State, open aggregates, transport queues, and batches are hard bounded. Start with
one low-risk Application and the defaults, then watch agent CPU/memory, resource
drop/reset counters, batch acknowledgements, database growth, history query
latency, and coverage before enabling more workloads.

Resource telemetry contains numeric kernel accounting, workload identity,
container name, node name, and Release identity. It does not read application
payloads, environment variables, command arguments, or file contents. Tenant and
Application scope is resolved from the authenticated stream on the server.

### Canary budgets and v1 rule constants

Resource collection may be enabled beyond one controlled Application only after
an A/B canary meets every budget below. Compare agent-off, the current observation
profile, and the same profile with resource collection on, using identical
ordinary and many-container workloads. Report both the measured value and the
sample duration; a missing measurement does not pass a gate.

| Gate | v1 canary budget |
| --- | --- |
| Agent CPU | Resource-on adds at most 20 millicores to steady-state mean and 50 millicores to p95 versus the current profile |
| Agent memory | Working set grows by at most 24 MiB, remains below the 96 MiB request in the ordinary workload, and shows no upward trend after recovery |
| Application impact | Throughput falls by at most 3% and p95 latency rises by at most 3% versus agent-off |
| Bounded state | Cgroup states stay at or below 4,096 and open aggregates at or below 1,024; ordinary load has no state-capacity eviction |
| Transport | Resource payload is at most 1 MiB per node per minute; acknowledgements catch up within two aggregation windows after recovery and ordinary load has no queue drops |
| Storage | Detailed plus rollup growth is at most 250 MiB per canary Application per day at its measured cardinality |
| Cleanup | One bounded pass completes within 60 seconds, advances its watermark, reports no error, and a forced transaction failure is recovered on the next pass |
| Query latency | Warm-cache p95 is at most 500 ms for a 24-hour minute query and 1 second for a 30-day hourly query and release comparison |
| Coverage | Ordinary load is at least 95%; pressure, outage, and restart cases retain at least 80% or show explicit gaps; coverage returns to 95% within two aggregation windows |

The existing 2026-09-07 `aliens` profile provides the starting envelope: the
loaded agent used about 41 millicores and 56.5 MiB at background, while burst
work reached about 64 millicores and 56.5 MiB. Its 100 millicore / 96 MiB requests
therefore leave the incremental budgets above without assuming the resource
profile has already passed. That run also observed retries and capacity loss
during bursts, so transport catch-up and explicit coverage gates are mandatory.

The v1 constants are fixed and versioned as follows:

| Constant | v1 value |
| --- | ---: |
| Detailed contribution/minute retention | 7 days |
| Hourly rollup retention | 90 days |
| Target warm-up after readiness | 10 minutes |
| Baseline and target stable windows | 30 minutes each |
| Minimum comparison coverage | 80% and at least 24 one-minute buckets on each side |
| Sustained finding | 3 adjacent covered one-minute buckets |
| Finding recovery hysteresis | 2 consecutive clean evaluations |
| CPU throttled-period finding | target and increase at least 5 percentage points |
| CPU, memory, or I/O PSI finding | target at least 5% and increase at least 3 percentage points |
| Memory headroom finding | target at or below 10% |
| Memory high/max event finding | increase of at least 1 event |
| CPU or memory utilization finding | increase of at least 25% when the baseline is non-zero |
| OOM-kill finding | at least 1 event; emitted immediately |
| Rule version | 1 |

The 80%/24-bucket requirement permits at most six missing minute buckets without
hiding loss. The ten-minute warm-up exceeds the short backlog recovery observed
in the existing profile. A five-percentage-point pressure threshold clearly
separates the demo workload's measured 65.3% throttled periods from the agent's
0.036%, while the three-bucket rule rejects brief spikes. These choices remain
release-gated until the resource-enabled A/B and controlled canary measurements
pass the budgets above.

The completed `aliens` release-gate run is recorded in
[`benchmarks/resource-release-gates-2026-09-07.md`](benchmarks/resource-release-gates-2026-09-07.md).
CPU, memory, state, payload-size, storage, cleanup-retry, and query-latency gates
passed. The paced application-impact and post-outage coverage-recovery gates did
not pass, while direct filesystem-read accounting remained unavailable on the
hardened host. Keep resource collection opt-in until a follow-up run passes every
gate.

The retention worker publishes bounded, label-free cleanup telemetry as
`okoscope_resource_retention_cleanup_deleted_rows_total`,
`okoscope_resource_retention_cleanup_errors_total`,
`okoscope_resource_retention_cleanup_duration_microseconds_total`, and
`okoscope_resource_retention_cleanup_last_success_timestamp_seconds`. Cleanup
updates its closure watermarks and deletes detail/hourly rows in one transaction;
an error rolls the watermark and deletions back so the next worker pass can retry.

## Troubleshooting and rollback

- No resource capability: confirm `enabled: true`, a unified cgroup v2 hierarchy,
  and the read-only cgroup mount.
- Gaps or insufficient coverage: inspect agent capacity/drop/reset counters,
  reconnects, short-lived containers, and missing kernel files. Increase bounded
  capacities only after confirming pressure.
- No Release attribution: resource history remains valid, but the observed
  Release identity did not resolve inside the authenticated Application scope.
- No comparison: wait for the warm-up and target window, or inspect the response's
  `collecting`, `insufficient_coverage`, `no_baseline`, or `unavailable` state.
- Unexpected regression: compare replica counts, limits, traffic, node placement,
  and platform changes before acting on the release.

To roll back collection, set `observation.resources.enabled=false` and upgrade the
agent release. This stops new scans and resource batches without deleting stored
history. Server and Web support can remain deployed while collection is disabled.
The disabled default is covered by the agent handshake test: it omits
`resource.utilization/v1`, while unrelated observation capabilities continue to
operate. Resource retention is server-side and continues to follow its policy,
so turning collection off does not erase existing rows.
