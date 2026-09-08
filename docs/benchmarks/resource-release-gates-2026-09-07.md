# Resource observation release gates — 2026-09-07

This report extends the controlled `aliens` canary with comparable agent-off,
current-profile, and resource-on measurements. It records failed gates as failed;
resource observation remains disabled by default.

## Method

The ordinary scenario used one `quickstart-demo` replica. The many-container
scenario temporarily used six replicas on `worker-192.168.0.9`, then returned to
the original single replica. Every profile ran the same phases: 45 seconds idle,
60 seconds paced HTTP, 60 seconds four-worker HTTP burst, 60 seconds process
burst, and 45 seconds recovery. HTTP timing uses BusyBox `time`; phase duration
includes Kubernetes sampling and boundary snapshots, so throughput is normalized
by measured rather than requested duration.

The raw results are:

- `resource-ab-agent-off-2026-09-07.json`
- `resource-ab-current-2026-09-07.json`
- `resource-ab-resource-on-2026-09-07.json`
- `resource-ab-many-agent-off-2026-09-07.json`
- `resource-ab-many-current-2026-09-07.json`
- `resource-ab-many-resource-on-2026-09-07.json`

The test used the canary agent image
`sha256:05128c2390dfbd516029174064afe788ccaa2997884c87d3f3724e1836a7364b`.
Agent-off used an unmatched temporary node selector. Current kept the existing
process and network profile with resource collection disabled. Resource-on used
15-second cgroup sampling and one-minute aggregation. All temporary selectors and
replica changes were reverted.

## Ordinary workload

| Phase | Profile | Throughput | HTTP p95 | Agent mean / p95 CPU | Working set mean / max | RSS mean |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Idle | Current | — | — | 35.85m / 38.29m | 41.31 / 42.21 MiB | 8.78 MiB |
| Idle | Resource-on | — | — | 42.20m / 46.28m | 55.66 / 55.66 MiB | 23.12 MiB |
| Paced HTTP | Agent-off | 7.742/s | 20 ms | — | — | — |
| Paced HTTP | Current | 6.075/s | 60 ms | 57.89m / 60.76m | 41.81 / 42.23 MiB | 9.29 MiB |
| Paced HTTP | Resource-on | 5.839/s | 90 ms | 66.37m / 87.49m | 55.69 / 55.71 MiB | 23.14 MiB |
| HTTP burst | Agent-off | 11.079/s | 300 ms | — | — | — |
| HTTP burst | Current | 8.760/s | 350 ms | 66.59m / 78.48m | 42.26 / 42.29 MiB | 9.73 MiB |
| HTTP burst | Resource-on | 9.306/s | 320 ms | 67.96m / 71.53m | 55.71 / 55.73 MiB | 23.14 MiB |
| Process burst | Agent-off | 44.039/s | — | — | — | — |
| Process burst | Current | 34.001/s | — | 57.47m / 58.36m | 42.27 / 42.30 MiB | 9.74 MiB |
| Process burst | Resource-on | 35.263/s | — | 56.23m / 59.09m | 55.69 / 55.70 MiB | 23.14 MiB |
| Recovery | Current | — | — | 38.92m / 39.15m | 42.26 / 42.28 MiB | 9.74 MiB |
| Recovery | Resource-on | — | — | 42.06m / 44.52m | 55.70 / 55.71 MiB | 23.15 MiB |

Resource-on added 1.37–8.48 millicores to mean CPU in the comparable idle and
HTTP phases and 7.99–26.73 millicores to p95. Process-burst mean was 1.24m lower.
Working set increased by 13.4–14.4 MiB and remained below the 96 MiB request. CPU
and memory pass their incremental budgets in this run.

Paced HTTP throughput was 3.9% below current and 24.6% below agent-off; p95 rose
from 60 to 90 ms versus current. HTTP-burst throughput was 6.2% above current but
16.0% below agent-off. The generator and 100m demo limit introduce visible
between-run noise, but the strict application-impact budget cannot discard an
unfavourable result as noise. This gate fails.

## Six-replica workload

| Phase | Profile | Throughput | HTTP p95 | Agent mean / p95 CPU | Working set mean / max |
| --- | --- | ---: | ---: | ---: | ---: |
| Idle | Current | — | — | 44.08m / 48.23m | 41.35 / 41.38 MiB |
| Idle | Resource-on | — | — | 49.88m / 53.21m | 41.35 / 41.38 MiB |
| Paced HTTP | Agent-off | 40.100/s | 40 ms | — | — |
| Paced HTTP | Current | 29.353/s | 70 ms | 91.00m / 118.85m | 42.95 / 47.02 MiB |
| Paced HTTP | Resource-on | 27.990/s | 90 ms | 89.26m / 110.26m | 42.67 / 43.50 MiB |
| HTTP burst | Agent-off | 71.305/s | 350 ms | — | — |
| HTTP burst | Current | 49.804/s | 430 ms | 93.22m / 98.06m | 47.14 / 47.36 MiB |
| HTTP burst | Resource-on | 57.736/s | 350 ms | 88.60m / 95.77m | 47.41 / 47.62 MiB |
| Process burst | Agent-off | 238.280/s | — | — | — |
| Process burst | Current | 176.409/s | — | 107.26m / 133.29m | 47.80 / 48.08 MiB |
| Process burst | Resource-on | 197.659/s | — | 92.05m / 95.12m | 48.17 / 48.35 MiB |
| Recovery | Current | — | — | 53.72m / 56.13m | 48.01 / 48.04 MiB |
| Recovery | Resource-on | — | — | 51.17m / 51.84m | 48.81 / 48.81 MiB |

Resource-on added 5.8m idle mean CPU; under generated load its sampled CPU was
1.7–15.2m lower than current. Working-set differences remained within 0.8 MiB.
The six-replica state stayed far below the 4,096 cgroup and 1,024 open-aggregate
bounds. No source became unavailable and no negative counter delta appeared when
the Deployment returned from six replicas to one.

Paced throughput was 4.6% below current and p95 rose from 70 to 90 ms. Burst and
process throughput were higher with resource-on, again demonstrating run noise.
The paced result fails the 3% application-impact budget.

## Pressure, restart, outage, and recovery

The HTTP/process phases drove the demo's CPU quota and produced sustained CPU
throttling and CPU PSI in resource history. A separate 60-second I/O burst made
280 synchronous 8 MiB overwrites of one temporary file. The resulting full
one-minute point reported 13.84 MB/s writes, 39.67 write operations/s, and 2.66%
I/O PSI `some` and `full`, with 99.9997% coverage. Memory high/max, OOM, and
OOM-kill events remained zero. The temporary file was removed.

Repeated Helm profile changes restarted all agents without negative deltas. The
six-to-one scale transition produced a final six-container partial bucket and a
new one-container lifetime rather than mixing old baselines.

For the backend-outage case, only the canary agents were pointed at an
unreachable loopback endpoint for about 170 seconds; the production server and
Web remained available. Resource queue and batch bounds were temporarily reduced
to two. Agents used bounded exponential reconnect backoff. Restoration used the
normal endpoint and bounds. PostgreSQL preserved explicit gaps from 17:12 to
17:15 UTC, then received a 24.95%-covered restart bucket and a later 99.997%
full bucket with every source available. Full coverage did not return within two
aggregation windows, so the recovery budget fails. Restarting the agents to
restore their endpoint intentionally discarded process-local pending data; the
test verifies bounded loss and explicit gaps, not successful queue replay.

## Transport, storage, cleanup, and queries

At idle, loaded-node agent TX changed from 0.11 KiB/s in current to 0.22 KiB/s
with resource-on, an observed increment of about 6.6 KiB/node/min. Under event
load, total agent traffic reached 32.67 KiB/s, but that includes runtime events
and cannot be assigned to resource payloads. Stored contributions averaged 1,342
bytes and never exceeded 1,360 bytes; one aggregate per node/container-name/
Release/minute remains far below the 1 MiB/node/min resource payload budget.
Direct process read-syscall accounting was unavailable through the hardened host
`/proc` mount, so the filesystem-read gate remains unmeasured.

The live sample contained 39 contributions and 1,027 rollup points, using 160 KiB
and 696 KiB including indexes. A rolled-back PostgreSQL scale transaction created
51,840 indexed rollup points: 24 metrics at one-minute resolution for 24 hours and
hourly resolution for 30 days. It occupied 29 MiB. The representative warm
queries completed in 4.95 ms for 24-hour minute history, 3.81 ms for 30-day hourly
history, and 1.80 ms for a 30-minute release aggregate. These pass the 500 ms/
1 second query budgets and remain below the 250 MiB/Application/day storage
budget at measured cardinality.

Resource cleanup metrics recorded 5.38 seconds cumulative execution, three
transaction errors caused by observed PostgreSQL deadlocks, and a later successful
timestamp. Server logs show the next bounded minute pass succeeding after each
failure. No rows were old enough for deletion. This validates rollback/retry and
the 60-second bound; deletion and watermark movement remain covered by the
PostgreSQL integration test.

## Decision

CPU, memory, bounded state, payload size, storage, cleanup retry, and query
latency fit their canary budgets. The application-impact and outage recovery gates
do not pass. Direct filesystem-read and phase-boundary resource loss counters were
not measurable from this deployed image. Resource observation therefore remains
disabled by default and broad selector rollout remains blocked. The data is still
useful for an opt-in controlled Application because gaps and source availability
remain explicit.
