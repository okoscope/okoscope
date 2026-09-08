# Multi-Application stream acceptance

Benchmark, local acceptance, and the `aliens` release verification were completed
on 2026-09-02 for the coordinated Application-credential stream release. Secret
values were not printed or retained in the report.

## Selected bounds and benchmark

The supported hard limits are 32 distinct Application streams per agent and 4,096
queued events per stream. The defaults use those limits with batches of 256 events.
Configuration above either hard limit is rejected before observers start.

The ignored queue benchmark fills every per-stream buffer and measures the process
resident-set increase. On an Apple Silicon development host using the debug test
profile it produced:

| Streams | Queued events | RSS increase |
| ---: | ---: | ---: |
| 1 | 4,096 | 4,560 KiB |
| 8 | 32,768 | 26,224 KiB |
| 16 | 65,536 | 49,664 KiB |
| 32 | 131,072 | 96,560 KiB |

This worst-case filled-buffer result remains below the production agent's 512 MiB
memory limit and grows linearly. Each distinct route owns exactly one bounded queue,
task, and gRPC connection; selector routes sharing a credential are deduplicated.

Run each count in a fresh process so allocator retention does not affect the next
measurement:

```sh
for streams in 1 8 16 32; do
  OKOSCOPE_BENCHMARK_STREAMS="$streams" \
    cargo test -p agent application_queue_memory_is_bounded -- --ignored --nocapture
done
```

The PostgreSQL 17 benchmark performs 1,000 indexed authentication updates plus
active-credential checks. Average latency was 220, 202, 204, and 221 microseconds
for credential sets of 1, 8, 16, and 32 respectively. No count-dependent regression
was observed.

```sh
DATABASE_URL=postgres://okoscope@127.0.0.1:55432/okoscope \
  cargo test -p server --test application_credentials \
  credential_check_overhead_is_bounded -- --ignored --nocapture
```

## Local end-to-end verification

Against an isolated PostgreSQL 17 instance, the provisioning, Application
credential, and ingestion suites cover hierarchy creation, one-time token exposure,
multiple streams, automatic tenant-scoped Cluster resolution, durable acknowledgement
and deduplication, rotation, mid-stream revocation, and cross-Application isolation:

```sh
DATABASE_URL=postgres://okoscope@127.0.0.1:55432/okoscope \
  cargo test -p server --test provisioning --test application_credentials \
  --test ingestion -- --ignored --nocapture
```

The acceptance run exposed and fixed a concurrent observed-Release insert conflict,
then passed the race test five consecutive times and the complete suites.

## `aliens` release verification

Select the required context before every command:

```sh
kubectx aliens
```

The 2026-09-02 audit confirmed commit
`155bad900ac41ae87acbee0c41645b94af3a6232` on the server and all three agents,
migration 21 complete, healthy server/agent rollout, read-only projected Application
credential files, the admin credential sourced from a Secret, and narrow agent RBAC
for reading the `kube-system` Namespace. Agent logs showed accepted Application
streams, acknowledgements, and no credential material.

Two isolated acceptance Applications were temporarily mapped to `payment-api` and
`control-api`. Their events remained separated by Application ID while both reused
one automatically discovered Cluster in the acceptance Organization. Replacing the
first Application's Secret with its rotation credential and rolling the DaemonSet
preserved ingestion for both Applications. After revoking the active first credential,
its event count remained 104 while the second Application increased from 242 to 292,
proving revocation stopped only the selected stream. The original selector and Secret
projection were restored, all three agent Pods returned Ready, the temporary Secret
was deleted, and all three acceptance credentials were revoked. Acceptance tenant
metadata and events remain in PostgreSQL because tenant deletion is out of scope.

Rollback remains application-only after ingestion begins: roll back the agent first,
then the server, preserve applied migrations and PostgreSQL/PVC identities, and never
restore or print revoked plaintext credentials.
