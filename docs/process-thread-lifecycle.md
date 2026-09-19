# Process and thread lifecycle observation

Okoscope treats process creation, executable replacement, and process
termination as separate observed facts:

- `process.start` is emitted when the kernel creates a thread-group leader.
- `process.exec` retains its existing meaning: a process successfully replaced
  its executable image. Repeated execs do not imply repeated process creation.
- New classified `process.exit` evidence is emitted only for a thread-group
  leader. Historical process-exit rows remain unchanged and may contain legacy,
  unclassified task exits. Inventory reads label these as
  `legacy_unclassified`; capable-agent exits are labeled `leader`.

Lifecycle-capable agents attach one qualified generation to `process.start`,
every repeated `process.exec`, thread windows, and the leader `process.exit`.
Exec refreshes executable evidence without allocating a generation. When the
first evidence is exec, thread activity, or exit, the generation is explicitly
incomplete (`start_observed=false`); no start is backfilled and no bare PID is
joined. Historical exec and exit payloads omit the additive generation field.

Runtime inventory retains its stable broad kinds while its summary adds a
`process_lifecycle` object with separate `created`, `executed`, and `terminated`
occurrence totals. This prevents clients from inferring creation from exec or
mixing process termination with container lifecycle counts.

Non-leader task creation, rename, and exit are aggregated in fixed 60-second
windows. Each window contains authoritative process-level created, exited,
active-at-start, active-at-end, and peak-active counters. Current task names are
deduplicated into at most 64 normal buckets; additional unseen names use the
closed `other` bucket and increment an overflow counter. A rename moves a live
task between current-name buckets without changing the process-level active
total. Names and counters do not create Runtime Groups, policies, suppressions,
or executable inventory identities.

The agent advertises `task.lifecycle/v1` only after its task-creation, rename,
and exit CO-RE programs all load and attach. If the verifier or attachment
rejects any required program, the capability is withheld while existing exec,
network, DNS, file, resource, and Kubernetes lifecycle observers continue.
The production `union` canary matrix is Ubuntu 22.04 Linux
5.15.0-138/139-generic and Ubuntu 24.04 Linux 6.8.0-137-generic. Every exact
kernel must pass verifier loading during the production canary.

The implementation spike selected `tp_btf/sched_process_fork` for creation and
`tp_btf/task_rename` for rename, with fixed CO-RE records and bounded ring-buffer
loss counters. The programs built and the verifier accepted and attached both
hooks on the local LinuxKit 7.0.12 development kernel; successful load produced
no verifier rejection log. Decoder fixtures prove leader/non-leader
classification, fixed layouts, malformed-size rejection, bounded UTF-8 command
handling, and native exit-status decoding. The production `union` inventory is
Ubuntu 22.04 Linux 5.15.0-138-generic and 5.15.0-139-generic plus Ubuntu 24.04
Linux 6.8.0-137-generic, all with BTF; those exact kernels remain the rollout
gate. Failure to load or attach either BTF
tracepoint withholds the entire `task.lifecycle/v1` capability instead of
degrading rename accuracy, while existing observers remain enabled.

## Evidence quality and bounds

Every process generation has an observation epoch. A generation created from a
kernel start is marked start-observed; state first encountered after observation
began is explicitly incomplete. Thread windows expose `baseline_provenance`,
`baseline_complete`, `name_overflow`, and closed gap reasons. Consumers must
treat active counts as lower bounds whenever the baseline is incomplete or a
gap is present.

Within a process generation, each observed task creation receives an
independently monotonic task generation. Live state is keyed by process
generation, TID, and task generation. Kernel monotonic timestamps prevent a
late rename or exit from a prior use of the same TID from moving or removing the
replacement task; detected reuse with a missed transition marks the window with
an explicit kernel-loss gap.

The authenticated Application endpoints are:

- `GET /api/v1/projects/{project_id}/applications/{application_id}/thread-activity`
- `GET /api/v1/projects/{project_id}/applications/{application_id}/thread-activity/summary`

Both require an explicit or default bounded time scope, enforce existing
tenant-safe not-found authorization, and return `Cache-Control: no-store`.
Windows support deterministic cursor pagination up to 200 rows per page. A
process-generation filter must be paired with its observation epoch. The
summary reads at most 10,000 windows and returns `truncated=true` when totals
are lower bounds. The authoritative request and response schemas are in
`openapi/okoscope-v1.yaml`.

Migration 31 creates dedicated idempotent storage keyed by tenant,
Application, process identity, generation, epoch, and window bounds. Disabling
the capability or rolling back the agent requires no destructive migration;
already stored evidence remains readable.

## Measured bounds

The initial fixed limits are 64 distinct normal names per process generation,
60-second windows, 200 windows per API page, 10,000 windows per summary, and an
8,192-entry agent lifecycle-state budget shared across selected processes and
tasks. Snapshot enumeration stops at that same hard task budget and reports
`snapshot_truncated`.

Application heartbeats include additive unlabeled lifecycle diagnostics only
after a transition has trustworthy Application attribution: output drops,
generation misses, snapshot failures/truncation, name overflow, incomplete
windows, and delivery gaps. Kernel loss, decode failure, unknown-task rename,
and attribution failure occur before a safe tenant route exists and remain
node-local metrics, readiness state, and safe logs; they are never guessed or
distributed among Applications.

The PostgreSQL benchmark fixture inserted 10,000 windows with 64 names each and
ran eight concurrent newest-200 queries through the Application scope index.
On the local development PostgreSQL instance it used 12,361,728 bytes including
indexes, inserted in 811 ms, and completed the concurrent query set in 129,515
µs. The checked test requires the query set to remain below one second;
production canary work must remeasure these figures with concurrent agents.
