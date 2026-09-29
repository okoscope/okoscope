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
or executable inventory identities. When a process leader exits, the agent
retains its final aggregate until the fixed window closes, delivers it once,
and then releases the process state.

Enable `observation.processExit` for task creation, rename, and exit collection.
Executable replacement remains controlled independently by `processExec`.
The agent advertises `task.lifecycle/v1` only after its task-creation, rename,
and exit CO-RE programs all load and attach. If the verifier or attachment
rejects any required program, the capability is withheld while existing exec,
network, DNS, file, resource, and Kubernetes lifecycle observers continue.
Required hooks are `tp_btf/task_newtask` for creation and
`tp_btf/task_rename` for rename, with fixed CO-RE records and bounded ring-buffer
loss counters. Both hooks and the exit program must load and attach on each
observed node before the capability is advertised. A missing or rejected hook
withholds the complete lifecycle capability; the agent does not claim accurate
rename accounting from partial hook support. See [platform support](platform-support.md)
for the supported host profile.

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
The time scope defaults to the preceding hour and must be positive and no
longer than 31 days. Windows use deterministic newest-first cursor pagination:
the default page has 50 rows, the maximum is 200, and limits outside 1-200 or
cursors outside the requested scope are rejected with `400 invalid_request`.
A process-generation filter must be paired with its observation epoch.

The summary reads at most 10,000 windows and returns `truncated=true` when
older windows are omitted. Created and exited totals sum the retained windows;
summary names combine transition counts under each observed name. The result
contains at most 66 names, folding additional names into the reserved `other`
bucket. `name_overflow` includes reported window overflow and names folded by
the summary.

Active-at-end and peak counts describe one qualified process generation and
observation epoch. When the selected windows span multiple qualified processes
or epochs, summary active, peak, and per-name active counts are `null`. A null
count means unavailable, not zero: it avoids combining incompatible absolute
populations or presenting a sum of per-process peaks as a simultaneous
Application peak. The windows retain their own measured counts.

Incomplete baselines, observation gaps, and truncation remain explicit. Clients
label affected counts as lower bounds and show unavailable counts separately. The authoritative request and response schemas are in
`openapi/okoscope-v1.yaml`.

Migration 31 creates dedicated thread-window storage. Migration 32 extends
uniqueness to the Project and observing agent and updates the process lookup
index; existing windows are preserved. Idempotency is keyed by tenant,
Project, Application, agent, process identity, generation, epoch, and window bounds. Disabling
the capability or rolling back the agent requires no destructive migration;
already stored evidence remains readable until its normal retention boundary.
Thread windows follow the Project's effective raw-runtime retention horizon
and are removed in bounded worker transactions. They do not produce retained
history snapshots; expired windows cannot be reconstructed from Runtime Groups.

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

The PostgreSQL acceptance fixture exercises 10,000 windows with 64 names each
and concurrent newest-200 queries through the Application scope index. Run it
on the intended deployment hardware to assess query latency and storage growth
before enabling observation broadly. See
[runtime inventory performance](runtime-inventory-performance.md) for acceptance
checks.
