# File activity syscall-path profile

`file.activity.syscall-path/v1` is an experimental, opt-in observation profile. It reports successful operations only when the agent can retain a bounded normalized absolute pathname argument supplied by the process. It does not claim to resolve symbolic links, relative paths, bind-mount aliases, hard links, or canonical filesystem object identity.

## Probe matrix

The syscall tracepoint field layouts below were checked on the live `aliens` nodes running Ubuntu 5.15.0-138, 5.15.0-139, and 6.8.0-137. Linux 6.1 uses the same stable syscall tracepoint argument/return ABI and remains a required build/verifier target before production enablement.

| Operation | Entry/exit tracepoints | Retained fields | Success rule |
|---|---|---|---|
| open/create | `sys_enter_openat`, `sys_exit_openat` | `dfd`, pathname, flags | returned fd >= 0; create is certain only with `O_CREAT|O_EXCL` |
| modify | `sys_enter_write`, `sys_exit_write` | fd resolved through a successful tracked open | return > 0 |
| truncate | `openat` with `O_TRUNC`, `sys_enter_truncate`, `sys_exit_truncate` and tracked `ftruncate` | absolute pathname or tracked fd | successful open or return == 0 |
| delete | `unlink` and `unlinkat` entry/exit pairs | pathname, plus `dfd` and flags for `unlinkat` | return == 0 and `AT_REMOVEDIR` is absent |
| rename | `rename` and `renameat2` entry/exit pairs | ordered old/new pathnames, plus dirfds and flags for `renameat2` | return == 0; replacement is known false only with `RENAME_NOREPLACE`, otherwise unknown |
| lifecycle | `sys_enter_close`, `sys_exit_close` | fd | successful close removes tracked fd state |

All argument slots are eight bytes in the checked tracepoint formats; syscall return is the signed eight-byte field at offset 16. The probe reads pathname bytes with a fixed user-string bound and rejects relative, non-normalized, unterminated, oversized, or unreadable values before they can enter output.

## Deliberate limitations

- Relative pathname arguments are counted and dropped; the agent does not consult `/proc/<pid>/cwd` or guess a `dirfd` path.
- A successful open without `O_EXCL` cannot prove that `O_CREAT` created a new file, so it does not emit `file.create` in v1.
- Descriptor modifications are visible only while the `(TGID, fd, generation)` mapping from a successful absolute-path open is retained.
- The first profile covers the documented syscall set, not memory-mapped dirty-page writeback or filesystem activity that bypasses those calls.
- Paths describe process input, not a canonical inode. Filters and server grouping intentionally operate on that reported identity.

These constraints make the evidence incomplete but non-guessing. Loss counters distinguish relative paths, user-memory read failures, oversize paths, missing descriptor mappings, correlation misses, capacity, and ring-buffer loss.

## Configuration

File activity is disabled by default. Enabling it requires at least one operation and one
normalized absolute include prefix. Exclusions win and matching is on path-component
boundaries, so `/app/data` does not match `/app/database`.

```yaml
observation:
  files:
    enabled: true
    operations: [create, modify, delete, rename]
    includePaths: [/app/data]
    excludePaths: [/app/data/private, /app/data/cache]
```

Paths are bounded to 1024 bytes including the terminating NUL in the kernel record. Create,
delete, and rename are delivered immediately. Modify is deliberately delayed by the fixed
five-second `FILE_MODIFY_AGGREGATION_WINDOW`; a rename or delete flushes an earlier pending
modify first. The window is a code constant and is not configurable.

## Privacy and telemetry

The event contains process-visible pathname metadata, which can itself be sensitive. Narrow
includes and explicit exclusions are therefore part of the safety boundary. File contents,
write buffers, byte counts, host-translated paths, mount IDs, and inode IDs are never sent.
Rejected path values and workload names are not written to logs or metric labels.

Heartbeat and server metrics expose only bounded aggregate counters: correlation capacity and
misses, path read/relative/invalid/oversize rejection, descriptor misses, configured filtering,
aggregation capacity, decode/rate/queue loss, and kernel ring loss. A rising relative-path or
descriptor-miss counter normally means the workload uses a path form outside v1. Kernel loss or
aggregation capacity means observation should be narrowed before increasing general queue limits.

## Staged enablement and rollback

Deploy the additive server schema first, then roll out agents with `files.enabled: false`. Enable
one selected workload with a narrow include, verify readiness advertises
`file.activity.syscall-path/v1`, and compare accepted events with all loss counters before widening
scope. The Kubernetes e2e fixture exercises an identically active unselected workload and an
excluded subdirectory to make leakage visible.

Rollback is disable-only: set `files.enabled: false` and restart the agent. This detaches the
profile and removes the capability from the next session; stored additive events and schema stay
readable and require no destructive database rollback. If startup is unready, inspect the error
for the exact missing tracepoint/map/profile component; partial hook coverage is never advertised.

## Automated end-to-end acceptance

Run the repeatable kernel-to-release test against the `aliens` context with a selected workload
release and an earlier baseline release:

```sh
E2E_RELEASE_VERSION=smoke-v2 \
E2E_BASELINE_RELEASE_ID=00000000-0000-0000-0000-000000000000 \
tests/kubernetes/file-activity-e2e.sh
```

File observation must already be enabled. The test generates unique create, aggregated modify,
rename, and delete operations in the bounded fixture, then verifies capability registration, raw
durability, group occurrences, first-seen outbox work, inventory navigation and sightings, release
projections, release-diff classification, and selected/excluded workload isolation.
