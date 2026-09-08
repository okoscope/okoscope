# Outbound network observation

Outbound network observation records completed `connect()` syscall attempts for explicitly selected Kubernetes workloads. It is disabled by default and supports only the documented Linux x86_64, cgroup v2 production profile with the `syscalls/sys_enter_connect` and `syscalls/sys_exit_connect` tracepoints.

## Enablement

Enable the capability for a bounded fixture before expanding workload selectors:

```yaml
observation:
  processExec: true
  syscalls: [ptrace, setns]
  network:
    connect: true
```

When enabled, the agent advertises `network.connect/v1`. Startup fails rather than silently claiming readiness if either required tracepoint cannot be attached. Existing process and syscall observation are unchanged when network observation is omitted or disabled.

Each event contains the selected workload and process identity, entry observation time, `ipv4` or `ipv6`, canonical destination IP, destination port, and one syscall outcome:

- `succeeded`: `connect()` returned zero;
- `in_progress`: non-blocking `connect()` returned Linux `EINPROGRESS` (115); this does not prove that a handshake later completed;
- `failed`: `connect()` returned another bounded Linux errno.

The first release does not infer TCP versus UDP from the file descriptor and describes records as connection attempts, not established flows.

## Privacy boundary

The probes copy only bounded `sockaddr_in` or `sockaddr_in6` destination fields. They do not capture packet payloads, socket buffers, HTTP headers or bodies, URLs, TLS contents, DNS names, Unix-domain paths, source ephemeral ports, process environments, or unrestricted arguments. Unsupported socket families are counted and discarded before address bytes are retained.

Destination IPs remain tenant-scoped runtime evidence. They must not be used in logs or metric labels, reverse-resolved, or converted into untrusted clickable links by clients.

## Capacity and cardinality

Pending syscall state uses a fixed 4096-entry kernel map keyed by `pid_tgid`; the event ring buffer, userspace queue, batch size, and global event-rate limit remain bounded. Runtime groups use exact workload, process command, address family, destination IP, and destination port. Outcome and errno remain occurrence fields and do not split group identity.

Rotating destination IPs can produce many groups. Enable one workload at a time, watch group creation and loss counters, and disable observation before increasing selectors if cardinality or queue pressure is unexpected.

## Troubleshooting counters

Agent hello/heartbeats expose monotonic, unlabeled counters:

- `connect_correlation_capacity`: pending map insertion failed;
- `connect_correlation_miss`: an exit had no retained entry;
- `connect_decode_failed`: pointer, length, port, result, or userspace conversion was invalid;
- `connect_unsupported_family`: a non-IPv4/IPv6 socket family was ignored;
- `connect_kernel_lost`: a completed record could not reserve ring-buffer space.

None of these counters include destination, tenant, workload, PID, or event identity. Inspect them together with existing unattributed, capacity, replay, and acknowledgement counters.

## Rollout and rollback

Deploy the compatible server and Web UI before the agent. Verify the server accepts the additive protobuf variant and the UI safely renders `network.connect`, then deploy the agent with `connect: false`. Enable only the controlled fixture, exercise successful, failed, and non-blocking attempts, and verify storage, grouping, release diff, notification, API, and UI behavior.

Rollback by setting `observation.network.connect: false` and rolling back the agent first. Stored network events use the existing JSON payload column and require no destructive migration; compatible server and Web versions may remain deployed. Never delete PostgreSQL data, Secrets, or PVCs as part of rollback.

