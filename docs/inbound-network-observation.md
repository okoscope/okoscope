# Inbound network observation

Inbound observation records successful TCP listener transitions and connections actually accepted by selected Kubernetes workloads. It is disabled by default and captures no packet or application payload.

## Platform and hooks

The supported profile is Linux amd64 with cgroup v2, BTF, tracefs, and the existing agent eBPF capabilities. The `aliens` baseline checked on 2026-08-20 contains Ubuntu kernels `5.15.0-138`, `5.15.0-139`, and `6.8.0-137`; all expose `sock/inet_sock_set_state`, BTF, and the `inet_csk_accept` kernel symbol.

The agent observes effective endpoints at `sock/inet_sock_set_state`. Successful server-side established sockets are retained in a fixed 16,384-entry LRU keyed by the opaque kernel socket address. A return probe on `inet_csk_accept` proves that userspace accepted the socket in the accepting process context, looks up the endpoints, deletes the retained entry, and emits `network.accept`. This remains valid when an application calls `accept` or `accept4` with null peer-address arguments.

The agent advertises `network.listen/v1` or `network.accept/v1` only when each configured hook attaches successfully. Startup fails instead of claiming complete observation when a required hook is unavailable.

## Configuration

```yaml
observation:
  processExec: true
  syscalls: []
  network:
    listen: true
    accept: false
    maxAcceptedEventsPerSecond: 1000
```

`listen` and `accept` are independent and default to `false`. Accepted connections are subject to `maxAcceptedEventsPerSecond` and the global safety rate, queue, and batch bounds. Listener events use the global bounds.

## Event semantics

`network.listen` contains TCP transport, address family, effective canonical local address and non-zero local port. A failed `listen` call emits no event. Wildcard and dual-stack endpoints are preserved exactly as the kernel reports them; the agent does not infer equivalence between `0.0.0.0` and `::`.

`network.accept` contains TCP transport, address family, canonical local address and port, and canonical remote address and port. It proves application acceptance, not merely ingress traffic or a SYN. Remote endpoints are retained only in tenant-scoped bounded raw occurrence responses. They do not enter runtime group summaries, notification payloads, metric labels, release behavior identity, or application inventory identity.

No inbound event contains packets, socket buffers, HTTP, TLS, URLs, credentials, process environments, or unrestricted arguments.

## Grouping and inventory

Runtime groups use trusted deployment scope, event kind, receiving process command, TCP, family, and local endpoint. Different clients accepted on one local endpoint update one `network.accept` group.

Application inventory uses the kind `inbound_endpoint` and identity TCP, family, local address, and local port across deployments and releases. Its semantic evidence distinguishes `listener_observed` from `accept_observed`. Kubernetes manifest ports alone never create runtime inventory.

Release diff treats listener groups as application behavior. Changes in accepted-client addresses or traffic volume do not make a listener new or disappeared.

## Loss visibility

Heartbeats report monotonic `inbound_decode_failed`, `inbound_attribution_failed`, `inbound_unsupported_family`, `inbound_kernel_lost`, `inbound_rate_limited`, and `inbound_correlation_miss` counters. Server metrics report accepted events and created groups separately for listen and accept. None use endpoints, ports, processes, or workloads as labels.

Before expanding rollout, all counters should remain zero during a bounded canary except intentional rate limiting. A growing correlation-miss counter means the established-socket cache or selected hook semantics need investigation; it must not be interpreted as accepted traffic.

## Verification and rollback

1. Build both Linux artifacts with `docker build -f Dockerfile.agent .` and confirm the eBPF verifier accepts the object on every supported kernel line.
2. Enable `listen` only for a selected canary workload. Exercise IPv4, IPv6, wildcard, and port-zero listeners and verify canonical `network.listen` occurrences.
3. Enable `accept` with a conservative rate. Exercise ordinary and null-peer-address accept calls and verify one occurrence per successful accept, correct local/remote endpoints, selected-workload attribution, and no control-workload evidence.
4. Verify PostgreSQL raw events, one local-endpoint group across multiple clients, one application inventory endpoint with separate evidence flags, release comparison, metrics, and bounded APIs.

For one trusted application, recent raw evidence and projected endpoints can be checked with bounded queries:

```sql
SELECT event_kind, process_command, payload, observed_at
FROM runtime_events
WHERE organization_id = $1 AND project_id = $2 AND application_id = $3
  AND event_kind IN ('network.listen', 'network.accept')
ORDER BY observed_at DESC
LIMIT 100;

SELECT inventory_kind, semantic_summary, occurrence_count, first_seen_at, last_seen_at
FROM runtime_inventory_items
WHERE organization_id = $1 AND project_id = $2 AND application_id = $3
  AND inventory_kind = 'inbound_endpoint'
ORDER BY last_seen_at DESC
LIMIT 100;
```

Rollback is configuration-first: disable `accept` and `listen`, then roll back the agent if necessary. The additive server remains compatible with older agents and can retain already accepted evidence.

## Canary evidence and acceptance thresholds

The `aliens` canary was rechecked on 2026-09-02. Agents on Ubuntu kernels
`5.15.0-138`, `5.15.0-139`, and `6.8.0-137` attached the required hooks and
advertised both inbound capabilities. The selected `payment-api` workload on
`6.8.0-137` produced an IPv6 wildcard listener, accepted-connection evidence
with trusted workload/process attribution, and an IPv4 loopback listener bound
to port zero whose effective kernel-assigned port was `35919`. Multiple accepted
remote ports converged on one group per local endpoint and remote endpoints were
retained only in raw occurrences.

The canary also exposed a pre-filter accounting defect: ordinary TCP state
transitions with a zero local port incremented `inbound_decode_failed`. The
transition classifier now ignores irrelevant states before endpoint validation.
Do not expand a deployment until a 15-minute steady-state window meets all of
these thresholds:

- `inbound_decode_failed`, `inbound_attribution_failed`,
  `inbound_unsupported_family`, and `inbound_kernel_lost` have zero delta;
- `inbound_correlation_miss` has zero delta under ordinary traffic and remains
  below 0.1% of accepted events during a stress run;
- `inbound_rate_limited` is zero below the configured limit and matches the
  expected excess above it;
- raw events, group occurrence totals, and inventory occurrence totals reconcile;
- the number of accepted-connection groups and inbound inventory items remains
  equal to local endpoint cardinality, independent of remote client cardinality.

If any threshold fails, disable `accept` first, then `listen`, verify that the
capabilities disappear after the agent rollout, and retain the additive server
schema while the agent is rolled back.
