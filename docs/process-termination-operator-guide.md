# Process termination and restart evidence

Okoscope keeps three authorities separate:

- `process.exit` is kernel evidence. A normal status or terminating signal is
  native; `128 + signal` is display-only convention. The wait-status core flag
  does not prove that a core file exists.
- `container.terminated` and `container.restart` are Kubernetes/runtime
  evidence. `OOMKilled` is authoritative only for that source.
- `container.restart_loop` is derived evidence using projection version 1:
  three observed increments in ten minutes for one container lifetime.

`SIGKILL` or conventional 137 alone never means OOM. `CrashLoopBackOff` is a
waiting/backoff state, not a termination cause. Correlation requires matching
tenant, workload, Pod UID, container name/runtime ID and the documented
30-second event-time tolerance; multiple candidates remain ambiguous.

## Scope and blind spots

Version 1 observes regular app containers, not init or ephemeral containers.
Events can be absent before agent startup, after ring-buffer loss, during Pod
watch degradation, or when generation/attribution state was evicted. No stack,
core content, environment, or unrestricted argument data is captured.

The agent advertises `process.exit/v1` only after the C CO-RE object loads and
attaches, and `container.lifecycle/v1` only while the typed Kubernetes watch is
trusted. Check heartbeat counters for `exit_*` and `lifecycle_*`, readiness
detail, and structured logs before treating absence as evidence of no crash.

## Verification

```sql
SELECT event_kind, payload, observed_at, received_at
FROM runtime_events
WHERE organization_id = $1
  AND event_kind IN ('process.exit','container.terminated','container.restart')
ORDER BY observed_at DESC
LIMIT 100;

SELECT * FROM runtime_event_correlations
WHERE organization_id = $1 AND project_id = $2;

SELECT * FROM runtime_restart_projection_memberships
WHERE organization_id = $1 AND project_id = $2
ORDER BY window_ended_at DESC;
```

API responses are tenant scoped, paginated, and `Cache-Control: no-store`.
Rollback withholds capabilities and stops projection work; additive raw evidence
and migration 0013 remain readable and are not destructively removed.
