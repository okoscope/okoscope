# Termination correlation and restart projection profile

Version 1 correlates kernel and Kubernetes evidence only when organization,
project, application, workload UID, Pod UID, container name, runtime container
ID, and a 30-second absolute event-time tolerance all agree. Zero candidates
remain absent and multiple candidates remain ambiguous. Source events are never
rewritten or deleted.

Restart projection version 1 requires three observed restart increments in a
rolling ten-minute event-time window for one trusted Pod/container lifetime.
Delta jumps contribute their exact observed delta and retain the observation-gap
flag. Event-ID membership is idempotent, late events recompute only their bounded
window, and state is capped at 100,000 occurrences with a two-window retention
horizon.

The controlled fixture matrix covers services, workers, Jobs, and sidecars. A
1,000-occurrence local benchmark is included as
`representative_restart_volume_remains_bounded`; it validates the v1 threshold
and capacity behavior. On the 2026-08-23 development run, 1,000 mixed-profile
occurrences completed in 152 ms. This does not change the 3-in-10-minutes decision. Production
canary latency and false-correlation metrics remain rollout gates rather than
inputs that silently change projection version 1.

The same run classified 2,000 controlled correlation fixtures (1,000 exact
lifetime matches and 1,000 replacement-container mismatches) without a false
match in under 5 ms. The durable query is capped at two candidates and retains
the selected symmetric 30-second event-time bound.
