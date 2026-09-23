# Outbound network observation acceptance evidence

Acceptance was completed on 2026-08-18 in the `aliens` Kubernetes context against Linux 5.15 nodes.

## Immutable rollout

- Server and agent: `ghcr.io/okoscope/okoscope-{server,agent}:42c160e3f55029fa927c36b95cb87bca25e72be6`
- Web: `ghcr.io/okoscope/okoscope-web:7f3c1465b5aa995f241636d67d720b1f6b631fec`
- Server and Web were available before network observation was enabled.
- The agent DaemonSet completed rollout with 3/3 Ready pods and successfully attached both connect tracepoints.

## Controlled fixture

Observation was enabled only for the `Job/selected-network-fixture` workload in the temporary `okoscope-network-acceptance` namespace. A second Job remained unselected.

The selected workload produced four acknowledged events:

- IPv4 succeeded;
- IPv4 failed with bounded errno 111 at the same endpoint as the succeeded event;
- IPv4 non-blocking attempt with `EINPROGRESS` errno 115;
- IPv6 succeeded.

The agent reported `sent: 4`, `acknowledged: 4`, `retried: 0`, and zero capacity, decode, or kernel-output loss. The unselected workload produced zero stored events.

## Storage and grouping

PostgreSQL contained canonical typed `NetworkConnect` payloads with release attribution to `smoke-v2-20260817`. The succeeded and failed occurrences at the same IPv4 endpoint shared one runtime group with occurrence count two. IPv6 was stored canonically as `::1`.

Release summaries and one safe `runtime_group.first_seen` outbox item per new group were present. Searches across stored payloads found none of the forbidden packet payload, DNS, source-port, URL, header, or body fields.

## Quality gates

- Rust formatting, Clippy with warnings denied, unit tests, and PostgreSQL integration tests passed.
- The eBPF object and production agent/server containers built successfully on Linux.
- OpenAPI validation and generated-client checks passed.
- Web unit, build, Playwright, narrow-viewport, and axe checks passed.
- Kubernetes manifests and deployment policy checks passed.

## Rollback

After acceptance, the base agent ConfigMap was restored with `observation.network.connect: false`, the DaemonSet returned to 3/3 Ready, and the temporary acceptance namespace was deleted. Stored evidence was retained; no Secret, PostgreSQL data, or PVC was removed.
