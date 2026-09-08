# Notification activation implementation audit

The existing notification subsystem already provides the data-plane guarantees required for production activation:

- migration 4 stores encrypted destinations, durable deliveries, bounded attempt history, leases, and uniqueness for each outbox/destination pair;
- `FOR UPDATE SKIP LOCKED`, conditional lease ownership, and the partial unique index support concurrent server replicas;
- shutdown stops the worker loop and the server waits for an in-progress cycle for a bounded interval;
- URL policy, signing, response truncation, retry classification, backfill suppression, destination tests, tenant-scoped APIs, request IDs, and group notification summaries have integration coverage;
- current metrics include materialization, claims, attempts, retries, failures, pending, in-flight, and expired leases.

The smallest production activation change is therefore configuration and operations work, not a replacement worker or database migration:

1. fail fast when enabled notification configuration is invalid;
2. provide a listener-free `notification-check` command that validates configuration and schema and reports only safe activation metadata;
3. make shutdown drain an explicit bounded setting;
4. expose worker activation, enabled destination count, due/retrying/terminal counts, oldest due age, cycle failures, and drain outcomes;
5. render disabled/enabled worker settings strictly into immutable deployment artifacts and provenance;
6. prove the existing delivery contract locally and in the reference cluster before leaving activation enabled.

Receiver outages remain metrics/log signals and do not make the API unready. Delivery remains disabled by default, and global disable preserves durable outbox and delivery rows.

The destination, one-time-secret, test-delivery, delivery-history, and group-summary APIs already use explicit serialized structures and tenant-scoped pagination. Worker health remains an operator metric rather than a bearer-authenticated Web API: the bounded state gauge is sufficient for self-hosted activation, while the frontend milestone treats a future typed health endpoint as optional and does not invent a client-side contract.

## Reference deployment checkpoint

On 2026-08-17, release `b4de1ab31d25a6d5627eaf015ad991cd7a30a0c4` was deployed to the `aliens` cluster with delivery disabled. Migration 6 and the listener-free notification check completed before rollout. Both server replicas, all three agent Pods, both Web replicas, the public routes, and the certificate were healthy. Build info matched the release, 15 existing runtime events remained present, the worker state was `0` (disabled), and every process-local notification delivery counter remained zero. The sole historical database attempt predated this rollout; no pending or in-flight delivery existed.

A temporary path-scoped HTTPS receiver then verified the timestamped HMAC signature and stable delivery identifier without exposing its URL or signing secret in repository or release artifacts. Test delivery succeeded. With both server workers enabled, a selected `process.exec` behavior produced one logical delivery, received one deterministic retryable response, recovered on the second attempt, and reached `delivered` state in the group API. Repeating the same behavior increased its occurrence count to two without another logical delivery. Receiver verification recorded zero invalid signatures.

The destination was disabled before global delivery was returned to disabled through a configuration-fingerprinted rolling update. The rollout completed inside the configured drain bound with zero pending or in-flight acceptance deliveries; delivery history and the two group occurrences remained durable. The temporary receiver route, workload, service, configuration, and signing Secret were removed. Recovery is to recreate a controlled receiver, rotate the destination secret, and explicitly render delivery enabled through the same preflight sequence.

## Recovery and retention acceptance

On 2026-08-17, release `06296fdb96df83621ac81395ab2bf780de34a0be` was exercised in the `aliens` cluster with retention disabled. Isolated Project-scoped fixtures proved single retry, equivalent idempotent replay, changed-input conflict, cancellation, bounded bulk retry with remaining work, and bulk changed-input conflict. A controlled receiver accepted the recovered delivery with HTTP 200 and the delivery became terminally succeeded. The raw API credential, idempotency keys, destination URL, signing secret, and payload were not recorded.

Delivery was then restored to disabled and all recovery fixtures and temporary receiver resources were removed. A separate one-shot retention command used isolated deliveries older than one day: it deleted exactly one terminal delivery while preserving old pending and in-flight deliveries and their attempts. The surviving fixtures and the one-shot Job were removed afterward. Final verification showed delivery and retention disabled, no acceptance fixture identifiers, and the original notification table counts restored.
