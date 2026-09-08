# MVP deployment and verification

The bundled manifest is an evaluation deployment. It uses plaintext gRPC and example credentials and MUST NOT be exposed outside an isolated development cluster.

## Build and deploy

### Images from GitHub Container Registry

The `ci` GitHub Actions workflow tests the workspace and builds multi-platform (`linux/amd64`, `linux/arm64`) agent and server images. Pushes to `main`, version tags matching `v*`, and manual runs publish:

- `ghcr.io/<owner>/<repository>-agent:<commit-sha>`
- `ghcr.io/<owner>/<repository>-server:<commit-sha>`

The workflow also publishes the `main`, version-tag, and `latest` aliases when applicable. Deploy immutable commit-SHA tags rather than mutable aliases. Every publishing run provides an `okoscope-mvp-<commit-sha>` artifact containing `okoscope-mvp.yaml` with both image references already rendered; download it from the workflow run and apply it:

```sh
kubectl apply -f okoscope-mvp.yaml
kubectl -n okoscope rollout status deployment/okoscope-server
kubectl -n okoscope rollout status daemonset/okoscope-agent
```

For private GHCR packages, create a pull secret with a token that has `read:packages`, then attach it to both service accounts before rollout:

```sh
kubectl -n okoscope create secret docker-registry ghcr \
  --docker-server=ghcr.io \
  --docker-username='<github-user>' \
  --docker-password='<token-with-read-packages>'
kubectl -n okoscope patch serviceaccount default \
  -p '{"imagePullSecrets":[{"name":"ghcr"}]}'
kubectl -n okoscope patch serviceaccount okoscope-agent \
  -p '{"imagePullSecrets":[{"name":"ghcr"}]}'
kubectl -n okoscope rollout restart deployment/okoscope-server
kubectl -n okoscope rollout restart daemonset/okoscope-agent
```

The job requests `packages: write` for its `GITHUB_TOKEN`. Organization policies may override this; verify **Settings → Actions → General → Workflow permissions** if GHCR returns `permission_denied`.

### Local images

Build `okoscope/server:dev` from `Dockerfile.server` and `okoscope/agent:dev` from `Dockerfile.agent`, load them into the target cluster, then apply:

```sh
kubectl apply -k deploy/kubernetes/common
kubectl apply -f tests/kubernetes/e2e-workloads.yaml
kubectl -n okoscope rollout status deployment/okoscope-server
kubectl -n okoscope rollout status daemonset/okoscope-agent
```

The agent requires host PID visibility, `/proc`, cgroup v2, tracefs, BTF, and eBPF privileges. The MVP manifest uses `privileged: true`; production hardening must replace it with the smallest capability set validated for the target distribution. The agent can observe process metadata for every workload on its node even though it forwards only configured workloads, so node access and images must be tightly controlled.

Before a cluster deployment, the image can be smoke-tested on a compatible Docker Linux VM. The repository includes a raw agent configuration at `docs/examples/agent.yaml`; unlike `agent-config.yaml`, it is not wrapped in a ConfigMap. With a valid kubeconfig mounted for client initialization, the following command mounts tracefs, loads both eBPF programs, and attaches `process.exec` to `sched/sched_process_exec` and syscall observation to `raw_syscalls/sys_enter`:

```sh
docker run --rm --privileged --platform linux/amd64 \
  -e KUBECONFIG=/root/.kube/config \
  -v "$HOME/.kube/config:/root/.kube/config:ro" \
  -v "$PWD/docs/examples/agent.yaml:/etc/okoscope/agent.yaml:ro" \
  -v /path/to/application-token:/var/run/secrets/okoscope/applications/payment-api:ro \
  --entrypoint /bin/sh okoscope/agent:dev \
  -c 'mount -t tracefs tracefs /sys/kernel/tracing && exec /usr/local/bin/okoscope-agent'
```

If attachment succeeds, the agent proceeds to server connection attempts. An `attach okoscope_exec` or `attach okoscope_sys_enter` error instead means the kernel-side smoke test failed. This smoke test validates probe loading and attachment only; Kubernetes attribution and PostgreSQL persistence are covered by the acceptance checks below.

For a non-development installation, remove `developmentPlaintext`, issue a server certificate whose SAN contains the service hostname, mount its certificate/key into the server and the CA certificate into agents, and configure `OKOSCOPE_TLS_CERTIFICATE`, `OKOSCOPE_TLS_PRIVATE_KEY`, and `server.caFile`. When `server.caFile` is set, the agent trusts that custom CA independently of the container's system root store; when it is absent, the agent uses system roots. Store every one-time Application credential in a Kubernetes Secret and never commit its value.

## Web UI API

The versioned browser contract is [`openapi/okoscope-v1.yaml`](../openapi/okoscope-v1.yaml). Generate a client in the separate UI repository with an OpenAPI 3.1-compatible generator; use `GET /api/v1/build-info` without authentication to compare `api_version`, `git_commit`, and `required_database_migration` before loading the UI.

Organization creation and global `/api/v1/admin/...` discovery use only `adminAuth`. Project and Application creation plus Application-credential listing, issuance, and revocation accept either `bearerAuth` for the owning Organization or `adminAuth`; cross-tenant targets return a non-enumerating `404`. Browser provisioning POST requests should send a newly generated canonical UUID in `Idempotency-Key`. Organization and Project retries return the original resource. Application and credential retries return `operation_already_completed` and never expose their one-time plaintext token again. Provisioning validation errors use stable machine-readable codes and may include a `fields` map for form-level feedback.

All protected routes currently accept the operator bearer credential. Storing this credential in browser storage gives the browser broad tenant access, so this is an MVP deployment model, not user authentication. Prefer a same-origin reverse proxy that keeps the API and UI behind TLS and injects or brokers credentials server-side. User sessions and scoped RBAC remain future work.

Cross-origin browser access is disabled by default. Set `OKOSCOPE_CORS_ORIGINS` to a comma-separated list of exact `http` or `https` origins (for example `https://okoscope.example.com`); wildcards and URL paths are rejected at startup. Roll out first with an empty value, verify same-origin access, then add only the UI origin and check an authenticated preflight. CORS grants browser permission only—it never replaces bearer authentication.

Transactional email uses standard authenticated SMTP and a PostgreSQL outbox. Prefer the Helm interface documented in [production self-hosting](self-hosted-deployment.md#transactional-email): it maps non-secret `mail` values to `OKOSCOPE_MAIL_*` / `OKOSCOPE_SMTP_*` settings and reads the SMTP username, password, and dedicated 64-hex-character mail encryption key only from Kubernetes Secrets. The worker is off by default. Production requires HTTPS action links plus STARTTLS or implicit TLS with certificate validation; plaintext SMTP is limited to an explicitly selected local development configuration.

The server image receives `OKOSCOPE_GIT_COMMIT` as a Docker build argument in GitHub Actions; local builds deterministically report `unknown`. This milestone has no database migration. Rollback consists of deploying the previous server image and removing `OKOSCOPE_CORS_ORIGINS`; stored runtime data is unaffected.

For navigation performance, run [`ops/queries/navigation.sql`](../ops/queries/navigation.sql) with tenant IDs from the installation and confirm PostgreSQL uses tenant/ownership indexes rather than unbounded scans.

## Acceptance checks

Trigger process execution in the selected and control Deployments:

```sh
kubectl -n okoscope-demo exec deploy/payment-api -- /bin/sh -c true
kubectl -n okoscope-demo exec deploy/control-api -- /bin/sh -c true
```

Trigger the configured `setns` syscall in the selected workload. The call may return `EPERM` in the unprivileged test container, but the `sys_enter` observation still records the attempted syscall:

```sh
kubectl -n okoscope-demo exec deploy/payment-api -- nsenter -t 1 -m true
```

Port-forward PostgreSQL and inspect selected events:

```sh
kubectl -n okoscope port-forward service/postgres 5432:5432
psql postgres://okoscope:okoscope@localhost:5432/okoscope -f ops/queries/recent-events.sql
psql postgres://okoscope:okoscope@localhost:5432/okoscope -f ops/queries/runtime-groups.sql
```

The query must show a `process.exec` row with `process_command = 'sh'`, namespace `okoscope-demo`, kind `Deployment`, and workload `payment-api`; it must not show `control-api`. A short-lived executable can disappear from `/proc` before userspace enrichment, so the MVP falls back to the kernel `comm` value (`sh`) instead of promising the original `/bin/sh` path. The agent indexes the host cgroup v2 hierarchy by inode so this race does not lose container attribution.

The `nsenter` command must produce a `syscall` row whose payload names `setns`. The attempt returning `EPERM` is expected and platform-specific: the MVP observes syscall entry, not its return value. Agent JSON logs expose filtered, unattributed, unsupported, decode-failed, capacity-dropped, kernel-lost, sent, retried, and acknowledged counters. After the control execution, `filtered` must increase while no `control-api` event is stored.

## Upgrade and rollback

Apply additive migrations before or together with a compatible server, then roll the server before the DaemonSet. Protocol version negotiation rejects incompatible agents explicitly.

Rollback removes or restores the DaemonSet first, then restores the server image. Do not delete the StatefulSet PVC or run reverse/destructive migrations. Database removal is a separate operator-approved action.

Known limits: one tested Linux profile, Deployment owner chains only, bounded in-memory per-Application delivery buffers, DaemonSet rollout required for credential changes, no raw-event retention policy or UI, and no enforcement or risk scoring.

## Runtime event grouping upgrade

Migration `0003_runtime_event_groups.sql` is additive and required by server readiness. The current coordinated agent protocol uses an Application credential for each stream; the server derives Organization, Project, and Application from its SHA-256 digest and discovers Cluster identity from the agent's Kubernetes UID. `api-credential` continues to authenticate the existing read API until user authorization replaces it.

List groups using the Organization-bound credential. Project and Application are explicit filters, while Organization is always derived from the credential:

```sh
kubectl -n okoscope port-forward service/okoscope-server 8080:8080
curl -H 'Authorization: Bearer <api-credential>' \
  'http://localhost:8080/api/v1/runtime-groups?project_id=<project-uuid>&application_id=<application-uuid>'
curl -H 'Authorization: Bearer <api-credential>' \
  'http://localhost:8080/api/v1/runtime-groups/<group-uuid>'
curl http://localhost:8080/metrics
```

Rotate the API credential by changing the Secret value and restarting the server. Bootstrap replaces the stored digest for the `self-hosted` credential, invalidating the previous value.

Existing raw events are not grouped automatically. Run the explicit, restartable backfill as a one-off server container during a controlled window:

```sh
okoscope-server \
  --database-url postgres://okoscope:okoscope@postgres:5432/okoscope \
  backfill \
  --organization-id <organization-uuid> \
  --project-id <project-uuid> \
  --fingerprint-version 1 \
  --batch-size 500 \
  --throttle-ms 50
```

Backfill-created `runtime_group.first_seen` outbox records have `source=backfill`. Webhook destinations suppress these messages by default and require an explicit `deliver_backfill` opt-in before materialization.

To roll back, deploy the prior server image. The additive grouping tables remain unused and raw-event ingestion continues. Do not reverse or drop migration `0003` during a service rollback. Inspect group totals, ungrouped events, and pending outbox records with `ops/queries/runtime-groups.sql`.

## First-seen observability upgrade

Migration `0006_first_seen_observability.sql` adds deterministic first-seen event identity and operator lifecycle metadata. Deploy migration 0006 and the compatible server before enabling lifecycle or occurrence views in the separate Web UI. The UI compatibility gate must require build-info `required_database_migration >= 6` and regenerate its client from `openapi/okoscope-v1.yaml`; older servers do not provide these routes or fields.

The group detail API now returns a secret-free notification summary, while raw occurrences use the separately bounded `/api/v1/runtime-groups/{group_id}/occurrences` collection. Use `docs/first-seen-observability-smoke.md` for the deployed verification procedure. Rollback to an older server image leaves the additive migration in place; do not drop the new columns during rollback.

## Webhook notification delivery

Migration `0004_notification_delivery.sql` is additive. The example manifest supplies a syntactically valid development encryption key but leaves `OKOSCOPE_NOTIFICATION_DELIVERY_ENABLED=false`. Replace the key with 32 cryptographically random bytes encoded as 64 hexadecimal characters before creating destinations; back it up separately from PostgreSQL. Losing the key makes stored signing secrets undecryptable.

Create a Project destination through the authenticated API:

```sh
curl -X POST \
  -H 'Authorization: Bearer <api-credential>' \
  -H 'Content-Type: application/json' \
  http://localhost:8080/api/v1/projects/<project-uuid>/webhook-destinations \
  -d '{"name":"primary","url":"https://receiver.example.com/okoscope","deliver_backfill":false}'
```

The generated `secret` appears only in this response. Store it in the receiver secret manager. List/get APIs never return plaintext or encrypted secret material. Rotate through `POST .../<destination-id>/rotate-secret`; the response contains the replacement once. Disable with `POST .../<destination-id>/disable`, which also cancels pending work while retaining history.

Test a destination without consuming runtime outbox work:

```sh
curl -X POST -H 'Authorization: Bearer <api-credential>' \
  http://localhost:8080/api/v1/projects/<project-uuid>/webhook-destinations/<destination-id>/test
```

Every request contains `Okoscope-Delivery`, `Okoscope-Event`, `Okoscope-Timestamp`, and `Okoscope-Signature`. Verify the signature as lowercase hex HMAC-SHA256 over `<Okoscope-Timestamp>.<exact-body-bytes>` with the destination secret. Reject stale timestamps and deduplicate by `Okoscope-Delivery`: delivery is at-least-once, so a worker crash after receiver acceptance can repeat the same delivery ID.

Production destinations require HTTPS. Okoscope disables redirects and rejects URL credentials, fragments, and targets resolving to loopback, link-local, private, multicast, unspecified, or carrier-grade NAT addresses. Restrict server egress with a Kubernetes NetworkPolicy or infrastructure firewall. HTTP/private targets require explicit development flags and MUST NOT be enabled in a shared cluster.

After configuring a test destination, enable the worker with `OKOSCOPE_NOTIFICATION_DELIVERY_ENABLED=true`. Tune polling, claim size, concurrency, leases, request timeout, attempts, backoff, and response limits using the `OKOSCOPE_NOTIFICATION_*` and `OKOSCOPE_WEBHOOK_*` variables documented by `okoscope-server --help`. Keep lease duration longer than request timeout.

Inspect delivery health through `/metrics`, the Project delivery APIs, and `ops/queries/notification-delivery.sql`. Retryable network/timeouts and HTTP 408/425/429/5xx responses use capped exponential backoff with jitter. Other 4xx and exhausted retries become terminal failures. Response excerpts are truncated and headers are not stored.

To recover from a worker outage, restore outbound connectivity and restart the server; expired leases are reclaimed automatically. To roll back, set delivery enabled to false and deploy the prior image. Pending outbox and delivery rows remain durable. Do not drop migration `0004` during a service rollback.

## Automatic release discovery and runtime diff

Migration `0019_automatic_release_discovery.sql` is additive. For an Application mapped to one Deployment, the agent derives the Release from the immutable image digests reported in Pod status. It sends revision evidence on the existing authenticated Application stream before buffered runtime events. The server creates or reuses the observed Release atomically; operators do not call the Release API or edit a release value during normal Kubernetes rollout.

The selector only identifies the workload:

```yaml
scope:
  workloads:
    - applicationCredentialFile: /var/run/secrets/okoscope/applications/payment-api
      namespace: production
      kind: Deployment
      name: payment-api
```

`scope.workloads[].release` remains accepted as a deprecated legacy fallback for older rollout procedures. When complete Pod digest evidence exists it takes precedence. Incomplete image status never blocks workload observation: the event is accepted without automatic Release attribution and the bounded reason is observable.

The authenticated manual Release API remains available during compatibility for non-observed and older agents. Manual rows are preserved with `source: manual` and are never merged into an observed Release by version text alone.

Deploy the migration and compatible server before agents advertise `kubernetes.release-discovery/v1`. New agents negotiate the capability before sending evidence; an older server must not receive the new typed messages. Evidence and readiness snapshots are idempotent and replay after reconnect. Episode closure requires an initialized continuous watch plus confirmed absence for `OKOSCOPE_RELEASE_EPISODE_STABILIZATION_SECONDS` (default 120, allowed 30–3600); watch gaps cannot close or promote an episode.

One immutable Release can have multiple deployment episodes. Returning to an older digest opens a new episode classified as `rollback_candidate`; simultaneous revisions remain active independently. `ready_pod_share` is the share of Ready Pods in one snapshot, not traffic allocation or declared canary/A/B intent.

List releases and compare a target with its automatically selected previous release:

```sh
curl -H 'Authorization: Bearer <api-credential>' \
  'http://localhost:8080/api/v1/projects/<project-uuid>/applications/<application-uuid>/releases?limit=50'

curl -H 'Authorization: Bearer <api-credential>' \
  'http://localhost:8080/api/v1/projects/<project-uuid>/applications/<application-uuid>/releases/<target-release-uuid>/runtime-diff?limit=50'
```

Pass `baseline_id=<release-uuid>` for an explicit comparison. Entries are `new`, `disappeared`, or `unchanged`; baseline and target counts are returned separately. Inspect attribution and summary state with `ops/queries/release-runtime-diff.sql`. Rollback can deploy the prior binaries while leaving migration `0005` in place; do not drop its nullable columns or tables while attributed data exists.

Without `baseline_id`, episode transition evidence selects the replaced Release, including rollback to an older immutable Release. Responses identify `explicit`, `transition`, `concurrent_transition_fallback`, `legacy_deployment_order`, or `none` as the selection source. Application rollback may restore prior agent/server images but must leave migrations 0005 and 0019, Releases, episodes, runtime data, Secrets, and PostgreSQL storage intact.

## Notification retention policies

Migration 22 introduces Organization settings inherited by Projects and a unified history window. Follow [the retention upgrade guide](notification-retention-settings.md) before upgrading an installation with cleanup enabled. Legacy retention environment values initialize existing policies once; use the settings API/UI for subsequent changes and OKOSCOPE_NOTIFICATION_RETENTION_PAUSED for an operational pause.
