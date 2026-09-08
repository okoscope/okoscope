# Production self-hosted deployment

Start with the [installation quick starts](installation.md). Helm is the supported public interface. Okoscope requires an existing PostgreSQL database and never creates, upgrades, backs up, restores, or deletes database infrastructure or storage.

## Production values

See the [complete Helm values reference](helm-values.md) for both charts, defaults, required fields, and validation limits.

Registration defaults to disabled. Keep `server.registrationEnabled: false` for a private installation and use `/setup` for its first owner. To offer public signup, set `server.registrationEnabled: true`; this is supported with Web ingress enabled. Each signup creates a new Organization and its owner. It does not grant global administration or join an existing Organization.

Use separate TLS hostnames for HTTP and gRPC. The first release gates examples for ingress-nginx and Traefik; other controllers require operator verification.

```yaml
database:
  existingSecret: production-database
  urlKey: connection-url
internalSecret:
  existingSecret: okoscope-internal-production
server:
  replicas: 2
  registrationEnabled: false
web:
  replicas: 2
notifications:
  enabled: true
ingress:
  web:
    enabled: true
    className: nginx
    host: okoscope.example.com
    tlsSecret: okoscope-web-tls
  grpc:
    enabled: true
    className: nginx
    host: grpc.okoscope.example.com
    tlsSecret: okoscope-grpc-tls
```

The chart supplies `nginx.ingress.kubernetes.io/backend-protocol: GRPC` for the nginx gRPC route. With `className: traefik`, it supplies the Traefik h2c service annotation. TLS terminates at the Ingress while the server uses cluster-internal plaintext. To have cert-manager create `Certificate` resources, set `certManager.enabled=true` and `certManager.clusterIssuer`; otherwise pre-create the TLS Secrets.

The Web container receives `OKOSCOPE_API_BASE_URL=/` and `OKOSCOPE_API_UPSTREAM=http://<release>-server:8080` from the chart, and proxies exact `/api` and `/api/*` requests to that internal Server Service while preserving their URI. Web ingress and `service/okoscope-web` port-forwarding therefore serve the UI and browser API together; the Server HTTP Service does not need separate public exposure.

The chart also trusts the exact browser Origin derived from `ingress.web.host`:
`https://<host>` when `ingress.web.tlsSecret` is configured, otherwise
`http://<host>`. No domain is hardcoded. If another reverse proxy or a local UI
address sends browser requests to the Server, add only those exact origins under
`server.corsOrigins`; values must contain the scheme and host, with an optional
port, but no path or wildcard. The chart safely serializes the derived and explicit
origins into `OKOSCOPE_CORS_ORIGINS`.

For externally managed internal keys, the referenced Secret must contain `admin-credential`, `webhook-encryption-key`, `identity-token-key`, and `mail-encryption-key`, or the alternative key names configured below `internalSecret`. The mail key is 32 random bytes encoded as 64 hexadecimal characters and protects queued verification/reset render data; back it up and never rotate it while encrypted outbox rows remain. Leaving `internalSecret.existingSecret` empty lets Helm generate keys once with `lookup`; the retained Secret and existing values are reused on upgrades. An upgrade from a chart that predates mail generates only the missing mail key. Offline GitOps rendering must use an externally managed Secret because `lookup` cannot recover live state.

Set `imagePullSecrets` for a private registry. Resource requests and limits live under `server.resources`, `web.resources`, and, when enabled, `okoscope-agent.resources`. Notifications are disabled by default and are enabled with `notifications.enabled=true`; the webhook encryption key must remain stable and separately recoverable.

The optional local agent uses the same values contract as the standalone chart below `okoscope-agent`. It still requires an existing Application credential Secret and at least one workload mapping.

## Transactional email

Transactional email is provider-neutral authenticated SMTP and is disabled by default. Private setup and `bootstrap-owner` remain mail-free. Public registration cannot be enabled until mail is usable; production validation requires an HTTPS browser origin, certificate-verified STARTTLS or implicit TLS, a sender address, an SMTP credential Secret, and the mail encryption key. Organization creation itself sends no email. Creating an Application queues a localized message for every currently verified owner of its Organization.

Create SMTP credentials without placing them in a values file or shell history:

```bash
printf 'SMTP username: ' >&2
IFS= read -r OKOSCOPE_SMTP_USERNAME
printf 'SMTP password: ' >&2
IFS= read -rs OKOSCOPE_SMTP_PASSWORD
printf '\n' >&2
kubectl -n okoscope-system create secret generic okoscope-smtp \
  --from-literal=username="$OKOSCOPE_SMTP_USERNAME" \
  --from-literal=password="$OKOSCOPE_SMTP_PASSWORD"
unset OKOSCOPE_SMTP_USERNAME OKOSCOPE_SMTP_PASSWORD
```

Then add non-secret values:

```yaml
server:
  registrationEnabled: false # enable only after test delivery succeeds
mail:
  enabled: true
  publicWebUrl: https://okoscope.example.com
  smtp:
    host: smtp.example.com
    port: 587
    tls: starttls
    existingSecret: okoscope-smtp
    usernameKey: username
    passwordKey: password
  sender:
    address: noreply@example.com
    name: Okoscope
  defaultLocale: en
  worker:
    concurrency: 4
    claimSize: 25
```

The chart does not create a network policy that could safely identify an SMTP hostname. Kubernetes normally permits egress; in a default-deny cluster, explicitly allow DNS plus TCP egress from Server Pods to the configured SMTP endpoint and port. Do not open plaintext ports in production. Multiple Server replicas share PostgreSQL claims and may run the worker concurrently.

All transactional messages use one reusable Console template implemented in
`crates/server/src/transactional_mail.rs`. Its email-safe structure is a dark
Okoscope header, monospaced `EVENT`/`STATUS` metadata, an optional scope row, a
bordered light content card, and a cyan safety note. Verification and password
reset messages add one prominent action button and repeat the full link in the
HTML and plain-text alternatives. Password-change and Application-created
messages are informational and deliberately contain no action. Keep layout CSS
inline and table-based, preserve both English and Russian copy, HTML-escape every
dynamic value, and do not add scripts, forms, remote images, fonts, or stylesheets.
SMTP and sender settings above affect transport headers only; they do not alter
the template branding.

Roll out with registration still disabled, render manifests locally, upgrade, and request a password-reset email for a dedicated existing test account. The public response is intentionally generic, so confirm enqueueing and SMTP acceptance with metrics rather than response text:

```bash
helm template okoscope deploy/helm/okoscope -f production-values.yaml >/tmp/okoscope-rendered.yaml
helm upgrade okoscope oci://ghcr.io/okoscope/charts/okoscope \
  --version <NEW_OKOSCOPE_VERSION> --namespace okoscope-system \
  -f production-values.yaml --wait --timeout 10m
kubectl -n okoscope-system port-forward service/okoscope-server 8080:8080
curl -fsS http://127.0.0.1:8080/metrics | grep '^okoscope_mail_'
```

`okoscope_mail_queue_depth` and `okoscope_mail_oldest_due_seconds` describe backlog; claims, attempts, successes, retries, terminal failures, and the last-success timestamp distinguish progress from failure. These metrics and structured logs deliberately omit recipient addresses, subjects, bodies, links, tokens, and provider error text. SMTP acceptance is not proof of inbox delivery.

### Timeweb Cloud example

Create the technical mailbox in Timeweb Cloud and use its full address for both the SMTP username and `mail.sender.address`. The current official settings are `smtp.timeweb.ru`, authenticated TLS on port `587` (`mail.smtp.tls: starttls`); Timeweb also documents SSL on `465`, represented by `implicit`. Okoscope production configuration does not use Timeweb's plaintext ports. See Timeweb's [official SMTP settings](https://timeweb.cloud/docs/cms/otpravka-pochty-cherez-smtp).

If the domain uses external name servers, copy the exact MX, SPF, and DKIM values shown for that domain in the Timeweb panel; do not invent or duplicate SPF records. With Timeweb name servers, verify the automatically managed records. Add a DMARC TXT policy after SPF/DKIM validate, starting with monitoring appropriate to your domain, and keep the visible From domain aligned with the authenticated mailbox domain. Allow DNS propagation before judging delivery. See Timeweb's [domain-mail DNS guide](https://timeweb.cloud/docs/mail/setting-up-domain-mail/dns-settings-for-timeweb-cloud) and [DNS record reference](https://timeweb.cloud/docs/domains/dns-records-management).

### Troubleshooting and rollback

- `okoscope_mail_enabled 0` means the worker is intentionally disabled. Recheck rendered non-secret values; never print Secret data.
- A Pod stuck before startup usually indicates invalid URL/TLS/bounds or a missing Secret/key. Use `kubectl describe pod` and redacted event reasons. Test TCP/TLS reachability from an approved diagnostic Pod without supplying credentials on its command line.
- Rising retries with an aging queue indicate connectivity, TLS, authentication, throttling, or transient SMTP rejection. Terminal failures or expired actions require a fresh verification/reset request; do not extract ciphertext or token rows.
- After SMTP acceptance, check SPF, DKIM, DMARC, sender alignment, provider quotas, recipient spam filtering, and the provider's redacted delivery diagnostics.
- To pause delivery, first disable public registration, then set `mail.enabled: false`; durable rows remain in PostgreSQL. Re-enable with the same mail encryption key to drain them.
- Before rolling back to a version that does not enforce verification, disable public registration and keep it disabled. Roll back application workloads without reversing the additive database migration. Restore verification-aware Server and Web versions before enabling registration again.

## Upgrades and migrations

Pin the same semantic version for both charts:

```bash
helm upgrade okoscope oci://ghcr.io/okoscope/charts/okoscope \
  --version <NEW_OKOSCOPE_VERSION> \
  --namespace okoscope-system \
  -f production-values.yaml \
  --wait --timeout 10m
```

For the existing `aliens` Helm release (`okoscope` in namespace `okoscope`), the repository Makefile provides:

```bash
make deploy-preview VERSION=<NEW_OKOSCOPE_VERSION>
make deploy VERSION=<NEW_OKOSCOPE_VERSION>
make deploy-status
```

`VERSION` is required and must identify a published chart. These commands upgrade an existing release; they do not install a new one or build/push local sources. They switch to `aliens` by default. Set `KUBE_NAMESPACE` and `HELM_RELEASE` for a different release in that context. `VALUES=production-values.yaml` optionally supplies overrides. Helm must support `--reset-then-reuse-values`: new chart defaults are merged with the previous release's explicit values and then the supplied overrides. Explicit image tags/digests in saved values therefore remain pinned; update those in `VALUES` when promoting new images. Preview uses a server-side dry run with Secret manifests hidden; migration hooks execute only on the real upgrade.

The old Makefile Kustomize targets (`deploy-render`, `deploy-diff`, and `migrate`) have been removed. `make deploy` no longer checks for the legacy `okoscope-secrets` Secret or applies legacy manifests. Migration hooks are part of the Helm upgrade. `make deployment-test` remains available for the legacy manifest policy tests, independently of Helm deployment.

The idempotent migration hook runs before install and upgrade with bounded retry and deadline. A failure stops rollout. Inspect it with `kubectl get jobs,pods -n okoscope-system -l app.kubernetes.io/component=migration` and its Pod logs, correct database connectivity/permissions, then repeat the same `helm upgrade`. Never edit migration rows or attempt to reverse a schema migration.

Use `helm rollback okoscope <REVISION> -n okoscope-system` only when the prior server version is forward-compatible with the applied database migration. Database backups and point-in-time recovery must be managed and tested outside Okoscope.

## Uninstall ownership

`helm uninstall okoscope -n okoscope-system` deletes chart-owned stateless resources. It does not delete the existing database Secret, external PostgreSQL, externally managed credentials, or externally managed TLS/CA Secrets. A chart-generated internal Secret is retained by policy and must be deliberately removed by the operator only after confirming it is no longer required.

## Existing Kustomize installations

Fresh Helm installs are supported in the first release. Automatic adoption of existing Kustomize resources is not. Keep the database and Secrets, back them up, render the new chart with `helm template`, and compare names/selectors before a planned clean migration. Do not install Helm over identically named live resources without first resolving ownership metadata.

The `deploy/kubernetes` Kustomize roots and bundled PostgreSQL manifests are internal/legacy during one compatibility window. They remain available to existing operators but are not a new-install contract. PostgreSQL manifests there must not be used as part of a new Okoscope installation.

## Release and cluster verification

Charts are published as `oci://ghcr.io/okoscope/charts/okoscope` and `oci://ghcr.io/okoscope/charts/okoscope-agent` with shared semantic versions. A release supplies verified immutable server, agent, and Web inputs and records the server's required migration. Publication must wait for chart policy tests and component availability.

Chart publication is an explicit operator action; creating a Git tag is not required
and does not trigger it. After CI has published verified server, agent, and Web images,
run the `release-helm-charts` GitHub Actions workflow with a semantic `version` (without
the `v` prefix) and the three `sha256:...` image digests. The workflow publishes both
OCI charts and stamps the same agent chart version into the server chart's onboarding
metadata. Only after publication succeeds should an operator deploy that server chart
version, or configure an existing server with matching values for
`OKOSCOPE_AGENT_CHART_REFERENCE`, `OKOSCOPE_AGENT_CHART_VERSION`,
`OKOSCOPE_AGENT_RECOMMENDED_VERSION`, `OKOSCOPE_AGENT_MINIMUM_VERSION`, and
`OKOSCOPE_PUBLIC_GRPC_ENDPOINT`. The endpoint must be externally reachable with TLS;
otherwise the UI cannot offer a usable agent installation command.

Repository release-candidate verification uses the `aliens` context:

```bash
kubectx aliens
helm template okoscope deploy/helm/okoscope -f production-values.yaml
kubectl rollout status deployment/okoscope-server -n okoscope-system --timeout=5m
```

Also verify `/readyz`, `/api/v1/build-info`, required migration readiness, Web/API routing, TLS gRPC connectivity, agent authentication, workload matching, and one bounded runtime event. These checks must never mutate or replace the user-owned PostgreSQL lifecycle.
