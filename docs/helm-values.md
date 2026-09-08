# Helm values reference

Both charts accept a YAML overrides file with `-f values.yaml`. Keep credentials in existing Kubernetes Secrets in the release namespace; values contain only Secret names and keys. Start with the [installation guide](installation.md) and [production deployment guide](self-hosted-deployment.md).

Inspect defaults for the exact published version you install:

```bash
helm show values oci://ghcr.io/okoscope/charts/okoscope --version <OKOSCOPE_VERSION>
helm show values oci://ghcr.io/okoscope/charts/okoscope-agent --version <OKOSCOPE_VERSION>
```

The tables describe the checked-in [server chart values](../deploy/helm/okoscope/values.yaml) and [agent chart values](../deploy/helm/okoscope-agent/values.yaml). Published releases replace image/version metadata. The source image tag `0000000000000000000000000000000000000000` is a placeholder, not a runnable release. Use a published, pinned chart version or explicitly supply verified image references when rendering local sources.

## Shared image settings

These fields live below `server.image` and `web.image` in `okoscope`, and below `image` in `okoscope-agent`.

| Suffix | Default | Meaning |
| --- | --- | --- |
| `repository` | `ghcr.io/okoscope/okoscope-server`, `ghcr.io/okoscope/okoscope-web`, or `ghcr.io/okoscope/okoscope-agent` | Component image repository. |
| `tag` | Release-pinned; source placeholder above | A 40-character lowercase Git SHA or semantic version; mutable tags such as `latest` are rejected. |
| `digest` | `""` | Optional `sha256:` plus 64 lowercase hex characters. Overrides the tag for the rendered image; the tag must still satisfy schema validation. |
| `pullPolicy` | `IfNotPresent` | `IfNotPresent`, `Always`, or `Never`. |

Each chart also accepts `imagePullSecrets: []`, a list such as `[{name: registry-credentials}]`. Configure it separately for an enabled agent subchart; parent image and resource settings are not inherited by the agent.

## `okoscope`: Server and Web

### Workloads and access

| Value | Default | Meaning / constraints |
| --- | --- | --- |
| `fullnameOverride` | Unset | Override the release-based resource name prefix. |
| `server.replicas` | `1` | Server replicas, minimum `1`. |
| `web.replicas` | `1` | Web replicas, minimum `1`. |
| `server.resources.requests` | `{cpu: 100m, memory: 128Mi}` | Server Pod resource requests. |
| `server.resources.limits` | `{cpu: "1", memory: 512Mi}` | Server Pod resource limits. |
| `web.resources.requests` | `{cpu: 25m, memory: 32Mi}` | Web Pod resource requests. |
| `web.resources.limits` | `{cpu: 250m, memory: 128Mi}` | Web Pod resource limits. |
| `server.registrationEnabled` | `false` | Enable public signup; each signup creates an Organization and owner. Private installations use `/setup` for the first owner. |
| `server.sessionLifetimeSeconds` | `43200` | Session lifetime in seconds; minimum `300`. |
| `server.corsOrigins` | `[]` | Additional exact browser origins for external proxies or local access, for example `https://admin.example.com` or `http://127.0.0.1:3000`. Paths, wildcards, query strings, fragments, and commas are rejected. The Web ingress origin is added automatically. |
| `podDisruptionBudget.enabled` | `true` | Create separate Server and Web disruption budgets. |
| `podDisruptionBudget.minAvailable` | `1` | Minimum available Pods for each budget, minimum `0`. With one replica, `1` prevents voluntary eviction of that Pod. |
| `okoscope-agent.enabled` | `false` | Install the optional local agent dependency. Put all its settings below `okoscope-agent`; see the agent reference below. |

### Database and Secrets

| Value | Default | Meaning |
| --- | --- | --- |
| `database.existingSecret` | `okoscope-database` | Required existing Secret containing the external PostgreSQL connection URL. The chart does not provision PostgreSQL. |
| `database.urlKey` | `database-url` | Key containing the connection URL. |
| `internalSecret.existingSecret` | `""` | Existing internal-key Secret. Empty generates a retained Secret and reuses it through Helm `lookup` on upgrades. Supply an external Secret for offline GitOps rendering. |
| `internalSecret.adminCredentialKey` | `admin-credential` | Administrative credential key. |
| `internalSecret.webhookEncryptionKey` | `webhook-encryption-key` | Stable webhook encryption key. |
| `internalSecret.identityTokenKey` | `identity-token-key` | Identity token key. |
| `internalSecret.mailEncryptionKey` | `mail-encryption-key` | Dedicated 32-byte, 64-hex-character key protecting secret-bearing mail outbox data. Generated and retained when `internalSecret.existingSecret` is empty; required in an external internal Secret. |
| `setupAuthorization.existingSecret` | `""` | Existing first-owner setup Secret. Empty generates and retains a setup-token Secret, reused through `lookup`. Use an external Secret for offline GitOps rendering. |
| `setupAuthorization.tokenKey` | `setup-token` | Setup authorization token key. |
| `setupAuthorization.expiresAtKey` | `setup-token-expires-at` | Optional expiration key read only from an externally managed setup Secret. See the setup procedure in the installation guide. |

### Ingress and certificates

The following settings apply independently below **both** `ingress.web` and `ingress.grpc`.

| Suffix | Default | Meaning / constraints |
| --- | --- | --- |
| `enabled` | `false` | Create the route. Requires a nonempty `host`. The gRPC route also requires `tlsSecret`. |
| `className` | `""` | Empty for the cluster default, or `nginx` / `traefik`. |
| `host` | `""` | Public hostname; use separate Web/API and gRPC hosts. |
| `annotations` | `{}` | Additional Ingress annotations with string values. The chart supplies controller-specific gRPC configuration. |
| `tlsSecret` | `""` | TLS Secret name, pre-created unless cert-manager is enabled. For Web ingress, empty renders HTTP and nonempty renders HTTPS; gRPC ingress requires TLS. |

| Value | Default | Meaning |
| --- | --- | --- |
| `certManager.enabled` | `false` | Create Certificate resources for enabled routes; requires cert-manager installed. |
| `certManager.clusterIssuer` | `""` | Required existing ClusterIssuer name when certificate management is enabled. |

TLS terminates at ingress; chart-managed server traffic inside the cluster uses plaintext. Web proxies browser API requests to the internal Server Service. The chart automatically adds the exact Web ingress origin to `OKOSCOPE_CORS_ORIGINS`, using `https://` when `ingress.web.tlsSecret` is set and `http://` otherwise. It appends `server.corsOrigins` as a comma-separated, YAML-quoted value and removes exact duplicates.

### Agent installation wizard

These values describe what the Server advertises to remote agents; they do not configure or install the local agent dependency.

| Value | Default | Meaning / constraints |
| --- | --- | --- |
| `agentInstallation.publicGrpcEndpoint` | `""` | Public TLS gRPC endpoint reachable from agent clusters, e.g. `https://grpc.okoscope.example.com:443`. Empty omits all agent-installation metadata from the Server environment. |
| `agentInstallation.chartReference` | `oci://ghcr.io/okoscope/charts/okoscope-agent` | Agent OCI chart reference. |
| `agentInstallation.chartVersion` | `0.1.0` in source | Chart version offered by the installation wizard. |
| `agentInstallation.recommendedAgentVersion` | `0.1.0` in source | Recommended agent version. |
| `agentInstallation.minimumAgentVersion` | `0.1.0` in source | Minimum supported agent version. |
| `agentInstallation.tlsMode` | `system` | `system` for system certificate trust, or `custom_ca` for a private CA. |
| `agentInstallation.caSecret.name` | `""` | Required for `custom_ca`, must be empty for `system`. Names a CA Secret to create in the agent namespace; the server chart does not create it. |
| `agentInstallation.caSecret.key` | `ca.crt` | CA certificate key advertised to agents. |

### Migrations and notifications

| Value | Default | Meaning / constraints |
| --- | --- | --- |
| `migration.backoffLimit` | `2` | Migration Job retry limit, `0–6`. |
| `migration.activeDeadlineSeconds` | `300` | Migration Job deadline in seconds, `30–3600`. Failed migration blocks installation/upgrade. |
| `notifications.enabled` | `false` | Enable the notification delivery worker. |
| `notifications.pollMilliseconds` | `1000` | Worker polling interval in milliseconds, minimum `100`. |
| `notifications.claimSize` | `50` | Maximum deliveries claimed per poll, `1–1000`. |
| `notifications.concurrency` | `8` | Delivery concurrency, `1–128`. |
| `notifications.leaseSeconds` | `30` | Delivery lease in seconds, minimum `1`. |
| `notifications.drainSeconds` | `15` | Shutdown drain interval in seconds, minimum `1`. |

### Transactional email

Mail is disabled by default. SMTP username/password values are intentionally not accepted anywhere in the schema: create an existing Kubernetes Secret and configure only its name and key names. Organization creation is mail-free; enabled mail supports account security workflows and Application-created messages to verified owners.

| Value | Default | Meaning / constraints |
| --- | --- | --- |
| `mail.enabled` | `false` | Enable transactional enqueueing and the PostgreSQL-backed SMTP worker. Required by public registration. |
| `mail.publicWebUrl` | `""` | Browser origin used in action links. Required when mail is enabled; HTTPS is mandatory unless development plaintext is explicit. No path, query, fragment, or credentials. |
| `mail.developmentPlaintext` | `false` | Permit local HTTP action links and plaintext SMTP. Unsuitable for shared or Internet-accessible installations. |
| `mail.smtp.host` | `""` | Provider-neutral SMTP hostname, required when enabled. |
| `mail.smtp.port` | `587` | SMTP TCP port, `1–65535`. |
| `mail.smtp.tls` | `starttls` | `starttls`, `implicit`, or development-only `plaintext`. Production TLS verifies certificates. |
| `mail.smtp.existingSecret` | `""` | Required existing Secret holding SMTP authentication credentials. |
| `mail.smtp.usernameKey` | `username` | SMTP username key in the credential Secret. |
| `mail.smtp.passwordKey` | `password` | SMTP password key in the credential Secret. |
| `mail.sender.address` | `""` | Required RFC-style sender mailbox. Align its domain with the authenticated sender and DNS policy. |
| `mail.sender.name` | `Okoscope` | Display name, `1–120` characters; newlines are rejected. |
| `mail.defaultLocale` | `en` | Default template locale: `en` or `ru`. User-targeted mail uses the stored user locale. |
| `mail.worker.pollMilliseconds` | `1000` | Queue polling interval, `100–60000`. |
| `mail.worker.claimSize` | `25` | Rows claimed per poll, `1–100`. |
| `mail.worker.concurrency` | `4` | Per-replica send concurrency, `1–32`. |
| `mail.worker.leaseSeconds` | `60` | Claim lease, `10–600` seconds. |
| `mail.worker.timeoutSeconds` | `15` | SMTP operation timeout, `1–120` seconds. |
| `mail.worker.maxAttempts` | `8` | Terminal attempt bound, `1–20`. |
| `mail.worker.retentionDays` | `30` | Non-secret terminal metadata retention, `1–365` days. Secret-bearing ciphertext is erased on success or terminal expiry. |

## `okoscope-agent`: node DaemonSet

Standalone installation requires `server.endpoint`, `identity.clusterName`, and at least one workload mapping. When installed as a dependency, prefix every value below with `okoscope-agent.`.

### Connection and workload selection

| Value | Default | Meaning / constraints |
| --- | --- | --- |
| `enabled` | `true` | Dependency condition when nested in the parent chart. Setting this to `false` in a standalone installation does not suppress its templates. |
| `nameOverride` | `""` | Override the chart-name portion of resource names. |
| `fullnameOverride` | `""` | Override the complete resource name, normally `<release>-<chart-name>`. |
| `server.endpoint` | `""` | Required gRPC URL; must start with `https://` unless development plaintext is enabled. |
| `server.developmentPlaintext` | `false` | Allow plaintext transport for isolated development only. |
| `server.caSecret.name` | `""` | Existing CA Secret in the agent release namespace. Empty uses system certificate trust. |
| `server.caSecret.key` | `ca.crt` | CA certificate key mounted read-only into the agent. |
| `identity.clusterName` | `""` | Required cluster identity. Node identity comes from the Kubernetes downward API. |
| `workloads` | `[]` | Required list of `1–32` mappings described below. |
| `workloads[].namespace` | Required | Namespace of the observed Deployment; may differ from the agent namespace. |
| `workloads[].kind` | Required | Only `Deployment` is supported. |
| `workloads[].name` | Unset | Deployment name; provide exactly one of `name` or `labels`. |
| `workloads[].labels` | Unset | Label selector with `1–16` nonempty string values, alternative to `name`. |
| `workloads[].credentialSecret.name` | Required | Existing Application credential Secret in the agent release namespace. |
| `workloads[].credentialSecret.key` | Required | Secret key containing that Application credential; projected into a read-only file. |

```yaml
server:
  endpoint: https://grpc.okoscope.example.com:443
identity:
  clusterName: production
workloads:
  - namespace: applications
    kind: Deployment
    name: payments
    credentialSecret:
      name: payments-application
      key: credential
```

For the optional local agent, nest the same example under `okoscope-agent:` and add `enabled: true` inside that block. Secret contents never belong in this file.

### Observation and safety

| Value | Default | Meaning / constraints |
| --- | --- | --- |
| `observation.processExec` | `true` | Observe process execution. |
| `observation.processExit` | `true` | Observe process termination. |
| `observation.syscalls` | `[]` | Explicit syscall-name allowlist; empty disables additional syscall observation. |
| `observation.files.enabled` | `false` | Enable file activity observation; requires nonempty operations and include paths. |
| `observation.files.operations` | `[create, modify, delete, rename]` | File operations to observe. |
| `observation.files.includePaths` | `[]` | Absolute normalized path prefixes to include. |
| `observation.files.excludePaths` | `[]` | Absolute normalized path prefixes to exclude; exclusions take precedence. |
| `observation.network.connect` | `true` | Observe outbound connections. |
| `observation.network.listen` | `true` | Observe listening sockets. |
| `observation.network.accept` | `true` | Observe accepted inbound connections. |
| `observation.network.maxAcceptedEventsPerSecond` | `25` | Accepted-event rate cap, `1–100000` when accept observation is enabled. |
| `observation.network.dns.enabled` | `false` | Enable DNS observation. |
| `observation.network.dns.udp` | `true` | Observe UDP DNS when DNS is enabled. |
| `observation.network.dns.tcp` | `true` | Observe TCP DNS when DNS is enabled; at least one transport must remain enabled. |
| `observation.resources.enabled` | `false` | Enable cgroup v2 CPU, memory, pressure, I/O, and PID sampling. |
| `observation.resources.sampleIntervalSeconds` | `15` | Sampling interval, `10–60` seconds. |
| `observation.resources.aggregationIntervalSeconds` | `60` | Fixed UTC aggregation interval; only `60` is accepted. |
| `observation.resources.maxCgroupStates` | `4096` | Maximum tracked container cgroup lifetimes, `1–65536`. |
| `observation.resources.maxOpenAggregates` | `1024` | Maximum open minute aggregates, `1–16384`. |
| `observation.resources.queueCapacity` | `256` | Per-Application resource delivery queue, `1–4096`. |
| `observation.resources.batchSize` | `64` | Resource aggregates per batch, `1–256` and no greater than the resource queue. |
| `safety.queueCapacity` | `4096` | Event queue capacity, `1–4096`. |
| `safety.batchSize` | `256` | Batch size, at least `1` and no greater than queue capacity. |
| `safety.maxEventsPerSecond` | `1000` | Agent event rate limit. |
| `safety.maxApplicationStreams` | `32` | Maximum distinct Application streams, `1–32`; must accommodate selected Applications. |

`observation` and `safety` are passed into the agent configuration. Helm accepts these objects, but the agent also validates their fields at startup. See [resource utilization](resource-utilization.md), [file activity](file-activity-syscall-profile.md), [outbound networking](outbound-network-observation.md), [inbound networking](inbound-network-observation.md), and [DNS observation](dns-resolution-observation.md) for capability limits.

### Pod resources and scheduling

| Value | Default | Meaning |
| --- | --- | --- |
| `resources.requests` | `{cpu: 100m, memory: 96Mi}` | Requests per agent Pod. |
| `resources.limits` | `{cpu: 500m, memory: 512Mi}` | Limits per agent Pod. |
| `nodeSelector` | `{}` | Node label constraints. Select nodes supported by the [platform requirements](platform-support.md). |
| `tolerations` | `[]` | Kubernetes taint tolerations. |
| `affinity` | `{}` | Kubernetes scheduling affinity. |
| `podAnnotations` | `{}` | Additional agent Pod annotations. |

The agent runs one Pod on each eligible node. It uses host PID access, host mounts, and eBPF-related capabilities; these are defined by the chart templates and are not exposed as values.
