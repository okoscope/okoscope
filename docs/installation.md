# Install Okoscope on Kubernetes

Okoscope publishes two charts with the same semantic release version:

- `oci://ghcr.io/okoscope/charts/okoscope-agent` connects a cluster to an existing hosted or self-hosted server.
- `oci://ghcr.io/okoscope/charts/okoscope` installs server, Web, migrations, and optionally the local agent. It never installs PostgreSQL.

Production commands should always include `--version <OKOSCOPE_VERSION>`. This is a
placeholder, not a predefined shell variable: replace it with the exact published
semantic version shown by the authenticated Okoscope onboarding page, for example
`--version 0.1.0`. If onboarding reports `installation_metadata_unavailable`, the
Okoscope operator has not yet published/configured an installable agent release;
do not guess a version. Component images are pinned by the chart release. Never put
a database URL or Application credential in a Helm values file or `--set` argument.
See the [Helm values reference](helm-values.md) for all chart settings, defaults, and
required fields.

Publishing a new component image does not update an existing chart release.
Release operators must run `release-helm-charts` with a new semantic version and
verified server, agent, and Web image digests. The workflow rejects any remaining
empty digest before packaging. After publication, update the Cloud installation
metadata to recommend the new agent chart version; existing installations keep
their pinned version until explicitly upgraded.

## Okoscope Cloud

Use [Okoscope Cloud onboarding](https://okoscope.com/onboarding) to select or create
your Project and Application, then generate the Secret and agent installation
commands for your Kubernetes cluster. Cloud operates the server and database;
you install only the agent.

The Cloud agent endpoint is `https://grpc.okoscope.com:443`. Use the chart version
shown by onboarding and the system certificate trust store; no custom CA Secret
is required. In the agent values example below, set `server.endpoint` to this
Cloud endpoint.

## Self-hosted

If you operate your own Okoscope server, follow [Self-host Okoscope](#self-host-okoscope)
below first. To connect to an existing installation, open that installation's
onboarding page and use its public gRPC endpoint and chart version. The Cloud
endpoint must not be used for an Application created on your own server. Configure
a custom CA Secret only if your installation uses a private CA.

## Connect Kubernetes: shared agent steps

Create an Application in Okoscope, copy its one-time `oko_app_v1_...` credential,
then follow the link to the authenticated onboarding wizard. If the Application's
Worker nodes section has no observations, its **Connect agent** button also opens
the wizard, starting with project selection. The wizard is the
authoritative source for the agent release namespace, Secret name, Secret key, and
the exact safe `kubectl` command. Use those generated values verbatim. For example,
if onboarding selects `okoscope-system`, `okoscope-application-credentials`, and
`payment-api`, create the Secret without writing the credential to disk:

```bash
kubectl create namespace okoscope-system
printf 'Application credential: ' >&2
IFS= read -rs OKOSCOPE_APPLICATION_TOKEN
printf '\n' >&2
kubectl -n okoscope-system create secret generic okoscope-application-credentials \
  --from-literal=payment-api="$OKOSCOPE_APPLICATION_TOKEN"
unset OKOSCOPE_APPLICATION_TOKEN
```

The separate `printf` prompt and `read -rs` form works in both Bash and zsh (the
default interactive shell on current macOS). Do not replace it with Bash's
`read -p`: in zsh, `-p` reads from a coprocess instead of displaying a prompt.
PowerShell uses different variable and secure-input syntax, so run this block
from Bash/zsh (including WSL or Git Bash). The Secret must be installed in the
agent release namespace, which can differ from the observed workload namespace.
Its name and data key must match the values shown by onboarding and referenced by
`workloads[].credentialSecret.name` and `workloads[].credentialSecret.key`.

Create `agent-values.yaml` containing only non-secret configuration:

```yaml
server:
  endpoint: https://grpc.okoscope.example:443
identity:
  clusterName: production
workloads:
  - namespace: production
    kind: Deployment
    name: payment-api
    credentialSecret:
      name: okoscope-application-credentials
      key: payment-api
observation:
  resources:
    enabled: false
```

Resource utilization collection is disabled by default. After completing a
server migration and deploying a compatible Web version, enable it for a small
canary by setting `observation.resources.enabled: true`. The defaults sample
cgroup v2 every 15 seconds and send fixed one-minute aggregates. See the
[resource utilization operator guide](resource-utilization.md) for prerequisites,
cost controls, retention, API semantics, and rollback.

`identity.clusterName` is the readable name chosen in onboarding, displayed for
Application Worker nodes. Agents send it when connecting; reconnecting updates
the name without changing cluster identity, which remains the Kubernetes cluster
UID within the Organization. Use the same trimmed name (1–64 characters, without
control characters) for all agents in a cluster. Upgrade both server and agents
to versions supporting the cluster name in the handshake to replace historical
UUID display names automatically. Older agents that omit the name retain the
existing name; a newly discovered cluster from an older agent uses its UID.

For separate agent installations in different namespaces, use unique Helm
release names: the generated ClusterRole and ClusterRoleBinding names are
cluster-wide. Change both the release name after `--install` and `--namespace`
in the command below, create the credential Secret in that agent namespace,
and use the matching resource name and namespace in the verification commands.

Install and verify:

```bash
helm upgrade --install okoscope-agent \
  oci://ghcr.io/okoscope/charts/okoscope-agent \
  --version <OKOSCOPE_VERSION> \
  --namespace okoscope-system \
  -f agent-values.yaml
kubectl rollout status daemonset/okoscope-agent-okoscope-agent \
  --namespace okoscope-system --timeout=5m
```

For a private CA, create an additional Secret and configure `server.caSecret.name` and `server.caSecret.key`. That CA is used independently of the container's system root store. System trust is used only when `caSecret.name` is empty. Plaintext transport is an explicitly isolated development mode only: use an `http://` endpoint together with `server.developmentPlaintext=true`; never use it across untrusted networks.

Use `labels` instead of `name` for a bounded label selector. Do not set both. Multiple mappings may use different Secret names and keys. The chart grants read-only access to Pods, Deployments, ReplicaSets, and the `kube-system` Namespace, and requires Linux eBPF support described in [platform support](platform-support.md).

If the DaemonSet is not ready, inspect `kubectl logs -n okoscope-system daemonset/okoscope-agent-okoscope-agent`. Common causes are an unreachable TLS endpoint, an incorrect CA, unsupported kernel/BTF support, or a missing Secret key.

The agent runtime image includes Debian's `ca-certificates` package for system
TLS trust. Its build checks that the CA bundle is nonempty and can be parsed by
OpenSSL. If agent logs report `no native certs found`, the running image has no
usable system CA bundle: upgrade to a chart release that pins a corrected agent
image. A Pod can remain `Running` while its Cloud connection is failing, so also
check the agent logs and Application Worker nodes observations after rollout.

### Remove the Cloud agent from your cluster

To undo the installation, select the correct Kubernetes context and uninstall
each agent Helm release. Use your actual release name and agent namespace:

```bash
kubectl config current-context
helm uninstall okoscope-agent --namespace okoscope-system --wait
```

If agents are installed in several namespaces, find their releases with
`helm list --all-namespaces` and repeat cleanup for each release in its own
namespace. Removing one namespace does not remove the other installations.

Helm removes the agent DaemonSet, ConfigMap, ServiceAccount, ClusterRole and
ClusterRoleBinding, and its release history. This stops monitoring every
Application served by that release; it does not delete your application
Deployments. The credential Secret was created separately and remains: delete
it only if nothing else uses it, using the actual name from your installation
(`okoscope-application-credentials` in this guide, or the name from the wizard):

```bash
kubectl -n okoscope-system delete secret okoscope-application-credentials
```

If you created `okoscope-system` only for the agent and it contains no resources
you need, you can then remove it:

```bash
kubectl delete namespace okoscope-system
```

Do not delete a shared namespace, the workload namespace, or shared Secrets.
Remove any other Secrets you created solely for this installation, such as
image-pull or private-CA Secrets, only after confirming they are unused. Revoke
the corresponding agent credentials in the Cloud Application. Uninstalling the
agent removes its cluster resources; it does not delete observations already
sent to Cloud or restore unrelated changes made since installation.

## Self-host Okoscope

Prerequisites are Kubernetes, Helm 3, and an existing supported PostgreSQL database reachable from the target namespace. The database and its availability, TLS, security, capacity, backup, restore, and upgrade lifecycle remain the user's responsibility.

Create the database Secret safely:

```bash
kubectl create namespace okoscope-system
printf 'PostgreSQL connection URL: ' >&2
IFS= read -rs OKOSCOPE_DATABASE_URL
printf '\n' >&2
kubectl -n okoscope-system create secret generic okoscope-database \
  --from-literal=database-url="$OKOSCOPE_DATABASE_URL"
unset OKOSCOPE_DATABASE_URL
```

Install and verify:

```bash
helm upgrade --install okoscope \
  oci://ghcr.io/okoscope/charts/okoscope \
  --version <OKOSCOPE_VERSION> \
  --namespace okoscope-system \
  --set agentInstallation.publicGrpcEndpoint=grpc.example.com:443
kubectl rollout status deployment/okoscope-server \
  --namespace okoscope-system --timeout=5m
helm test okoscope --namespace okoscope-system
kubectl port-forward -n okoscope-system service/okoscope-web 8080:80
```

When agents must trust a private CA, set `agentInstallation.tlsMode=custom_ca`, `agentInstallation.caSecret.name=<SECRET>`, and `agentInstallation.caSecret.key=<KEY>`. The Secret must already exist in the namespace where the standalone agent will be installed; onboarding returns only its name and key, never certificate or key material. Leave the default `system` mode with an empty CA Secret name to use system roots.

Open `http://127.0.0.1:8080`. The pre-install/pre-upgrade migration Job must succeed before application rollout. It reads `database.existingSecret`/`database.urlKey`; there is deliberately no `database.url` value.
The Web pod proxies same-origin `/api` requests to the chart's internal Server Service, so this single Web port-forward supports both the UI and API without exposing the Server Service.
When Web ingress is enabled, the chart automatically trusts its exact browser
Origin, derived from `ingress.web.host` and whether `ingress.web.tlsSecret` is set.
For browser entry points not represented by that ingress (for example an external
reverse proxy or a separate local UI), list each exact `http://` or `https://`
origin under `server.corsOrigins`; do not include paths or wildcards.

Ordinary registration is disabled by default, including when Web ingress is enabled. For a public service where users create their own Organizations, first configure and test transactional email, an HTTPS `mail.publicWebUrl`, its SMTP credential Secret, and sender DNS as described in the [production guide](self-hosted-deployment.md#transactional-email). Then enable both `mail.enabled=true` and `server.registrationEnabled=true`. On an empty database, enabled public registration takes precedence over the private first-owner setup screen. Registration creates an unverified owner and no session; the user must explicitly confirm the emailed link and sign in. Organization creation sends no separate email.

For a private installation with registration disabled, retrieve the one-time setup authorization from its Kubernetes Secret, paste it into `/setup`, and create the first owner, Organization, and explicitly named Project:

```bash
kubectl get secret -n okoscope-system okoscope-setup \
  -o jsonpath='{.data.setup-token}' | base64 --decode
printf '\n'
```

Helm never prints the token. The Secret is preserved across upgrades, and setup permanently closes as soon as any owner exists. If the token is lost, use the existing `bootstrap-owner` operator command; setup never recovers or returns plaintext authorization. Application credentials are likewise shown only once. Connection readiness uses a 30-second compatible-agent heartbeat and becomes `stale` after five minutes; older agents remain usable but expose only authentication/event evidence.

An externally managed setup Secret may also contain an RFC 3339 expiry under
`setup-token-expires-at` (or `setupAuthorization.expiresAtKey`). Once expired, an ownerless
installation reports `setup_unavailable`; rotate the external token and expiry to recover.
Chart-generated tokens intentionally have no expiry and remain valid until the first owner claim.


See [production installation and operations](self-hosted-deployment.md) for ingress-nginx and Traefik TLS examples, external internal Secrets, upgrades, rollback, uninstall, private registries, notifications, and Kustomize transition.
