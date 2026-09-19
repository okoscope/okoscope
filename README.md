# Okoscope

Okoscope is an open-source, eBPF-powered runtime observability platform for
Linux workloads on Kubernetes. It turns kernel-level evidence from explicitly
selected Deployments into application-scoped runtime groups, inventory,
release comparisons, and operational health views.

It is licensed under Apache-2.0 and is currently a pre-1.0, independently
governed project, not a CNCF project. The project is preparing the technical,
community, security, and adoption foundations needed for a future CNCF Sandbox
application.

## What Okoscope observes

- Process execution, termination, and restart evidence.
- File activity from a bounded, documented syscall profile.
- Inbound and outbound network activity and DNS resolution.
- Optional cgroup v2 CPU, memory, and I/O utilization aggregates.
- Kubernetes and runtime inventory attributed to cluster, namespace, Deployment,
  Pod, and container identities.

Collection is opt-in per workload. The node agent enriches supported kernel
events with Kubernetes identity and sends bounded batches over an authenticated,
bidirectional gRPC session. The server stores tenant-scoped evidence and
projections in PostgreSQL and exposes them through a versioned HTTP API.

Okoscope also provides runtime grouping, first-seen and release comparisons,
configurable retention, notification delivery and recovery, Application agent
health, and role-based access across the platform, Organizations, and Projects.
Operators can assign human-readable names to stable runtime behaviors of every
supported event kind while Okoscope keeps the collected technical identity and
semantic evidence visible and unchanged.
Outbound destinations, DNS behavior, syscalls, and file activity are grouped by
canonical behavior across all Linux thread commands in an Application. Raw
occurrences and process-aware Runtime Groups retain the originating command for
investigation, while managed policies for these behaviors apply across threads.
Process lifecycle observation distinguishes kernel task creation
(`process.start`), executable replacement (`process.exec`), and leader
termination (`process.exit`). When the running kernel accepts all required
CO-RE programs, the agent advertises `task.lifecycle/v1` and emits bounded
60-second thread-activity aggregates by current Linux task name. Aggregate APIs
carry explicit baseline provenance, completeness, overflow, and observation-gap
evidence; thread names do not become Runtime Groups or policy identities. See
[`docs/process-thread-lifecycle.md`](docs/process-thread-lifecycle.md).
Lifecycle-capable evidence uses one PID-reuse-safe generation across creation,
repeated exec, thread activity, and leader exit. Older evidence remains readable
without an inferred generation or synthetic start.
Task lifecycle specifically uses the BTF tracepoints
`task_newtask` and `task_rename`; inability to load either hook withholds
that capability without disabling existing exec, network, DNS, file, resource,
or Kubernetes lifecycle observation. The production `union` canary matrix is
Ubuntu 22.04 Linux 5.15.0-138/139-generic and Ubuntu 24.04 Linux
6.8.0-137-generic; every exact kernel must pass verifier loading before the
capability is promoted.
Application heartbeats expose only lifecycle diagnostics that already have a
trusted Application route. Pre-route kernel loss, decode failure, and
attribution failure remain node-local metrics/readiness/log evidence and are
never guessed onto a tenant Application.
The Application domain view can additionally present logical DNS destinations:
A/AAAA questions and Kubernetes `cluster.local` search expansions corroborated
by an exact base question or multiple search suffixes in one resolver context
are grouped for display, while their exact resolver questions remain available
for policy evaluation, history, and audit.
Application health includes only diagnostic evidence assigned after workload
attribution to that Application's authenticated stream. Host activity,
unselected workloads, and other node-wide observer diagnostics are retained for
operator logs and are never presented as failures of the selected workload.
Application heartbeats require this scoped diagnostic snapshot; the server
rejects incompatible heartbeats without recording a health sample.
In the Application health view, every supported agent capability remains visible
in a single icon row: advertised capabilities are highlighted, unavailable ones
are dimmed, and localized names are available on hover or keyboard focus.

## Architecture

This repository is a Rust workspace containing the eBPF program, node agent,
protocol, event model, and server. The web UI is maintained in the separate
[`okoscope-web`](https://github.com/okoscope/okoscope-web) repository.

| Component | Responsibility |
| --- | --- |
| eBPF program | Captures the supported kernel observations on each selected Linux node. |
| Node agent | Selects workloads, adds Kubernetes context, batches events, and maintains the gRPC session. |
| Server | Authenticates ingestion and users, persists data, builds projections, and serves health and HTTP APIs. |
| PostgreSQL | Stores configuration, runtime evidence, projections, retention summaries, and migration state. |
| Web UI | Presents onboarding, runtime insights, operations, and access management through the public API. |

See [Architecture](ARCHITECTURE.md) for the data flow and trust boundaries. The
authoritative HTTP contract is [`openapi/okoscope-v1.yaml`](openapi/okoscope-v1.yaml).

## Install

Okoscope supports two Kubernetes deployment models:

- [Connect Kubernetes to Okoscope Cloud or an existing server](docs/installation.md#connect-kubernetes-shared-agent-steps)
  with the `okoscope-agent` OCI Helm chart.
- [Self-host Okoscope](docs/installation.md#self-host-okoscope) with the
  `okoscope` OCI Helm chart and an existing, operator-owned PostgreSQL database.

Helm is the public installation interface. Start with the
[installation guide](docs/installation.md), then use the
[Helm values reference](docs/helm-values.md) for defaults, required settings,
and Secret references. Production installations must pin a published semantic
chart version and must not put credentials or database URLs in values files or
`--set` arguments.

The current supported node profile is Kubernetes 1.32 or newer, containerd 2.x,
cgroup v2, Linux 6.1 LTS or newer with BTF, and x86_64. See
[Platform support](docs/platform-support.md) for the complete compatibility
contract and exclusions.

## Development

The default workspace targets build and test the userspace components. Building
the eBPF program additionally requires Linux, nightly Rust, and `bpf-linker`.

```sh
make build
make test
make check
make build-ebpf
```

`make check` runs formatting checks and strict Clippy for the supported workspace.
The manifests under `deploy/kubernetes` remain for existing Kustomize-based
environments but are not recommended for new installations.

## Operations and capabilities

- [Production self-hosting and operations](docs/self-hosted-deployment.md)
- [Authentication and access control](docs/access-control.md)
- [Runtime inventory](docs/runtime-inventory-operations.md)
- [Runtime event retention](docs/runtime-events-retention.md)
- [Resource utilization](docs/resource-utilization.md)
- [Process termination and restart evidence](docs/process-termination-operator-guide.md)
- [Outbound network observation](docs/outbound-network-observation.md)
- [Inbound network observation](docs/inbound-network-observation.md)
- [DNS resolution observation](docs/dns-resolution-observation.md)
- [Notification retention](docs/notification-retention-settings.md)
- [Helm deployment internals](docs/deployment.md)

## Project

- [Architecture](ARCHITECTURE.md)
- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [CNCF readiness](docs/cncf-readiness.md)
- [Contributing](CONTRIBUTING.md)
- [Governance and maintainers](GOVERNANCE.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Release process](RELEASES.md)
- [Adopters](ADOPTERS.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Apache License 2.0](LICENSE)
