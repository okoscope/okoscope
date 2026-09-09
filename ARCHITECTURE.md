# Architecture

Okoscope is a self-hosted runtime observability system for Linux workloads and
Kubernetes. Its design separates privileged node observation from storage,
querying, and presentation.

## Components

| Component | Responsibility |
| --- | --- |
| eBPF program | Observes an explicit set of kernel events on supported Linux hosts. |
| Node agent | Selects configured workloads, enriches observations with Kubernetes identity, batches events, and maintains a bidirectional gRPC session. |
| Protocol and event model | Define versioned transport messages and canonical event semantics shared by agent and server. |
| Server | Authenticates ingestion and users, persists tenant-scoped data in PostgreSQL, projects inventory and runtime groups, exposes health and HTTP APIs, and runs bounded maintenance work. |
| PostgreSQL | Stores tenant configuration, raw evidence, projections, retention summaries, and migration state. |
| Web UI | Uses the public HTTP API and is maintained in a separate repository. |

## Data flow

1. An operator explicitly configures workloads for observation.
2. The node-local eBPF program emits supported kernel observations.
3. The agent attributes an observation to cluster, namespace, workload, Pod,
   container, Project, and Application context where available.
4. The agent sends bounded batches through an authenticated gRPC session.
5. The server validates tenant scope and event shape, stores evidence, and
   updates query-oriented projections.
6. Users query tenant-scoped HTTP endpoints; the web UI renders those APIs.

## Trust boundaries

- The agent is privileged relative to observed workloads and must be deployed
  only on trusted nodes with the minimum required host access.
- Application credentials scope ingestion. User sessions and server-side policy
  scope read and administrative operations.
- PostgreSQL and internal server secrets are operator-managed trust anchors.
- Public HTTP and gRPC endpoints require transport security in production.
- Event payloads, labels, paths, endpoints, and Kubernetes metadata may be
  sensitive. Collection is opt-in and documented per capability.

## Compatibility and evolution

The authoritative HTTP contract is
[`openapi/okoscope-v1.yaml`](openapi/okoscope-v1.yaml). Protobuf definitions live
under `crates/protocol/proto`. Database changes are append-only numbered SQL
migrations. Deployments should roll out compatible server and web components
before enabling new agent event types.

The system favors bounded batches, explicit retention, idempotent migrations,
and observable failure states. Current platform constraints and operational
guidance are documented in [platform support](docs/platform-support.md) and the
[self-hosted deployment guide](docs/self-hosted-deployment.md).

Material architecture changes follow the public process in
[GOVERNANCE.md](GOVERNANCE.md).
