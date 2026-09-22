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

## Server layering

The server separates request handling from persistence:

| Layer | Location | Responsibility |
| --- | --- | --- |
| Transport | `*_api.rs`, `api.rs`, `navigation.rs` | Parse and authorize requests, map domain errors onto the HTTP error envelope, serialize responses. |
| Persistence | `repository/` | Own SQL statement text, row types, and tenant-scoping predicates. |

A shared entity queried from more than one endpoint belongs in a repository
rather than in a handler, so that its tenant-scoping predicate is written and
reviewed once. Repository methods are generic over `sqlx::PgExecutor`: a caller
passes a pool for a standalone read or a transaction handle to enlist the
statement in its own unit of work. Repositories never open or commit
transactions, and they return `sqlx::Error` because the status code for a
persistence failure depends on the endpoint, not on the query.

Persistence rows are distinct from response bodies. A repository returns a row
type; the endpoint projects it into the serializable shape named in the OpenAPI
contract, so that table layout and public JSON evolve independently.

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
