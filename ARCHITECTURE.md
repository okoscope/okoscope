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

The server is split into three layers. Each depends only on the one below it.

| Layer | Location | Responsibility |
| --- | --- | --- |
| Transport | axum handlers (`*_api.rs`, `api.rs`, `navigation.rs`, `notification/api.rs`, ...) and the agent gRPC session (`session.rs`) | Authenticate the caller, parse the request, call one service method, map its result or error onto a status, error code and message, record request metrics. |
| Service | `service/` | Carry the use case: authorization against the authenticated principal, input validation, the order of repository calls, and which of them share a transaction. Each service has its own error enum and knows nothing about HTTP or gRPC. |
| Persistence | `repository/` | Own SQL statement text, row types, and tenant-scoping predicates. |

Transport code never calls a repository, runs a query, resolves project
access, or opens a transaction; it asks a service. The few places that do
(the session extractor in `auth.rs`, the gauges in `metrics.rs`, a startup
check in `main.rs`) are listed with their reason in
`crates/server/tests/layers.rs`, which fails when a new one appears or an
existing one is no longer needed. The same test checks that services do not
use axum or tonic and that repositories do not open transactions.

Project-scoped use cases resolve the caller's access through
`service::project_access`, which reports a project the caller cannot see the
same way as one that does not exist. Service methods take the authenticated
principal first, then the scope the
request names, then the parsed inputs. The order of checks inside a use case
decides which error a request that is wrong in several ways gets, so it is
part of the use case's behaviour. Results live with the service; where a
response body is exactly that result, the type derives `Serialize` and the
transport sends it as it is.

A shared entity queried from more than one use case belongs in a repository,
so that its tenant-scoping predicate is written and reviewed once. Repository
methods are generic over `sqlx::PgExecutor`: a caller passes a pool for a
standalone read or a transaction handle to enlist the statement in its own
unit of work. Repositories never open or commit transactions, and they return
`sqlx::Error` because what a persistence failure means depends on the use
case, not on the query.

Persistence rows are distinct from response bodies. A repository returns a row
type; the service or endpoint projects it into the serializable shape named in
the OpenAPI contract, so that table layout and public JSON evolve
independently.

Background work (ingestion projections, retention and notification workers,
release discovery) runs outside request handling and uses repositories
directly.

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
