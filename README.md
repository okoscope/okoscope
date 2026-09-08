# Okoscope

Okoscope is a self-hosted, eBPF-powered runtime observability service for Linux and Kubernetes. It observes process execution and an explicit syscall allowlist for selected Deployments, attributes events to Kubernetes identities, sends them over a bidirectional gRPC session, stores them in PostgreSQL, and groups repeated behavior into Sentry-like runtime groups.

Okoscope is open-source software licensed under Apache-2.0. It is currently a
pre-1.0, independently governed project and is not a CNCF project. The project
is preparing the technical, community, security, and adoption foundations
needed for a future CNCF Sandbox application.

The repository is a Rust workspace containing the eBPF program, node agent, protocol, event model, and server. The web UI is developed separately.

```sh
make build
make test
make check
make build-ebpf # Linux with nightly Rust and bpf-linker
```

See [Outbound network observation](docs/outbound-network-observation.md) for the opt-in `network.connect` capability, privacy boundary, counters, and rollout order.

## Install

Choose one supported Kubernetes journey:

- [Connect Kubernetes to an existing Okoscope server](docs/installation.md#connect-kubernetes-to-okoscope) with the `okoscope-agent` OCI Helm chart.
- [Self-host Okoscope](docs/installation.md#self-host-okoscope) with the `okoscope` OCI Helm chart and an existing, user-owned PostgreSQL database.
- [Helm values reference](docs/helm-values.md) for both charts, including defaults, required settings, and Secret references.

Helm is the public installation interface. The manifests under `deploy/kubernetes` are retained for existing internal/Kustomize environments and are not recommended for new installations. See [platform support](docs/platform-support.md), [production installation and operations](docs/self-hosted-deployment.md), and [deployment internals](docs/deployment.md).

See [runtime event retention](docs/runtime-events-retention.md) for Organization/Project policies, lightweight daily snapshots, and historical coverage.

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
