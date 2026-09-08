# Changelog

All notable changes to Okoscope are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Okoscope is pre-1.0, so minor releases may contain documented breaking changes.

## [Unreleased]

## [0.1.0] - 2026-09-08

### Added

- First public Okoscope release.
- Linux and Kubernetes runtime observation with eBPF-backed process, lifecycle,
  file, network, DNS, and resource signals.
- Kubernetes workload attribution, authenticated bidirectional agent transport,
  PostgreSQL persistence, runtime grouping, inventory, release comparison, and
  retention policies.
- Tenant-scoped HTTP API with an authoritative OpenAPI contract, notification
  delivery and recovery, onboarding, and user authorization flows.
- OCI Helm charts for a standalone agent and a self-hosted control plane using
  an operator-owned PostgreSQL database.
- Open-source governance, contribution, support, security, release,
  architecture, roadmap, adopter, and Code of Conduct documentation.
- CI validation for Rust formatting, strict Clippy, userspace tests, PostgreSQL
  migrations, Helm contracts, and Kubernetes manifests.

[Unreleased]: https://github.com/okoscope/okoscope/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/okoscope/okoscope/releases/tag/v0.1.0
