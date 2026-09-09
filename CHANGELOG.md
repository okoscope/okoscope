# Changelog

All notable changes to Okoscope are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Okoscope is pre-1.0, so minor releases may contain documented breaking changes.

## [Unreleased]

## [0.2.0] - 2026-09-09

### Added

- Invite-based access for Organizations and Projects, including new and existing
  users, expiring links, resend, revocation, and English/Russian transactional
  email templates.
- Personal platform `super_admin` authority with global user and tenant
  administration that does not require tenant membership or impersonation.
- Organization `owner`, `admin`, and `member` roles; explicit Project `admin`
  and `member` roles; inherited Project access for Organization owners and
  administrators.
- Platform and tenant access-management interfaces, Organization selection,
  privilege confirmation for sensitive operations, and access audit history.
- Audited first-super-administrator setup and operator recovery flows.

### Changed

- Fresh setup now creates only a verified personal super-administrator; it no
  longer creates an Organization, Project, or tenant owner membership.
- Public signup is disabled by default. When explicitly enabled, it requires
  multi-Organization mode and creates a verified Organization owner without
  granting platform authority.
- `server.publicSignupEnabled` replaces the deprecated
  `server.registrationEnabled` Helm value for one compatibility window.
- Project and descendant-resource authorization now uses effective platform,
  Organization, and Project access consistently.

### Security

- Invitation links carry one-time secrets in URL fragments; the server retains
  digests while queued mail payloads remain encrypted and are erased after
  delivery.
- Concurrent checks protect the final usable super-administrator and final
  usable Organization owner, and access changes invalidate affected sessions.
- The shared operator credential is excluded from ordinary product APIs and is
  limited to setup compatibility and audited recovery.

### Upgrade notes

- Database migration 27 is required. It preserves existing Organization and
  Project visibility while adding platform roles, Project memberships,
  invitations, access audit records, and membership-independent sessions.
- Installations that keep public signup enabled must use
  `server.organizationMode=multiple` and working transactional mail.

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

[Unreleased]: https://github.com/okoscope/okoscope/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/okoscope/okoscope/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/okoscope/okoscope/releases/tag/v0.1.0
