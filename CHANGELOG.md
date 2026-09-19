# Changelog

All notable changes to Okoscope are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Okoscope is pre-1.0, so minor releases may contain documented breaking changes.

Tagged versions are `v0.1.0`, `v0.2.0`, `v0.2.2`, `v0.3.0`, and `v0.3.3`. The
remaining versions were released from `main` without a tag, so their comparison
links below use the release commit instead.

## [Unreleased]

## [0.3.3] - 2026-09-18

### Fixed

- Logical DNS presentation now combines a Kubernetes-expanded destination when
  multiple exact resolver questions in one Pod/container context corroborate
  the same base through different search suffixes, even if the base question
  itself was not retained.

## [0.3.2] - 2026-09-18

### Added

- Application runtime inventory now exposes additive logical DNS presentation
  groups that combine A/AAAA questions and corroborated Kubernetes search
  expansions while preserving every exact DNS identity, occurrence, policy
  association, and evidence-history route.

### Fixed

- Resource utilization sampling now tolerates cgroup directories disappearing
  during a live hierarchy scan and restarts its baseline after a delayed sample
  crosses a UTC aggregation boundary, preventing avoidable minute gaps.

## [0.3.1] - 2026-09-15

### Changed

- Application runtime inventory identity version 2 groups outbound destinations,
  DNS behavior, syscalls, and file activity across Linux thread commands. Raw
  occurrences and Runtime Groups retain the originating command, while managed
  policies for these behaviors apply to every thread in the Application.

### Upgrade notes

- Version 1 runtime evidence and user-authored runtime state are not migrated.
  Pause one selected Application, back up the database, perform the documented
  Application-scoped destructive reset, deploy compatible server and Web
  releases, and resume ingestion with a fresh version-2 inventory.

## [0.3.0] - 2026-09-14

### Added

- Application-scoped user labels can name stable runtime behaviors across all
  supported agent event kinds. The item-scoped API supports validation and
  optimistic concurrency; inventory, group, attention, search, and newly
  materialized notification views expose bounded labels without changing
  technical evidence, identity, policy evaluation, or occurrence accounting.

### Upgrade notes

- Database migration 30 is required. It adds durable, audited runtime behavior
  labels that survive raw-event and inventory projection cleanup and cascade
  only with their owning Application.

## [0.2.2] - 2026-09-14

### Changed

- Application agent health now reports only diagnostic losses assigned to the
  selected workload's authenticated stream. Node-wide and pre-attribution
  counters remain internal. Application heartbeats without a scoped diagnostic
  snapshot are now rejected without recording a health sample, and the HTTP API
  no longer exposes the obsolete diagnostic-availability compatibility flags.

### Upgrade notes

- Database migration 29 is required. It adds independently resettable,
  tenant- and Application-scoped diagnostic baselines and history buckets.
- Deploy the matching server, agent, and Web versions together; agents that omit
  Application-scoped heartbeat diagnostics are no longer compatible.

## [0.2.1] - 2026-09-09

### Added

- Application-scoped agent health history and an additive paginated API with
  advertised capabilities, stream freshness, event evidence, node-wide
  diagnostic deltas, reset markers, and bounded 1-hour, 6-hour, and 24-hour
  timelines.
- Application observation health now shows server-derived freshness, reporting
  node count, actionable no-data reasons, and retained worker data during
  readiness refresh failures.

### Upgrade notes

- Database migration 28 is required. It adds bounded Application-agent signal
  and node diagnostic buckets retained for at least 25 hours; existing runtime
  events and the workers API are unchanged.

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

[Unreleased]: https://github.com/okoscope/okoscope/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/okoscope/okoscope/compare/d7dbd5dd0f95556c1f324fb19038fdad3e1f4536...v0.3.3
[0.3.2]: https://github.com/okoscope/okoscope/compare/e54a99a27879cdf9b29f8197ef5f7a18daec9694...d7dbd5dd0f95556c1f324fb19038fdad3e1f4536
[0.3.1]: https://github.com/okoscope/okoscope/compare/v0.3.0...e54a99a27879cdf9b29f8197ef5f7a18daec9694
[0.3.0]: https://github.com/okoscope/okoscope/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/okoscope/okoscope/compare/56c94a2734db5d50040fc71482a1b5746b8e7ea3...v0.2.2
[0.2.1]: https://github.com/okoscope/okoscope/compare/v0.2.0...56c94a2734db5d50040fc71482a1b5746b8e7ea3
[0.2.0]: https://github.com/okoscope/okoscope/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/okoscope/okoscope/releases/tag/v0.1.0
