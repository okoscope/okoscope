# Okoscope Roadmap

The roadmap communicates direction rather than a delivery guarantee. Priorities
may change based on user feedback, security findings, operational evidence, and
maintainer capacity.

## Current focus

- Make self-hosted installation and upgrades predictable through versioned OCI
  Helm charts and explicit compatibility metadata.
- Improve the reliability and resource cost of Linux and Kubernetes runtime
  observation, including process, network, DNS, file, lifecycle, and resource
  signals.
- Strengthen tenant isolation, credential handling, retention, and operational
  visibility across agents and the server.
- Keep the OpenAPI contract, protobuf protocol, migrations, UI integration, and
  documentation synchronized.
- Establish the community, security, release, governance, and adoption evidence
  expected of a sustainable open-source project and future CNCF Sandbox
  applicant.

## Next

- Publish reproducible release notes, compatibility guidance, checksums, and
  supply-chain metadata for supported artifacts.
- Expand automated installation, upgrade, migration, and failure-recovery tests.
- Turn existing bounded performance studies into repeatable release gates.
- Improve contributor onboarding and label approachable issues for new
  contributors.
- Gather permissioned, verifiable adopter evidence and document integrations
  with the broader cloud-native ecosystem.

## Later

- Broaden supported Linux and Kubernetes environments based on measured demand.
- Mature APIs and operational contracts toward stable compatibility guarantees.
- Diversify reviewers, maintainers, adopters, and organizational participation.
- Prepare a CNCF Sandbox application when the project can demonstrate a clear
  cloud-native niche, community readiness, and neutral stewardship.

## Proposing roadmap changes

Open a feature request or discussion in the issue tracker. Explain the user
problem, affected personas, alternatives, compatibility implications, and how
success can be measured. Material roadmap changes follow the decision process in
[GOVERNANCE.md](GOVERNANCE.md).
