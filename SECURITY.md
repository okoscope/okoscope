# Security Policy

The Okoscope maintainers welcome responsible vulnerability reports.

## Supported versions

Security fixes are provided for the latest released minor version. Older
versions may require upgrading before receiving a fix. Pre-release builds and
source snapshots are supported on a best-effort basis.

| Version | Supported |
| --- | --- |
| Latest `0.2.x` release | Yes |
| `< 0.2` | No |

This table will be updated when the support policy changes.

## Reporting a vulnerability

Do not open a public issue. Use
[GitHub's private vulnerability reporting](https://github.com/okoscope/okoscope/security/advisories/new)
and include:

- the affected component and version or commit;
- prerequisites and reproducible steps;
- the expected and observed impact;
- a proof of concept, logs, or suggested remediation when available;
- whether the issue is known to have been exploited or publicly disclosed.

Remove credentials, personal data, and unrelated production data. If private
reporting is unavailable, contact a maintainer privately using the contact
method on their GitHub profile and ask for a secure reporting channel without
including vulnerability details in the first message.

## What to expect

Maintainers aim to acknowledge a report within five business days, provide an
initial assessment within ten business days, and keep the reporter informed at
meaningful milestones. These are targets, not service-level guarantees.

The project will coordinate validation, remediation, release timing, CVE
assignment when appropriate, and public disclosure with the reporter. Please
allow a reasonable remediation period before disclosure. The project will
credit reporters who request attribution and will honor requests for anonymity.

## Scope

Reports concerning the server, agent, eBPF program, protocol, container images,
Helm charts, build and release workflows, or the authoritative API contract are
in scope. General support requests, hardening suggestions without a concrete
security impact, and vulnerabilities in unsupported versions belong in the
normal issue tracker.
