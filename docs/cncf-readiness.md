# CNCF readiness

Okoscope is not currently a CNCF project. This document tracks evidence and
remaining work for a future Sandbox application against the current
[CNCF Sandbox application](https://github.com/cncf/sandbox/blob/main/.github/ISSUE_TEMPLATE/application.yml)
and [project lifecycle process](https://github.com/cncf/toc/blob/main/process/README.md).

The checklist is an internal self-assessment, not CNCF approval.

## Sandbox application evidence

| Area | Status | Evidence or action |
| --- | --- | --- |
| Reusable cloud-native project | Ready to explain | [README](../README.md) and [architecture](../ARCHITECTURE.md) describe a self-hosted observability system rather than a reference architecture. |
| Public source repository | Ready | The source is public at <https://github.com/okoscope/okoscope>. |
| Project description and use cases | Ready | [README](../README.md), [architecture](../ARCHITECTURE.md), and capability documentation under `docs/`. |
| Website | Ready | <https://okoscope.com> is configured as the GitHub repository homepage. |
| Roadmap | Ready | [ROADMAP.md](../ROADMAP.md). |
| Contribution guide | Ready | [CONTRIBUTING.md](../CONTRIBUTING.md). |
| Code of Conduct | Ready | [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) adopts the CNCF Code of Conduct and defines confidential escalation. |
| Maintainers file | Needs affiliation confirmation | [MAINTAINERS.md](../MAINTAINERS.md) has the required name, GitHub ID, and organization columns. Confirm that every listed affiliation is current before applying. |
| Security policy | Ready | [SECURITY.md](../SECURITY.md) and GitHub private vulnerability reporting. |
| License | Ready for policy review | Core code uses [Apache-2.0](../LICENSE). Complete a third-party dependency and image license audit before applying. |
| Governance and vendor neutrality | Documented; needs community evidence | [GOVERNANCE.md](../GOVERNANCE.md) defines contribution-based authority, conflicts, recusal, maintainer lifecycle, and organizational balance. Current maintainer concentration remains a practical risk. |
| Public support and change channels | Ready | GitHub issue forms and [SUPPORT.md](../SUPPORT.md). |
| Adopters | Evidence not yet recorded | [ADOPTERS.md](../ADOPTERS.md) deliberately contains no unverified claims. Add organizations only with permission. |
| Release process | Documented | [RELEASES.md](../RELEASES.md). Demonstrate the process through repeatable public releases and release notes. |
| Project/product separation | Needs application statement | Explain whether Okoscope is related to a commercial product or service and how the public project remains independently usable and governed. |
| Standard or specification | Ready to answer | Okoscope currently defines implementation APIs and protocols, not an independent normative industry standard. Revalidate before applying. |
| Parent-project separation | Not applicable unless ownership changes | If the project moves under another project's organization, obtain public maintainer approval before applying separately. |
| Trademark and accounts | Commitment required on acceptance | The applicant must agree to the CNCF IP Policy and transfer required project trademarks and accounts to the Linux Foundation/CNCF if accepted. Do not claim transfer before it occurs. |

## Recommended readiness work

These items reduce review risk even when they are not strict Sandbox entry
requirements:

- recruit contributors and reviewers outside the founding maintainer's
  organization, then demonstrate the governance process through real role
  changes;
- record permissioned adopter evidence and concrete integration or evaluation
  experience;
- enable organization-wide two-factor authentication and appropriate protected
  branch/ruleset controls without breaking the release workflow;
- add automated dependency review, vulnerability scanning, license scanning,
  SBOMs, artifact signing, and provenance to the release pipeline;
- apply for the OpenSSF Best Practices badge and track unresolved criteria;
- publish compatibility, upgrade, rollback, and security release evidence for
  multiple releases;
- verify the project name and trademarks, and document every repository,
  registry, domain, social account, and other asset that would enter CNCF
  stewardship;
- seek feedback from the relevant CNCF TAG. A General Technical Review is
  optional for Sandbox but can provide useful evidence;
- review eligibility for CNCF Landscape and LFX Insights listings.

## Application procedure

1. Resolve every item marked `Needs` and refresh links immediately before
   submission.
2. Complete the CNCF Sandbox issue form with direct links to evidence rather
   than future promises.
3. Respond publicly to reviewer questions and address any postponed findings.
4. If accepted, complete the Project Contribution Agreement, IP and trademark
   steps, repository and account transfer, license scanning setup, and the
   CNCF onboarding checklist.

For later Incubation or Graduation, use the then-current TOC application
templates. Those levels require substantially stronger evidence for adoption,
governance practice, maintainer and organizational diversity, engineering
maturity, and security review than Sandbox.
