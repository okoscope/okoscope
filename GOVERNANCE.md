# Okoscope Governance

Okoscope is an open, vendor-neutral project. Technical authority is earned
through contribution and stewardship; employment, financial sponsorship, or
trademark ownership grants no special project authority.

The project currently uses maintainer-led governance appropriate to its size.
As the community grows, governance will evolve publicly without reducing the
rights of existing contributors.

## Roles

### Contributor

Anyone who participates in issues, code, documentation, testing, design,
support, or community work is a contributor.

### Reviewer

Reviewers are trusted contributors who have demonstrated sound judgment in a
defined area. They may review changes and help triage issues, but cannot merge
changes solely by virtue of the role.

### Maintainer

Maintainers have merge authority and are accountable for project health,
releases, security response, governance, and community standards. Maintainers
and their areas of responsibility are listed in
[MAINTAINERS.md](MAINTAINERS.md). Repository ownership rules must match that
list.

### Emeritus maintainer

An emeritus maintainer is a former maintainer recognized for past service. The
role carries no merge or voting authority. Emeritus maintainers may return to
active status through the normal maintainer selection process.

## Becoming a reviewer or maintainer

A contributor may be nominated by any maintainer, including self-nomination.
Selection is based on sustained participation, quality of work, constructive
reviews, understanding of the relevant subsystem, reliability, and adherence
to the Code of Conduct. There is no fixed contribution count or employment
requirement.

After a public nomination period of at least seven days, active maintainers
decide by lazy consensus. Objections must be reasoned and related to the role's
responsibilities. The decision and role scope are recorded in a pull request
updating `MAINTAINERS.md` and repository ownership rules.

## Inactivity, resignation, and removal

A reviewer or maintainer may resign at any time. A maintainer who has not
participated for six months should be contacted privately and may move to
emeritus status through the normal decision process. The project may act sooner
when access creates a security or continuity risk.

A maintainer may be removed for repeated failure to meet responsibilities,
unresolved conflicts of interest, a serious Code of Conduct violation, or risk
to the project. Non-emergency removal follows a documented proposal, a
reasonable opportunity to respond, and consensus of all non-conflicted active
maintainers. Emergency access suspension may happen immediately and must be
documented after sensitive details are removed.

Maintainers must update their organizational affiliation within 30 days of a
change.

## Decisions

Routine changes use public issue and pull-request discussion. Maintainers seek
lazy consensus: a proposal proceeds when there are no unresolved, reasoned
objections after adequate review. Maintainers may require additional review for
security-sensitive or high-risk areas.

Material changes—including governance, public APIs, data compatibility,
security boundaries, major architecture, project scope, or CNCF requests—must
begin with a public proposal. The proposal must state the problem, alternatives,
tradeoffs, migration impact, and decision. Allow at least seven days for
community review unless an urgent security or operational incident requires a
faster reversible decision.

If consensus cannot be reached, active maintainers vote. Each maintainer has one
vote; approval requires two-thirds of non-conflicted votes and more approvals
than objections. With only one active maintainer, unresolved material decisions
remain open for community feedback unless delay poses a documented security or
project-continuity risk.

No organization may cast more than half of the counted maintainer votes. When
maintainer composition cannot satisfy that rule, the decision remains open or a
neutral external advisor is invited and the exception is documented. This
protection becomes fully operative once maintainers represent multiple
organizations.

## Conflicts of interest

Participants must disclose relevant conflicts. A conflicted maintainer may
provide factual context but must not approve, block, or vote on the decision.
Commercial product priorities may be proposed, but are evaluated by the same
project criteria as any other proposal.

## Releases and security

Maintainers authorize releases according to [RELEASES.md](RELEASES.md).
Vulnerability handling follows [SECURITY.md](SECURITY.md). Security-sensitive
work may be private until coordinated disclosure, after which decisions and
changes should be made public to the extent safe.

## Governance changes

Changes to this document follow the material-change process above. Governance
history remains visible in Git. The project reviews governance at least yearly
and when community size or organizational concentration changes materially.
