# Release Process

Okoscope is pre-1.0 software. Releases use semantic versioning, but minor
versions may include documented breaking changes while the public contracts are
still stabilizing.

## Cadence and support

Releases are feature- and readiness-driven; there is currently no fixed
schedule. The latest `0.1.x` minor line receives security support as described in
[SECURITY.md](SECURITY.md). Long-term-support releases are not currently
offered.

## Versioning and branches

- `main` is the development branch.
- Stable releases use signed or otherwise verifiable `vMAJOR.MINOR.PATCH` tags.
- Release candidates may use `vMAJOR.MINOR.PATCH-rc.N`.
- Patch releases contain compatible fixes whenever practical.
- A maintained release branch may be created when fixes must diverge from
  `main`; otherwise releases are tagged from `main`.

## Release artifacts

A coordinated release may include server and agent container images, the web UI
image, OCI Helm charts, source archives, the OpenAPI contract, and release
notes. Published metadata must identify compatible component versions and
immutable image digests.

## Release checklist

1. Select the version and move relevant entries from the `Unreleased` section
   of [CHANGELOG.md](CHANGELOG.md) into a dated version section. Document
   user-visible changes, breaking changes, migrations, compatibility, and known
   limitations.
2. Confirm CI passes, including formatting, strict Clippy checks, userspace
   tests, PostgreSQL-backed tests, and deployment validation.
3. Validate fresh installation, upgrade, rollback constraints, agent/server/web
   compatibility, and database migration readiness.
4. Review third-party dependency and container findings; resolve or explicitly
   track release-blocking security issues.
5. Build artifacts from the release commit, publish immutable references, and
   verify their provenance, digests, and installation instructions.
6. Create the release tag and GitHub release notes, verify the changelog compare
   links, then monitor installation and runtime health for regressions.

Only maintainers may authorize a release. A release must not be published from
an unreviewed working tree or by replacing artifacts associated with an existing
version. If publication partially fails and an artifact cannot be safely
recreated, issue a new patch version.

## Security releases

Security releases may use a private preparation process and accelerated review.
Public notes should identify affected versions, impact, mitigation, fixed
versions, and acknowledgements without exposing users before a fix is available.
