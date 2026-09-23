# Contributing to Okoscope

Thank you for helping improve Okoscope. Contributions of code, documentation,
testing, design feedback, and production experience are welcome.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
For support or vulnerability reports, use the channels described in
[SUPPORT.md](SUPPORT.md) and [SECURITY.md](SECURITY.md).

## Before opening a change

1. Search existing issues and pull requests.
2. Open an issue before making a large, user-visible, architectural, or API
   change. Describe the problem, alternatives, compatibility impact, and a
   proposed approach.
3. Keep changes focused. Separate unrelated refactoring from behavior changes.
4. Never include credentials, production data, private cluster details, or
   generated build artifacts.

Small fixes and documentation improvements can go directly to a pull request.

## Development setup

Okoscope uses the Rust toolchain pinned in `rust-toolchain.toml`. Most userspace
development works on macOS or Linux; building and running the eBPF component
requires a supported Linux environment, nightly Rust, and `bpf-linker`.

```sh
make build
make test
make check
```

Useful focused commands include:

```sh
cargo test -p server
cargo check -p protocol
make deployment-test
```

See the [installation guide](docs/installation.md),
[platform support](docs/platform-support.md), and
[architecture overview](ARCHITECTURE.md) for additional context.

## Pull requests

A pull request should:

- explain the user or operator problem and the chosen solution;
- link the corresponding issue when one exists;
- include tests proportional to the change;
- update user, operator, API, and architecture documentation when behavior
  changes;
- preserve backward compatibility, or clearly document why a breaking change
  is necessary;
- pass formatting, linting, tests, and deployment checks used by CI;
- use clear commit messages and contain no merge commits unless needed to
  resolve a conflict.

Reviewers evaluate correctness, security, operability, compatibility,
documentation, and maintainability. Authors are expected to respond to review
feedback, but reviewers should explain requested changes and distinguish
blocking concerns from suggestions.

## API and protocol changes

The authoritative HTTP contract is `openapi/okoscope-v1.yaml`. Update it in the
same change as server behavior. Protocol changes must remain compatible with
supported agent/server version combinations and include migration or rollout
guidance where appropriate.

Database migration changes must update every pinned required-migration version
and include PostgreSQL-backed migration coverage. Never rewrite a migration that
may already have been released; add a new migration instead.

## Contribution roles

Anyone may contribute. Review and maintainer responsibilities are earned through
sustained, constructive participation and are governed by
[GOVERNANCE.md](GOVERNANCE.md). Employment by any particular organization is
not required and grants no special authority.

## Licensing

By submitting a contribution, you agree that it may be distributed under the
repository's [Apache License 2.0](LICENSE) and that you have the right to submit
it. Third-party code must have a compatible license and retain all required
notices.
