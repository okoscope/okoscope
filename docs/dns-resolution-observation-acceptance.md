# DNS resolution observation acceptance evidence

Acceptance completed on 2026-08-18 in the `aliens` Kubernetes context on three
Linux 5.15 amd64 nodes.

## Immutable rollout

- Server: `ghcr.io/okoscope/okoscope-server:9f55b5485b62fbfe242cc41ec2f59af01e997e74`
- Agent: `ghcr.io/okoscope/okoscope-agent:719f1fa7eb2ed1e09dad0dc8018670e9e3bb5b90`
- Web: `ghcr.io/okoscope/okoscope-web:ebf251e5be915eec1be5398b55879a3a70d6b54e`
- Server and Web were rolled out before DNS was enabled.
- The DNS eBPF object passed the Linux verifier and attached ingress and egress
  probes to the Kubernetes cgroup v2 subtree on all three nodes. `NET_ADMIN` is
  required in addition to the existing bounded BPF capabilities.

## Controlled fixture

Observation selected only `Job/selected-dns-fixture`; a second Job remained
unselected. Both Jobs completed. The selected fixture exercised UDP and TCP,
A and AAAA, CNAME, NXDOMAIN, shared-IP ambiguity, cached connections, malformed
plaintext input, and opaque encrypted DNS.

PostgreSQL stored 62 `network.dns.query`, 62 `network.dns.response`, and 22
`network.connect` occurrences for the selected workload. Nine connection
occurrences carried qualified immutable DNS context. The unselected workload
stored zero events and searches found zero forbidden fixture names, packet,
source-port, header, body, authorization, or secret fields.

The fixture produced 14 DNS query groups and 14 DNS response groups. Release
`smoke-v2-20260817` contained the same DNS summaries (62 occurrences per DNS
direction); its diff against `smoke-v1-20260817` classified those 28 DNS groups
as new. First-seen outbox semantic payloads contained bounded names and excluded
transaction IDs and answer sets.

Agent delivery evidence reached `sent: 160`, `acknowledged: 160`, with zero
retry, capacity, rate-limit, kernel-loss, attribution-loss, oversize, malformed
compression, or ring-buffer loss. Background Kubernetes DNS traffic generated
bounded parser-decode counters before workload selection; these counters have
no domain, address, tenant, workload, transaction, PID, or event labels.

## Quality gates and rollback

Rust formatting, Linux Rust 1.91 Clippy with warnings denied, workspace unit and
PostgreSQL integration tests, nightly eBPF build, live Linux verifier, OpenAPI
inventory validation, deployment policy tests, frontend formatting/lint/type
checks, 43 component tests, build, Playwright/axe coverage, container image
builds, and Kubernetes manifest validation passed.

After evidence collection, the temporary namespace was deleted and the agent
returned to the base `okoscope-demo/payment-api` scope with
`observation.network.dns.enabled: false`. The final agent remained 3/3 Ready.
Stored evidence was retained.
