# DNS resolution observation

Okoscope can observe bounded plaintext DNS traffic for explicitly selected Kubernetes workloads.
The feature is disabled by default and never performs reverse DNS or decrypts DoH, DoT, DNSCrypt,
TLS, or HTTP traffic. Destination IP and port remain the canonical connection identity.

## Requirements and configuration

The agent requires Linux cgroup v2, BPF cgroup ingress/egress support, trusted socket cgroup
attribution, and permission to load and attach the packaged probes. When DNS observation is enabled
and these hooks cannot be attached, agent startup fails readiness instead of emitting unattributed
evidence.

Configure `observation.network.dns` in the agent configuration. `enabled` defaults to `false`.
UDP and TCP can be advertised independently. Platform bounds are: captured bytes 512–4096,
answers per response up to 16, names per address up to 8, TTL up to 86400 seconds, and non-zero
transaction, TCP stream, and event-rate capacities. Unknown fields are rejected.

```yaml
observation:
  network:
    connect: true
    dns:
      enabled: true
      udp: true
      tcp: true
      maxCapturedBytes: 1232
      maxPendingTransactions: 4096
      maxTcpStreams: 1024
      maxAnswersPerResponse: 16
      maxNamesPerAddress: 8
      maxTtlSeconds: 86400
      maxEventsPerSecond: 1000
```

Enable one controlled workload selector first. Query/response evidence includes only canonical DNS
names, A/AAAA addresses, bounded CNAME links, response code, effective TTL, transport/direction,
and existing trusted workload/process attribution. Raw packets, EDNS bodies, TXT/MX/SRV data,
source ephemeral ports, environment variables, unrestricted arguments, and secrets are excluded.

## Interpretation and limitations

`network.dns.query` and `network.dns.response` are observed evidence. A later connection may carry
an immutable `dns_context` only when the same workload recently observed an exact non-expired
address answer. Confidence is `observed_recently`; this does not prove causation. Shared/CDN IPs can
produce multiple names and are explicitly marked ambiguous. Cached, expired, unmatched, malformed,
or encrypted resolution leaves the connection IP-only. CNAME evidence describes the observed chain
but is not a browser link or navigation target.

Names are sensitive and high-cardinality. They are retained with existing runtime-event retention,
are tenant scoped, bounded in storage and APIs, and never used as metric labels. Monitor monotonic
DNS decode, compression, truncation, unsupported-record, correlation, reassembly, rate/capacity,
attribution, oversize, and kernel-loss counters before expanding selectors.

## Troubleshooting and rollback

- No DNS events: confirm the workload selector, plaintext port 53 traffic, UDP/TCP capability, and
  cgroup v2 attachment. Cached or encrypted DNS legitimately produces no decoded name.
- Queries without responses: inspect correlation misses, TCP reassembly, truncation, rate limits,
  and kernel ring loss. The agent emits no guessed response.
- Connections without context: confirm exact IP, workload scope, response match, and TTL window.
- Unexpected group growth: narrow selectors and inspect query names/response codes; names never
  change connection group identity.

Rollback by setting `observation.network.dns.enabled: false` and rolling the agent first. This
detaches DNS probes while process, syscall, and connection observation continue. Additive server and
Web versions may remain deployed; stored typed events remain readable. No Secret, data, or PVC
deletion is required.
