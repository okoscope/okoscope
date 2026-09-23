# DNS resolution frontend handoff

The canonical contract is `openapi/okoscope-v1.yaml`. Regenerate Okoscope Web with
`npm run api:generate`; do not create handwritten variants of the generated unions.

Supported event payloads are `NetworkDnsQuery`, `NetworkDnsResponse`, and optional `dns_context`
on `NetworkConnect`. DNS group summaries expose process, canonical name, query type, transport,
direction, and response code where applicable. Transaction IDs, resolver addresses, answer sets,
and CNAME chains are occurrence evidence and do not define group identity. Release diff and
first-seen notifications use the same bounded semantic summary.

Render names as inert text. Never create links, automatic navigation, fetches, reverse lookups, or
client-side resolution from a name. Keep IP/port visually primary for connections. Context must show
confidence, evidence age/expiry, and ambiguity when multiple names exist. Empty context is a normal
unavailable state: explain that cache, expiry, encrypted DNS, unmatched traffic, or disabled capture
may be responsible without claiming which occurred.

Accessible labels must distinguish DNS evidence from canonical destination identity. Preserve
keyboard navigation, tenant-safe error handling, correlated request IDs, cursor/filter URL state,
null release handling, and credential-safe session state. Tests must cover UDP/TCP, A/AAAA, CNAME,
NXDOMAIN/no-answer, multiple answers/names, TTL/age, ambiguity, large counts, and unavailable states.
Fixtures and UI must reject or ignore raw packet bytes, EDNS content, arbitrary headers/bodies,
URLs, source ports, secrets, and any unsupported payload fields.
