# Frontend outbound network observation handoff

Regenerate the Okoscope Web client from `openapi/okoscope-v1.yaml`. Existing runtime group, occurrence, lifecycle, release-diff, and notification APIs now include typed unions for `network.connect`; no dedicated topology endpoint is introduced.

## Rendering contract

For a runtime group whose `event_kind` is `network.connect`, render `semantic_summary` as:

- process command;
- address family (`IPv4` or `IPv6`);
- canonical destination IP as inert text;
- destination port.

For each occurrence, narrow `payload.type === "NetworkConnect"` and additionally render outcome:

- `succeeded`: syscall returned zero;
- `in_progress`: connection attempt continued asynchronously and is not confirmed established;
- `failed`: show the numeric bounded errno without inventing a receiver-provided message.

Use the same rendering in group detail, occurrence history, release diff, and first-seen notification context. Filtering continues through `event_kind=network.connect`; pagination, stale data, correlated request IDs, authorization handling, lifecycle confirmations, and release navigation retain existing behavior.

## Safety requirements

Do not reverse-resolve destinations or turn destination-derived strings into clickable links. Do not display or persist packet data, HTTP/TLS fields, DNS names, source ports, socket buffers, credentials, or raw unknown payload fields. Exhaustive union narrowing must fall back to the existing safe unknown-event presentation for future event variants.

Credentials and API responses remain memory-only. Network destinations must not become analytics, error, or metric labels.

## Required verification

- Compile-time fixtures for IPv4 and IPv6 semantic summaries and `succeeded`, `in_progress`, and `failed` occurrence payloads.
- Component coverage for all outcomes, errno, large occurrence counts, absent release attribution, safe unknown variants, and forbidden-field absence.
- Release-diff coverage for `new`, `disappeared`, and `unchanged` network groups.
- Playwright and axe coverage for filtering to `network.connect`, opening a group and occurrence history, keyboard navigation, and request-ID errors.
- A production smoke against the controlled fixture after compatible server, Web, and agent images are deployed.
