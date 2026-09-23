# Application worker platform frontend handoff

Use `GET /api/v1/projects/{project_id}/applications/{application_id}/workers` to show the workers with accepted runtime-event evidence for an application. The collection is ordered by `last_observed_at` descending and accepts `cursor` plus a `limit` from 1 through 200. Treat `next_cursor` as opaque and send it back unchanged.

Each item is one agent-backed node. Applications can legitimately have several simultaneous `kernel_release` and `architecture` values, so do not collapse the response into one application-level kernel. `first_observed_at` and `last_observed_at` describe evidence for this application; `agent_last_seen_at` describes the agent heartbeat/session recency. The API intentionally does not claim that a worker is online.

When the collection is empty, show the empty-state explanation and a “Connect agent” action linking to `/onboarding`. The wizard starts with project selection. Keep this action out of loading, initial-error, and populated states, including applications with only inactive workers.

Both platform fields are nullable. Render null as an explicit unavailable state such as “Not reported”; it commonly occurs for database rows that predate migration 12 and remains until the agent reconnects. Render `node_name`, `cluster_name`, `agent_version`, `architecture`, and `kernel_release` only as inert text. Do not turn reported strings into links or infer distribution, support, vulnerability, or eBPF compatibility claims.

The fixture [`application-workers.json`](fixtures/application-workers.json) covers heterogeneous AMD64/ARM64 kernels, missing legacy metadata, and another page. Error handling uses the common authenticated API envelopes: invalid cursor or limit is `400`, missing credentials is `401`, and a foreign or path-mismatched application is tenant-safe `404`.
