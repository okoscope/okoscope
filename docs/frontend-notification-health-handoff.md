# Frontend handoff: Project notification health

Use the generated OpenAPI operation `getNotificationHealth` for the Project notification status panel. Poll `GET /api/v1/projects/{project_id}/notification-health` every 10 seconds while the page is visible, retain the previous snapshot during background refresh, and mark data stale after 30 seconds without a successful response. Stop polling when the session ends or the Project route changes.

Render the state as follows:

- `disabled`: delivery is administratively disabled; explain that durable pending/retryable work is preserved.
- `idle`: delivery is enabled and no Project work is queued.
- `backlogged`: show pending/due counts and oldest due age.
- `retrying`: show retrying count and oldest due age with a receiver-recovery hint.
- `failing`: show terminal failure and expired-lease counts with a link to filtered delivery history.
- `draining`: explain that new claims stopped while in-flight work finishes or leases expire.

Display activation, enabled destination count, pending, due, retrying, in-flight, expired lease, failed, oldest due age, and `observed_at`. Treat counts as bounded non-negative integers and `oldest_due_age_seconds: null` as no due work. Do not infer health from destination URLs, delivery error bodies, Prometheus, or browser-local state.

Use the shared API error component. Show the correlated request ID for support, preserve the previous snapshot on transient 5xx/network errors, distinguish 401 session expiry from tenant-safe 404, and never persist bearer credentials or health responses in browser storage. Add component tests for all six states, stale refresh, null age, large counts, and error/request-ID behavior; add Playwright and axe coverage for disabled guidance and failure-to-history navigation.
