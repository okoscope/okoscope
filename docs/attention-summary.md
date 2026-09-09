# Attention summary API

Okoscope exposes two authenticated snapshots:

- `GET /api/v1/attention-summary` for Organization-wide triage;
- `GET /api/v1/projects/{project_id}/applications/{application_id}/attention-summary` for Application investigation.

Both accept `window=24h|7d` (default `24h`), `limit=1..50` (default `20`), and `recommendation_limit=1..10` (default `5`). The Organization endpoint also accepts `changed_application_limit=1..10`; the Application endpoint accepts `largest_change_limit=1..10`; both default to `5`.

```console
curl -H 'Authorization: Bearer …' \
  'https://okoscope.example/api/v1/attention-summary?window=24h&limit=20'
```

```json
{
  "generated_at": "2026-08-22T12:00:00Z",
  "window": {
    "kind": "24h",
    "from": "2026-08-21T12:00:00Z",
    "to": "2026-08-22T12:00:00Z"
  },
  "totals": {
    "new_discoveries": 7,
    "open_discoveries": 12,
    "acknowledged_discoveries": 4,
    "changed_applications": 3,
    "projects_with_notification_problems": 2,
    "failed_notification_deliveries": 14
  },
  "priority_items": [],
  "changed_applications": [],
  "notification_problems": [],
  "recommendations": []
}
```

## Snapshot and totals

The server opens a read-only repeatable-read transaction and obtains one database transaction timestamp. `window.to` is exactly `generated_at`; `window.from` is 24 hours or seven days earlier. A section failure fails the whole request rather than substituting zeroes.

Window membership is inclusive: `[window.from, window.to]`. `new_discoveries` includes every scoped Runtime Group first seen in that interval, regardless of current lifecycle state. `open_discoveries` and `acknowledged_discoveries` are complete current-state totals and are not restricted to the window. Failed-delivery totals use terminal time in the window. Totals are database aggregates over the full tenant scope and do not depend on cursor pages.

## Release comparison

The target is the latest Application release ordered by `(deployed_at DESC, id DESC)` and the baseline is the immediately preceding release. An Application with no baseline is not called changed and its Application summary has no comparable release result. A comparable Application is changed only when at least one group is `new` or `disappeared`.

`disappeared` means that runtime behavior was observed in the baseline and is no longer observed in the target. It does not assert deletion. Occurrence deltas are factual count differences; largest changes are bounded and ordered by absolute delta, relevant observation timestamp, and group ID.

## Priority and recommendations

Priority items use the exact tuple `(priority rank ASC, reason count DESC, relevant timestamp DESC, stable resource UUID ASC)`, with urgent=0, high=1, and normal=2. Failure and missing-destination facts are urgent; backlog/retry and comparable release changes are high; open discoveries are normal. A newly seen open discovery emits `new_discovery`, not a duplicate `open_discovery`.

Reason count is the terminal failure count, `1` for a missing destination, the maximum of due/retrying/expired-lease counts for delayed delivery, `new + disappeared` for release change, or occurrence count for discovery.

Recommendations are deterministic and deduplicated per actionable Project or Application scope: `review_failed_deliveries`, `configure_webhook_destination`, `review_notification_backlog`, `review_release_changes`, and `review_new_discoveries`. Clients localize reason codes and construct routes from the typed resource reference; the API never returns frontend URLs.

## Limits and safety

The handlers use a constant, bounded set of tenant-scoped SQL queries and never traverse cursor pages or query once per Project/Application. The repository budgets are nine statements for the Organization endpoint and eight for the Application endpoint, independent of tenant cardinality. Version one deliberately has no server-side cache; `Cache-Control: no-store` is returned. A short cache may be considered only after measuring production cost.

Observed commands, paths, domains, and addresses are untrusted inert data. The API does not label observations as security severity, risk, vulnerability, or incidents and never returns webhook URLs, secrets, credentials, signatures, raw payloads, or receiver response excerpts.

Latest-release comparisons can be biased when a release has had little observation time. Consumers must present timestamps and factual counts rather than infer confidence or risk.
