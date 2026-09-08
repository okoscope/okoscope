# Frontend handoff: notification delivery recovery

Implement retry, cancel, bulk retry, and recovery audit in the separate Okoscope Web UI using the generated client from `openapi/okoscope-v1.yaml` as the only transport type source.

## User flows

- Show `Retry` only for a failed delivery whose concrete detail reports retry eligibility; require explicit confirmation that webhook delivery is at-least-once and retains the stable delivery ID.
- Show `Cancel` only for queued work; explain that an active HTTP attempt cannot be interrupted and surface the stable `delivery_active_lease` conflict after refreshing detail.
- Offer bulk retry only from a filtered failed-delivery view. Echo the filters and server batch limit in the confirmation dialog, then show selected, retried, skipped, remaining, and `has_more` from the response.
- Add Project recovery-operation history and detail views with actor, command, target, safe counts, request ID, timestamps, and affected deliveries.

## Idempotency lifecycle

Generate one cryptographically random `Idempotency-Key` per user-confirmed command. Keep it only in memory until the command has a definitive response. Reuse the same key for network retries of that exact command; create a new key for a newly confirmed command. Never place the key in a URL, persistent browser storage, analytics, logs, or an error report.

Treat `idempotency_key_reused` as a conflict requiring a new confirmation rather than silently changing the command. Disable duplicate form submission while a command is pending.

## State and errors

After a successful command, invalidate delivery detail, delivery lists, notification health, and recovery-operation queries. On `409`, preserve the user's context, display the safe machine code and correlated request ID, refresh the delivery, and recompute enabled actions. Preserve the last successful read during temporary failures and label stale data.

Do not display or persist bearer credentials, raw idempotency keys, signing secrets, payload bodies, unrestricted receiver bodies, internal lease owners, or destination URLs beyond fields intentionally returned by OpenAPI.

## Acceptance

- Generated types cover all command inputs, results, conflicts, operation pages, and operation details without `Record<string, unknown>` fallbacks.
- Unit tests cover confirmation, in-memory idempotency reuse, changed-command keys, eligibility controls, `409` refresh, bulk `has_more`, stale reads, and request-ID copy.
- Playwright covers one retry, one queued cancellation, one bounded bulk command, and operation-history navigation.
- Accessibility tests cover keyboard confirmation, focus restoration, status text independent of color, and `aria-live` command results.

## Unified history retention

Delivery attempts and manual actions now share the effective Project retention window. Expired deliveries and their details disappear together; shared operation summaries can retain aggregate counts while their affected-delivery lists shrink. Idempotency keys are remembered only while the operation record survives. See [retention settings and API](notification-retention-settings.md).
