# Notification history retention

An Organization owner manages one policy: `enabled` and `history_days` (integer, 1–3650). A Project inherits the complete Organization policy unless it has a complete override. An explicit disabled override is different from inheritance. Members can read policies; only owners can change them.

Fresh Organizations default to disabled cleanup and 90 days. Projects inherit by default.

## API and UI

All endpoints use user-session authentication and existing trusted-Origin requirements for writes:

| Endpoint | Methods | Response |
| --- | --- | --- |
| `/api/v1/organizations/{organization_id}/notification-retention` | GET, PUT | `{ enabled, history_days }` |
| `/api/v1/projects/{project_id}/notification-retention` | GET, PUT, DELETE | `{ override: policy or null, effective: policy, inherited: organization policy, source: "organization" or "project" }` |

PUT replaces the entire policy. DELETE on the Project endpoint restores inheritance and returns the new effective policy. Reads are tenant scoped; member writes return 403 and cross-tenant resources return 404. The generated contract is in `openapi/okoscope-v1.yaml`.

In the Web UI, Organization controls appear in Profile and Project controls appear in Notifications. Both English and Russian labels are supported. The UI explains that enabling cleanup, shortening retention or returning to an enabled inherited policy can delete existing expired history.

## What expires

Age is measured from the delivery's latest terminal transition. Only succeeded, failed, suppressed and cancelled deliveries expire. Manual retry makes a delivery active; its next terminal outcome starts a new window. Pending and in-flight work survives regardless of age.

A delivery's attempts, single-delivery manual actions and operation links disappear in the same transaction. Shared bulk-operation summaries survive until their final linked delivery is deleted. They retain original aggregate counts, not expired delivery details. Originally empty bulk operations expire by completion time under the same policy.

An idempotency key is remembered only while its operation record exists. After deletion, a single-delivery command returns not found; a bulk command reusing an expired key can act as a new command on currently eligible deliveries. Clients must create a fresh key for each newly confirmed action, retaining a key only for retries of that action.

## Worker controls

User policies are read from PostgreSQL for each batch; no restart is needed. A batch already running can finish under its prior policy snapshot. `notification-retention` uses the same resolver as background maintenance. Sending webhooks and configuring encryption are not prerequisites for cleanup.

- `OKOSCOPE_NOTIFICATION_RETENTION_PAUSED=true` pauses maintenance, including one-shot cleanup, without changing tenant policies.
- `OKOSCOPE_NOTIFICATION_RETENTION_BATCH_SIZE` bounds root delivery candidates and separate empty-operation candidates (default 1000).
- `OKOSCOPE_NOTIFICATION_RETENTION_POLL_SECONDS` controls polling (default 3600).
- `okoscope_notification_retention_enabled` reports operational activation, not whether a particular tenant enables cleanup; `okoscope_notification_retention_paused` reports its inverse.
- Existing success, failure, deleted-row and duration metrics remain available without tenant labels.

Dependent histories cascade with their root delivery, so the total number of child rows can exceed the root batch size. Cleaners use a transaction advisory lock to avoid concurrent last-link deletion of a shared operation. Delivery locks coordinate with recovery; serialization conflicts roll back the complete batch and retry with a fresh snapshot up to three times; persistent failures are reported for a subsequent pass.

## Upgrade and rollback

1. Pause all old cleanup workers and scheduled one-shot commands before migration. Old workers do not understand tenant policies.
2. Apply migration 22 and deploy compatible servers with `OKOSCOPE_NOTIFICATION_RETENTION_PAUSED=true` during conversion.
3. Preserve the original values of `OKOSCOPE_NOTIFICATION_RETENTION_ENABLED`, `OKOSCOPE_NOTIFICATION_TERMINAL_RETENTION_DAYS` and `OKOSCOPE_NOTIFICATION_RECOVERY_RETENTION_DAYS` across replicas. They are deprecated **one-time import inputs** for Organizations present at migration time. Startup initializes those Organizations atomically, retaining the enabled state and using the larger old window. Newly created Organizations use disabled/90. Restarts never overwrite initialized/user-edited policies.
4. Inspect settings through the API before resuming maintenance. A disabled legacy policy remains disabled. Default legacy values convert existing Organizations to disabled/365.
5. Review eligible history before deliberately clearing the operational pause. The conversion replaces two independent clocks: a recent manual action on an old terminal delivery no longer delays that delivery's expiry. Choosing the larger old window does not preserve that old behavior exactly.
6. Verify isolated old terminal and active fixtures, inherited/overridden policies and shared-operation cleanup before production activation.

Rollback begins by pausing maintenance. Keep the additive schema and persisted policies. Do not start a legacy worker automatically against these policies. Deleted data cannot be restored by increasing retention; restoration requires external backups.
