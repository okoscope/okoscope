SELECT id, project_id, name, url, enabled, deliver_backfill, revision, updated_at
FROM webhook_destinations
ORDER BY updated_at DESC;

SELECT status, source, origin, count(*)
FROM notification_deliveries
GROUP BY status, source, origin
ORDER BY status, source, origin;

SELECT id, destination_id, status, attempt_count, max_attempts, available_at,
       lease_owner, lease_expires_at, last_error_class, created_at
FROM notification_deliveries
WHERE status IN ('pending', 'in_flight', 'failed')
ORDER BY available_at, created_at
LIMIT 200;

SELECT
  count(*) FILTER (WHERE status = 'pending') AS pending,
  count(*) FILTER (WHERE status = 'in_flight') AS in_flight,
  count(*) FILTER (WHERE status = 'in_flight' AND lease_expires_at <= now()) AS expired_leases,
  min(available_at) FILTER (WHERE status = 'pending') AS oldest_due,
  (SELECT count(*) FROM outbox_messages WHERE processed_at IS NULL) AS pending_outbox;

SELECT delivery_id, attempt_number, started_at, duration_ms, outcome,
       http_status, error_class, response_excerpt
FROM notification_delivery_attempts
ORDER BY started_at DESC
LIMIT 200;
