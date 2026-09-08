SELECT
  observed_at,
  received_at,
  event_kind,
  namespace,
  workload_kind,
  workload_name,
  pod_name,
  container_name,
  process_command,
  payload
FROM runtime_events
WHERE organization_id = '018f4f9c-3f9a-7de1-8000-000000000000'
  AND project_id = '018f4f9c-3f9a-7de1-8000-000000000001'
  AND application_id = '018f4f9c-3f9a-7de1-8000-000000000002'
  AND observed_at >= now() - interval '1 hour'
ORDER BY observed_at DESC
LIMIT 100;

