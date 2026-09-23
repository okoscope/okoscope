SELECT
  id,
  event_kind,
  semantic_summary,
  status,
  first_seen_at,
  first_seen_event_id,
  last_seen_at,
  occurrence_count,
  namespace,
  workload_kind,
  workload_name
  ,status_changed_at
  ,status_changed_by
FROM runtime_event_groups
ORDER BY last_seen_at DESC, id DESC
LIMIT 100;

SELECT
  count(*) AS group_count,
  coalesce(sum(occurrence_count), 0)::bigint AS grouped_occurrences,
  (SELECT count(*) FROM runtime_event_group_memberships) AS memberships,
  (SELECT count(*) FROM runtime_events e
   WHERE NOT EXISTS (
     SELECT 1 FROM runtime_event_group_memberships m
     WHERE m.event_id = e.id AND m.fingerprint_version = 1
   )) AS ungrouped_events,
  (SELECT count(*) FROM outbox_messages WHERE processed_at IS NULL) AS pending_outbox;

SELECT
  g.id AS group_id,
  e.id AS stored_event_id,
  e.event_id AS agent_event_id,
  e.observed_at,
  e.event_kind,
  e.process_command,
  e.namespace,
  e.pod_name,
  e.container_name,
  r.version AS release_version
FROM runtime_event_groups g
JOIN runtime_event_group_memberships m ON m.group_id = g.id
JOIN runtime_events e ON e.id = m.event_id
LEFT JOIN releases r ON r.id = e.release_id
ORDER BY e.observed_at DESC, e.id DESC
LIMIT 100;
