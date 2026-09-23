-- Operator query-plan checks for UI navigation. Replace UUIDs before running.
EXPLAIN (ANALYZE, BUFFERS)
SELECT p.id, p.created_at,
       (SELECT count(*) FROM applications a
        WHERE a.organization_id = p.organization_id AND a.project_id = p.id),
       (SELECT count(*) FROM runtime_event_groups g
        WHERE g.organization_id = p.organization_id AND g.project_id = p.id)
FROM projects p
WHERE p.organization_id = '00000000-0000-0000-0000-000000000000'
  AND (p.created_at, p.id) > ('1970-01-01T00:00:00Z', '00000000-0000-0000-0000-000000000000')
ORDER BY p.created_at, p.id
LIMIT 51;

EXPLAIN (ANALYZE, BUFFERS)
SELECT a.id, a.created_at,
       (SELECT count(*) FROM releases r WHERE r.organization_id=a.organization_id AND r.project_id=a.project_id AND r.application_id=a.id),
       (SELECT count(*) FROM runtime_event_groups g WHERE g.organization_id=a.organization_id AND g.project_id=a.project_id AND g.application_id=a.id),
       (SELECT max(e.observed_at) FROM runtime_events e WHERE e.organization_id=a.organization_id AND e.project_id=a.project_id AND e.application_id=a.id)
FROM applications a
WHERE a.organization_id = '00000000-0000-0000-0000-000000000000'
  AND a.project_id = '00000000-0000-0000-0000-000000000000'
ORDER BY a.created_at, a.id
LIMIT 51;
