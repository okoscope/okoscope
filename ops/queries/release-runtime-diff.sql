-- Release attribution coverage by Application.
SELECT application_id,
       count(*) FILTER (WHERE release_id IS NOT NULL) AS attributed,
       count(*) FILTER (WHERE release_id IS NULL) AS unattributed
FROM runtime_events GROUP BY application_id ORDER BY application_id;

-- Release-scoped runtime summaries, newest releases first.
SELECT r.application_id, r.version, r.deployed_at, g.event_kind,
       g.semantic_summary, s.occurrence_count, s.first_seen_at, s.last_seen_at
FROM runtime_event_group_releases s
JOIN releases r ON r.id = s.release_id
JOIN runtime_event_groups g ON g.id = s.group_id
ORDER BY r.deployed_at DESC, r.id DESC, g.id;

-- Replace both UUIDs to inspect an explicit baseline/target comparison.
WITH baseline AS (
    SELECT * FROM runtime_event_group_releases WHERE release_id = '00000000-0000-0000-0000-000000000000'
), target AS (
    SELECT * FROM runtime_event_group_releases WHERE release_id = '00000000-0000-0000-0000-000000000000'
)
SELECT COALESCE(target.group_id, baseline.group_id) AS group_id,
       CASE WHEN baseline.group_id IS NULL THEN 'new'
            WHEN target.group_id IS NULL THEN 'disappeared'
            ELSE 'unchanged' END AS classification,
       baseline.occurrence_count AS baseline_count,
       target.occurrence_count AS target_count
FROM baseline FULL OUTER JOIN target USING (group_id)
ORDER BY group_id;
