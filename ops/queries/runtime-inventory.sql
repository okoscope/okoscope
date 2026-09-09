-- Inventory projection totals and freshness by Application.
SELECT
    organization_id,
    project_id,
    application_id,
    count(*) AS item_count,
    sum(occurrence_count) AS projected_occurrence_count,
    min(first_seen_at) AS first_seen_at,
    max(last_seen_at) AS last_seen_at,
    max(updated_at) AS projection_updated_at
FROM runtime_inventory_items
GROUP BY organization_id, project_id, application_id
ORDER BY projection_updated_at DESC;

-- Source-to-projection membership difference. A non-zero delta requires reconciliation.
SELECT
    e.organization_id,
    e.project_id,
    e.application_id,
    count(*) AS source_event_count,
    count(im.event_id) AS projected_event_count,
    count(*) - count(im.event_id) AS missing_projection_count
FROM runtime_events e
JOIN runtime_event_group_memberships gm
  ON gm.event_id = e.id
 AND gm.fingerprint_version = 1
LEFT JOIN runtime_inventory_event_memberships im
  ON im.event_id = e.id
 AND im.identity_version = 1
GROUP BY e.organization_id, e.project_id, e.application_id
ORDER BY missing_projection_count DESC;

-- Inventory cardinality by safe, low-cardinality kind.
SELECT inventory_kind, count(*) AS item_count, sum(occurrence_count) AS occurrence_count
FROM runtime_inventory_items
WHERE organization_id = :'organization_id'
  AND project_id = :'project_id'
  AND application_id = :'application_id'
  AND identity_version = 1
GROUP BY inventory_kind
ORDER BY inventory_kind;
