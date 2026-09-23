\set ON_ERROR_STOP on

-- Required psql variables: organization_id, project_id, application_id.
-- Run only after pausing ingestion and inventory reads and taking a backup.
BEGIN;

CREATE TEMP TABLE reset_scope ON COMMIT DROP AS
SELECT a.organization_id, a.project_id, a.id AS application_id
FROM applications a
WHERE a.organization_id = :'organization_id'::uuid
  AND a.project_id = :'project_id'::uuid
  AND a.id = :'application_id'::uuid;

DO $$
BEGIN
  IF (SELECT count(*) FROM reset_scope) <> 1 THEN
    RAISE EXCEPTION 'reset scope must resolve to exactly one Application';
  END IF;
END $$;

CREATE TEMP TABLE reset_preserved_counts ON COMMIT DROP AS
SELECT
  (SELECT count(*) FROM applications a JOIN reset_scope s ON a.id = s.application_id) AS applications,
  (SELECT count(*) FROM releases r JOIN reset_scope s ON r.application_id = s.application_id) AS releases,
  (SELECT count(*) FROM deployment_episodes d JOIN reset_scope s USING (organization_id, project_id, application_id)) AS deployment_episodes,
  (SELECT count(*) FROM resource_contributions r JOIN reset_scope s USING (organization_id, project_id, application_id)) AS resource_contributions,
  (SELECT count(*) FROM application_ingestion_credentials c JOIN reset_scope s USING (organization_id, project_id, application_id)) AS credentials,
  (SELECT count(*) FROM application_agents a JOIN reset_scope s USING (organization_id, project_id, application_id)) AS application_agents,
  (SELECT count(*) FROM clusters c JOIN reset_scope s USING (organization_id)) AS clusters,
  (SELECT count(*) FROM agents a JOIN clusters c ON c.id = a.cluster_id JOIN reset_scope s ON s.organization_id = c.organization_id) AS agents,
  (SELECT count(*) FROM applications a JOIN reset_scope s ON a.project_id = s.project_id AND a.id <> s.application_id) AS other_applications,
  (SELECT count(*) FROM webhook_destinations d JOIN reset_scope s USING (organization_id, project_id)) AS project_destinations;

CREATE TEMP TABLE reset_groups ON COMMIT DROP AS
SELECT g.id FROM runtime_event_groups g JOIN reset_scope s USING (organization_id, project_id, application_id);
CREATE TEMP TABLE reset_items ON COMMIT DROP AS
SELECT i.id FROM runtime_inventory_items i JOIN reset_scope s USING (organization_id, project_id, application_id);
CREATE TEMP TABLE reset_outbox ON COMMIT DROP AS
SELECT o.id FROM outbox_messages o WHERE o.aggregate_id IN (SELECT id FROM reset_groups);
CREATE TEMP TABLE reset_deliveries ON COMMIT DROP AS
SELECT d.id FROM notification_deliveries d WHERE d.outbox_message_id IN (SELECT id FROM reset_outbox);
CREATE TEMP TABLE reset_recovery_operations ON COMMIT DROP AS
SELECT DISTINCT l.operation_id FROM notification_recovery_operation_deliveries l
WHERE l.delivery_id IN (SELECT id FROM reset_deliveries);

SELECT 'preflight' AS phase,
  (SELECT count(*) FROM runtime_events e JOIN reset_scope s USING (organization_id, project_id, application_id)) AS runtime_events,
  (SELECT count(*) FROM reset_groups) AS runtime_groups,
  (SELECT count(*) FROM reset_items) AS inventory_items,
  (SELECT count(*) FROM runtime_policies p JOIN reset_scope s USING (organization_id, project_id, application_id)) AS policies,
  (SELECT count(*) FROM runtime_behavior_user_labels l JOIN reset_scope s USING (organization_id, project_id, application_id)) AS labels,
  (SELECT count(*) FROM reset_outbox) AS outbox_messages,
  (SELECT count(*) FROM reset_deliveries) AS notification_deliveries;

DELETE FROM notification_recovery_operation_deliveries WHERE delivery_id IN (SELECT id FROM reset_deliveries);
DELETE FROM notification_recovery_operations WHERE id IN (SELECT operation_id FROM reset_recovery_operations)
  AND NOT EXISTS (SELECT 1 FROM notification_recovery_operation_deliveries l WHERE l.operation_id = notification_recovery_operations.id);
DELETE FROM notification_deliveries WHERE id IN (SELECT id FROM reset_deliveries);
DELETE FROM outbox_messages WHERE id IN (SELECT id FROM reset_outbox);

DELETE FROM runtime_group_policy_evaluations e USING reset_scope s
WHERE (e.organization_id, e.project_id, e.application_id) = (s.organization_id, s.project_id, s.application_id);
DELETE FROM runtime_sighting_policy_evaluations e USING reset_scope s
WHERE (e.organization_id, e.project_id, e.application_id) = (s.organization_id, s.project_id, s.application_id);
DELETE FROM runtime_policy_recomputations r USING reset_scope s
WHERE (r.organization_id, r.project_id, r.application_id) = (s.organization_id, s.project_id, s.application_id);
DELETE FROM runtime_policy_suppressions z USING reset_scope s
WHERE (z.organization_id, z.project_id, z.application_id) = (s.organization_id, s.project_id, s.application_id);
DELETE FROM runtime_policy_commands c USING reset_scope s
WHERE (c.organization_id, c.project_id, c.application_id) = (s.organization_id, s.project_id, s.application_id);
UPDATE runtime_policies p SET current_revision_id = NULL FROM reset_scope s
WHERE (p.organization_id, p.project_id, p.application_id) = (s.organization_id, s.project_id, s.application_id);
DELETE FROM runtime_policies p USING reset_scope s
WHERE (p.organization_id, p.project_id, p.application_id) = (s.organization_id, s.project_id, s.application_id);
DELETE FROM runtime_policy_states p USING reset_scope s
WHERE (p.organization_id, p.project_id, p.application_id) = (s.organization_id, s.project_id, s.application_id);
DELETE FROM runtime_behavior_user_labels l USING reset_scope s
WHERE (l.organization_id, l.project_id, l.application_id) = (s.organization_id, s.project_id, s.application_id);

DELETE FROM runtime_restart_loop_projections p USING reset_scope s
WHERE (p.organization_id, p.project_id, p.application_id) = (s.organization_id, s.project_id, s.application_id);
DELETE FROM runtime_inventory_items WHERE id IN (SELECT id FROM reset_items);
DELETE FROM runtime_event_groups WHERE id IN (SELECT id FROM reset_groups);
DELETE FROM runtime_events e USING reset_scope s
WHERE (e.organization_id, e.project_id, e.application_id) = (s.organization_id, s.project_id, s.application_id);

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM runtime_events e JOIN reset_scope s USING (organization_id, project_id, application_id))
    OR EXISTS (SELECT 1 FROM runtime_event_groups g JOIN reset_scope s USING (organization_id, project_id, application_id))
    OR EXISTS (SELECT 1 FROM runtime_inventory_items i JOIN reset_scope s USING (organization_id, project_id, application_id))
    OR EXISTS (SELECT 1 FROM runtime_policies p JOIN reset_scope s USING (organization_id, project_id, application_id))
    OR EXISTS (SELECT 1 FROM runtime_behavior_user_labels l JOIN reset_scope s USING (organization_id, project_id, application_id)) THEN
    RAISE EXCEPTION 'Application runtime reset left residual state';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM applications a JOIN reset_scope s ON a.id = s.application_id) THEN
    RAISE EXCEPTION 'Application was not preserved';
  END IF;
  IF EXISTS (
    SELECT 1 FROM reset_preserved_counts b
    WHERE b.applications <> (SELECT count(*) FROM applications a JOIN reset_scope s ON a.id = s.application_id)
       OR b.releases <> (SELECT count(*) FROM releases r JOIN reset_scope s ON r.application_id = s.application_id)
       OR b.deployment_episodes <> (SELECT count(*) FROM deployment_episodes d JOIN reset_scope s USING (organization_id, project_id, application_id))
       OR b.resource_contributions <> (SELECT count(*) FROM resource_contributions r JOIN reset_scope s USING (organization_id, project_id, application_id))
       OR b.credentials <> (SELECT count(*) FROM application_ingestion_credentials c JOIN reset_scope s USING (organization_id, project_id, application_id))
       OR b.application_agents <> (SELECT count(*) FROM application_agents a JOIN reset_scope s USING (organization_id, project_id, application_id))
       OR b.clusters <> (SELECT count(*) FROM clusters c JOIN reset_scope s USING (organization_id))
       OR b.agents <> (SELECT count(*) FROM agents a JOIN clusters c ON c.id = a.cluster_id JOIN reset_scope s ON s.organization_id = c.organization_id)
       OR b.other_applications <> (SELECT count(*) FROM applications a JOIN reset_scope s ON a.project_id = s.project_id AND a.id <> s.application_id)
       OR b.project_destinations <> (SELECT count(*) FROM webhook_destinations d JOIN reset_scope s USING (organization_id, project_id))
  ) THEN
    RAISE EXCEPTION 'Application reset changed preserved product state';
  END IF;
END $$;

SELECT 'postflight' AS phase,
  (SELECT count(*) FROM applications a JOIN reset_scope s ON a.id = s.application_id) AS applications_preserved,
  (SELECT count(*) FROM releases r JOIN reset_scope s ON r.application_id = s.application_id) AS releases_preserved,
  (SELECT count(*) FROM deployment_episodes d JOIN reset_scope s USING (organization_id, project_id, application_id)) AS deployment_episodes_preserved,
  (SELECT count(*) FROM application_ingestion_credentials c JOIN reset_scope s USING (organization_id, project_id, application_id)) AS credentials_preserved,
  (SELECT count(*) FROM application_agents a JOIN reset_scope s USING (organization_id, project_id, application_id)) AS application_agents_preserved;

COMMIT;
