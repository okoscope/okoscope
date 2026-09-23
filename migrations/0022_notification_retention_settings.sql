ALTER TABLE organizations
    ADD COLUMN notification_retention_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN notification_retention_days INTEGER NOT NULL DEFAULT 90
        CHECK (notification_retention_days BETWEEN 1 AND 3650),
    ADD COLUMN notification_retention_initialized BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN notification_retention_updated_at TIMESTAMPTZ,
    ADD COLUMN notification_retention_updated_by UUID REFERENCES users(id) ON DELETE SET NULL;

-- Only organizations existing at migration time need legacy configuration import.
ALTER TABLE organizations ALTER COLUMN notification_retention_initialized SET DEFAULT true;

ALTER TABLE projects
    ADD COLUMN notification_retention_enabled BOOLEAN,
    ADD COLUMN notification_retention_days INTEGER,
    ADD COLUMN notification_retention_updated_at TIMESTAMPTZ,
    ADD COLUMN notification_retention_updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD CONSTRAINT projects_notification_retention_complete CHECK (
        (notification_retention_enabled IS NULL AND notification_retention_days IS NULL)
        OR (notification_retention_enabled IS NOT NULL AND notification_retention_days IS NOT NULL
            AND notification_retention_days BETWEEN 1 AND 3650)
    );

CREATE VIEW effective_notification_retention AS
SELECT p.organization_id, p.id AS project_id,
    COALESCE(p.notification_retention_enabled,o.notification_retention_enabled) AS enabled,
    COALESCE(p.notification_retention_days,o.notification_retention_days) AS history_days
FROM projects p JOIN organizations o ON o.id=p.organization_id
WHERE o.notification_retention_initialized;

CREATE INDEX notification_deliveries_tenant_retention_idx
    ON notification_deliveries (organization_id,project_id,terminal_at,id)
    WHERE status IN ('succeeded','failed','suppressed','cancelled');

CREATE INDEX notification_recovery_target_retention_idx
    ON notification_recovery_operations (target_delivery_id)
    WHERE target_delivery_id IS NOT NULL;
